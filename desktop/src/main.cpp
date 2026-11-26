#include "app_window.h"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#else
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

import std;
import desktop.async_worker;
import desktop.client_db;
import desktop.core_supervisor;
import desktop.desktop_host_config;
import desktop.http_control;
import desktop.ipc_client;
import desktop.kdl_ops;
import desktop.share_link;
import desktop.single_instance;
import desktop.system_proxy;
import desktop.telemetry_store;
import desktop.tray_controller;
import desktop.tun_privilege;
import desktop.ui_actions;
import desktop.ui_prefs;
import desktop.window_blur;
import desktop.workspace_composer;
import desktop.workspace_models;
import desktop.workspace_store;
import desktop.workspace_sync;

#include "main_helpers.hpp"
#include "ui_redesign_helpers.hpp"
#include "ui_binding_helpers.hpp"
#include "tun_elevation_flow.hpp"
#include "workspace_ui_flow.hpp"
#include "main_quick_controls.hpp"
#include "main_callbacks.hpp"

using desktop_ui_helpers::default_config_dir;
using desktop_ui_helpers::default_control_endpoint;
using desktop_ui_helpers::is_en_ui;
using desktop_ui_helpers::on_ui_thread;
using desktop_ui_helpers::open_with_system_editor;
using desktop_ui_helpers::read_file_text;
using desktop_ui_helpers::tr;
using desktop_ui_helpers::write_file_atomic;

auto main(int argc, char** argv) -> int {
    (void)argc;
#ifndef _WIN32
    std::signal(SIGPIPE, SIG_IGN);
#endif
    auto cfg_dir = default_config_dir();
    std::error_code dir_ec;
    std::filesystem::create_directories(cfg_dir, dir_ec);
    auto config_path = cfg_dir / "config.kdl";
    auto secrets_dir = cfg_dir / "secrets";
    auto binary_path = desktop_ui_helpers::resolve_core_binary(argv[0]);
    slint::set_xdg_app_id("nexus-desktop");

    auto ui = nexus_ui::AppWindow::create();
    slint::ComponentWeakHandle<nexus_ui::AppWindow> weak_ui(ui);
    auto blur_ctrl = std::make_shared<desktop::WindowBlurController>();
    desktop_ui_helpers::setup_native_window_blur(*ui, weak_ui, blur_ctrl);

    std::function<void()> show_window_from_ui;
    auto instance = desktop::SingleInstanceGuard::acquire("nexus-desktop", [weak_ui, &show_window_from_ui] {
        on_ui_thread(weak_ui, [&show_window_from_ui](auto& s) {
            if (show_window_from_ui) show_window_from_ui();
            else s->window().show();
        });
    });
    if (!instance) return 0;

    auto fallback_sock = default_control_endpoint(cfg_dir);
    std::unique_ptr<desktop::ClientDatabase> client_db;
    std::string db_open_error;
    if (auto opened = desktop::ClientDatabase::open(cfg_dir / "nexus-client.db"); opened) {
        client_db = std::make_unique<desktop::ClientDatabase>(std::move(*opened));
    } else {
        db_open_error = opened.error();
    }

    if (!std::filesystem::exists(config_path, dir_ec)) {
        (void)write_file_atomic(config_path, desktop_ui_helpers::build_default_desktop_config(fallback_sock));
    }
    auto initial_kdl = read_file_text(config_path);
    auto ctl_cfg = desktop_ui_helpers::parse_control_config(initial_kdl, fallback_sock, cfg_dir);

    desktop::CoreSupervisor supervisor(binary_path);
    desktop::IpcClient ipc(ctl_cfg.socket);
    desktop::HttpControlClient http_ctrl(ctl_cfg.http_host, ctl_cfg.http_port, ctl_cfg.bearer_token);
    desktop::SystemProxyController sys_proxy;
    std::vector<desktop::OutboundGroupSnapshot> cached_groups;
    std::unordered_set<std::string> pinned_members;
    desktop_ui_helpers::MemberModelPipeline member_models;
    ui->set_members(member_models.sorted);
    std::vector<desktop::LogEntrySnapshot> cached_logs;
    std::mutex logs_mu;
    desktop_ui_helpers::RateTracker rate_tracker;
    std::optional<std::chrono::steady_clock::time_point> core_started_at;
    std::atomic<bool> metrics_in_flight{false};
    std::atomic<bool> conns_in_flight{false};
    std::atomic<bool> lifecycle_busy{false};
    std::uint64_t last_ledger_up = 0, last_ledger_down = 0;
    int conn_poll_tick = 0;
    desktop::AsyncWorker worker;
    desktop::AsyncWorker probe_worker;

    ui->set_config_path(slint::SharedString(config_path.string()));
    auto loaded_prefs = (client_db ? desktop::load_ui_prefs_from_db(*client_db) : std::nullopt)
                            .value_or(desktop::UiPrefs{});
    desktop_ui_helpers::apply_prefs_to_ui(*ui, loaded_prefs, desktop::detect_system_locale());
    desktop_ui_helpers::clear_telemetry_ui(*ui);
    desktop_ui_helpers::apply_kdl_to_ui_state(*ui, initial_kdl);
    if (!db_open_error.empty()) {
        bool const en = is_en_ui(*ui);
        auto msg = tr(en, "客户端数据库打开失败: ", "Client database error: ") + db_open_error;
        ui->set_diagnostic_ok(false);
        ui->set_diagnostic_message(slint::SharedString(msg));
        desktop_ui_helpers::push_toast(*ui, msg, "error");
    }
    worker.post([weak_ui] {
        bool supported = desktop::SystemProxyController::supported();
        on_ui_thread(weak_ui, [supported](auto& s) { s->set_system_proxy_supported(supported); });
    });

    auto persist_prefs = [&ui, &client_db] {
        if (client_db) (void)desktop::save_ui_prefs_to_db(*client_db, desktop_ui_helpers::capture_prefs_from_ui(*ui));
    };

    bool window_visible = true;
    std::function<void()> sync_tray;
    std::function<void()> on_window_shown;
    std::function<void()> on_window_hidden;
    std::atomic<bool> quit_once{false};

    desktop_ui_helpers::WorkspaceUiContext ws_ctx{
        *ui, weak_ui, worker, supervisor, ipc, http_ctrl, rate_tracker, core_started_at, lifecycle_busy,
        cfg_dir, config_path, fallback_sock, sync_tray, client_db.get(), {}, {}, {}, {}, {}, {}, "proxy", {}, {}
    };

    desktop::TrayController tray(desktop_ui_helpers::make_tray_callbacks(
        weak_ui, window_visible, sync_tray, on_window_shown, on_window_hidden, quit_once));
    sync_tray = [&] {
        desktop_ui_helpers::sync_tray_state(
            tray, supervisor, *ui, cached_groups, pinned_members, ws_ctx.doc, ws_ctx.telemetry.active_profile_id, window_visible);
    };
    ui->set_tray_native_active(tray.native_backend_active());

    auto sync_memory_ui = [&] {
        auto app_rss = desktop::current_process_memory_bytes();
        auto core_rss = supervisor.running() ? supervisor.memory_bytes() : 0ULL;
        auto total_rss = app_rss + core_rss;
        ui->set_app_memory_text(slint::SharedString(app_rss > 0 ? desktop_ui_helpers::format_bytes_human(app_rss) : "--"));
        ui->set_core_memory_text(slint::SharedString(core_rss > 0 ? desktop_ui_helpers::format_bytes_human(core_rss) : "--"));
        ui->set_total_memory_text(slint::SharedString(total_rss > 0 ? desktop_ui_helpers::format_bytes_human(total_rss) : "--"));
        ui->set_app_memory_ratio(total_rss > 0 ? static_cast<float>(static_cast<double>(app_rss) / static_cast<double>(total_rss)) : 1.0f);
    };

    auto record_traffic_totals = [&](std::uint64_t up_total, std::uint64_t down_total) {
        if (!client_db) return;
        std::int64_t up_d = up_total >= last_ledger_up ? static_cast<std::int64_t>(up_total - last_ledger_up) : 0;
        std::int64_t down_d = down_total >= last_ledger_down ? static_cast<std::int64_t>(down_total - last_ledger_down) : 0;
        last_ledger_up = up_total;
        last_ledger_down = down_total;
        if (up_d > 0 || down_d > 0) {
            auto hr = std::chrono::duration_cast<std::chrono::hours>(std::chrono::system_clock::now().time_since_epoch()).count();
            std::string pid = ws_ctx.telemetry.active_profile_id;
            worker.post([db = client_db.get(), hr, pid = std::move(pid), up_d, down_d] {
                (void)db->record_traffic_delta(hr, pid, up_d, down_d);
            });
        }
    };

    auto poll_telemetry = [&](bool refresh_groups_too) {
        desktop_ui_helpers::poll_telemetry_async(
            weak_ui, worker, http_ctrl, cached_groups, pinned_members, member_models, rate_tracker, metrics_in_flight,
            refresh_groups_too, sync_tray, record_traffic_totals);
    };

    on_window_shown = [&] {
        sync_memory_ui();
        if (supervisor.running()) {
            poll_telemetry(std::string_view(ui->get_active_node()).empty());
            if (ui->get_active_tab() == 2 && !ui->get_connections_paused()) ui->invoke_refresh_connections();
            ui->invoke_refresh_logs();
        }
    };
    on_window_hidden = [&] {
        { std::lock_guard lk(logs_mu); cached_logs.clear(); }
        ui->set_logs(std::make_shared<slint::VectorModel<nexus_ui::LogLineItem>>());
        ui->set_connections(std::make_shared<slint::VectorModel<nexus_ui::ActiveConnectionItem>>());
        worker.post([db = client_db.get()] { desktop::reclaim_process_memory(db); });
    };
    show_window_from_ui = [&] {
        ui->window().show();
        window_visible = true;
        on_window_shown();
        sync_tray();
    };

    desktop_ui_helpers::bind_quick_control_callbacks(ws_ctx, sys_proxy, persist_prefs);

    desktop_ui_helpers::TunFlowContext tun_ctx{
        *ui, weak_ui, worker, supervisor, ipc, http_ctrl, rate_tracker, core_started_at,
        cfg_dir, config_path, fallback_sock, lifecycle_busy, sync_tray, persist_prefs,
        [&](bool on) {
            ws_ctx.host.enable_tun = on;
            (void)desktop_ui_helpers::persist_host_db(ws_ctx);
            desktop_ui_helpers::sync_workspace_to_ui(ws_ctx);
        }
    };
    desktop_ui_helpers::bind_tun_callbacks(tun_ctx);
    desktop_ui_helpers::bind_workspace_callbacks(ws_ctx);

    ui->on_activate_profile([&](slint::SharedString id) {
        ui->global<nexus_ui::WorkspaceState>().invoke_activate_profile(id);
    });
    ui->on_toggle_core([&] {
        desktop_ui_helpers::toggle_core_with_workspace(ws_ctx, [&](std::string kdl, bool prefer_persistent, bool en) {
            desktop_ui_helpers::toggle_core_async(
                weak_ui, worker, supervisor, sys_proxy, ipc, http_ctrl, sync_tray, cached_groups, pinned_members, member_models, rate_tracker,
                core_started_at, metrics_in_flight, lifecycle_busy, cfg_dir, config_path, fallback_sock, std::move(kdl), prefer_persistent, en);
        });
    });

    ui->on_reload_config([&] {
        bool en = is_en_ui(*ui);
        if (!supervisor.running()) {
            desktop_ui_helpers::push_toast(*ui, tr(en, "核心未运行", "Core is not running"), "warn");
            return;
        }
        worker.post([&, weak_ui, en] {
            auto reply = ipc.reload();
            if (!reply.ok) { if (auto hr = http_ctrl.reload(); hr.ok) reply = {true, "OK"}; }
            auto msg = reply.ok ? tr(en, "热重载成功", "Reloaded") : (tr(en, "热重载失败: ", "Reload failed: ") + reply.body);
            on_ui_thread(weak_ui, [ok = reply.ok, msg = std::move(msg)](auto& s) {
                desktop_ui_helpers::push_toast(*s, msg, ok ? "success" : "error");
            });
        });
    });
    ui->on_save_and_reload([&](slint::SharedString text) {
        bool en = is_en_ui(*ui);
        std::string payload(text);
        ui->set_diagnostic_message(slint::SharedString(tr(en, "正在校验并保存...", "Validating & saving...")));
        worker.post([&, weak_ui, en, payload = std::move(payload)] {
            auto res = desktop_ui_helpers::validate_draft_config(cfg_dir, supervisor, payload, en);
            if (!res.ok) {
                auto disk_kdl = read_file_text(config_path);
                on_ui_thread(weak_ui, [&sync_tray, disk_kdl = std::move(disk_kdl), msg = tr(en, "拒绝下发无效配置: ", "Invalid config rejected: ") + res.message](auto& s) {
                    s->set_diagnostic_ok(false); s->set_diagnostic_message(slint::SharedString(msg));
                    if (!disk_kdl.empty()) desktop_ui_helpers::apply_kdl_to_ui_state(*s, disk_kdl);
                    sync_tray(); desktop_ui_helpers::push_toast(*s, msg, "error");
                });
                return;
            }
            bool saved = write_file_atomic(config_path, payload);
            std::string disk_kdl = saved ? std::string{} : read_file_text(config_path);
            desktop::IpcReply reply{saved, saved ? tr(en, "已保存", "Saved") : tr(en, "写入失败", "Write failed")};
            if (saved) {
                bool was_running = supervisor.running();
                if (was_running) {
                    reply = ipc.reload();
                    if (!reply.ok && http_ctrl.reload().ok) reply = {true, "OK"};
                }
                if (!was_running || reply.ok) {
                    auto next_ctl = desktop_ui_helpers::parse_control_config(payload, fallback_sock, cfg_dir);
                    ipc.set_endpoint(next_ctl.socket);
                    http_ctrl.set_endpoint(next_ctl.http_host, next_ctl.http_port);
                    http_ctrl.set_bearer_token(next_ctl.bearer_token);
                }
            }
            std::string msg = !saved ? tr(en, "写入配置文件失败", "Failed to write config file")
                : (reply.ok ? tr(en, "校验通过，已保存并热重载", "Saved & reloaded") : (tr(en, "已保存，但重载失败: ", "Saved; reload failed: ") + reply.body));
            on_ui_thread(weak_ui, [&sync_tray, ok = saved && reply.ok, saved, payload, disk_kdl = std::move(disk_kdl), msg = std::move(msg)](auto& s) {
                if (saved) {
                    desktop_ui_helpers::apply_kdl_to_ui_state(*s, payload);
                } else {
                    s->set_tun_enabled(desktop_ui_helpers::kdl_has_tun_inbound(disk_kdl));
                }
                s->set_diagnostic_ok(ok); s->set_diagnostic_message(slint::SharedString(msg));
                sync_tray(); desktop_ui_helpers::push_toast(*s, msg, ok ? "success" : "error");
            });
        });
    });

    ui->on_open_external_editor([&] { open_with_system_editor(config_path); });
    ui->global<nexus_ui::ToastState>().set_has_endpoint_formatter(true);
    ui->global<nexus_ui::ToastState>().on_format_endpoint_cb([](slint::SharedString h, slint::SharedString p) {
        return slint::SharedString(desktop::format_host_port(std::string_view(h), std::string_view(p)));
    });
    ui->on_copy_text([&](slint::SharedString text) {
        worker.post([s = std::string(text)] { (void)desktop_ui_helpers::copy_text_to_clipboard(s); });
    });
    ui->on_copy_proxy_env([&] {
        bool en = is_en_ui(*ui);
        auto cmd = desktop_ui_helpers::build_proxy_env_from_inbounds(desktop_ui_helpers::read_inbounds_from_ui(*ui));
        if (cmd.empty()) {
            desktop_ui_helpers::push_toast(*ui, tr(en, "请先启用本地入站端口", "Enable a local inbound port first"), "warn");
            return;
        }
        worker.post([cmd = std::move(cmd)] { (void)desktop_ui_helpers::copy_text_to_clipboard(cmd); });
        desktop_ui_helpers::push_toast(*ui, tr(en, "已复制终端代理环境变量", "Copied proxy export command"), "success");
    });
    desktop_ui_helpers::bind_dash_layout_callbacks(*ui, persist_prefs);
    ui->on_clear_cache([&] {
        bool en = is_en_ui(*ui);
        worker.post([&, weak_ui, en] {
            auto reply = http_ctrl.clear_cache();
            auto msg = reply.ok ? tr(en, "缓存已清空", "Cache cleared") : (tr(en, "清空缓存失败: ", "Clear cache failed: ") + reply.body);
            on_ui_thread(weak_ui, [ok = reply.ok, msg = std::move(msg)](auto& s) {
                desktop_ui_helpers::push_toast(*s, msg, ok ? "success" : "error");
            });
        });
    });
    ui->on_import_share_link([&](slint::SharedString raw_uri) {
        desktop_ui_helpers::import_share_uri_to_workspace(ws_ctx, std::string_view(raw_uri));
    });

    desktop_ui_helpers::DesktopCallbacksContext cb_ctx{
        *ui, weak_ui, worker, probe_worker, supervisor, ipc, http_ctrl, client_db.get(), ws_ctx.telemetry,
        cfg_dir, config_path, fallback_sock, cached_groups, pinned_members, member_models, cached_logs, logs_mu, sync_tray
    };
    struct ShutdownGuard {
        std::atomic<bool>& quit_once;
        desktop::TrayController& tray;
        desktop::AsyncWorker& worker;
        desktop::AsyncWorker& probe_worker;
        ~ShutdownGuard() {
            quit_once.store(true, std::memory_order_release);
            tray.stop();
            probe_worker.stop();
            worker.stop();
        }
    } shutdown_guard{quit_once, tray, worker, probe_worker};
    desktop_ui_helpers::bind_secondary_callbacks(cb_ctx);
    ui->on_refresh_profiles([&] { desktop_ui_helpers::refresh_workspace_from_disk(ws_ctx); });
    ui->on_quit_requested([&] { if (!quit_once.exchange(true, std::memory_order_acq_rel)) slint::quit_event_loop(); });
    ui->window().on_close_requested([&] {
        if (ui->get_close_to_tray() && tray.native_backend_active() && !quit_once.load(std::memory_order_acquire)) {
            window_visible = false;
            on_window_hidden();
            sync_tray();
            return slint::CloseRequestResponse::HideWindow;
        }
        window_visible = false;
        if (!quit_once.exchange(true, std::memory_order_acq_rel)) slint::quit_event_loop();
        return slint::CloseRequestResponse::HideWindow;
    });

    sync_memory_ui();

    slint::Timer telemetry_timer(std::chrono::seconds(1), [&] {
        if (lifecycle_busy.load(std::memory_order_acquire)) return;
        bool const core_up = supervisor.running();
        if (!core_up && (core_started_at || ui->get_core_running())) {
            bool en = is_en_ui(*ui);
            core_started_at.reset();
            ws_ctx.running_selector_members.clear();
            rate_tracker.reset();
            last_ledger_up = 0; last_ledger_down = 0;
            ui->set_core_running(false);
            ui->set_system_proxy_enabled(false);
            worker.post([&sys_proxy] { (void)sys_proxy.restore(); });
            auto err = supervisor.last_error();
            auto msg = err.empty() ? tr(en, "核心意外退出", "Core exited unexpectedly") : (tr(en, "核心已退出: ", "Core exited: ") + err);
            ui->set_diagnostic_ok(false); ui->set_diagnostic_message(slint::SharedString(msg));
            desktop_ui_helpers::push_toast(*ui, msg, "error");
            desktop_ui_helpers::clear_telemetry_ui(*ui);
            sync_tray();
            return;
        }
        // Pause high-frequency memory, metrics, connections & logs UI polling while hidden in tray!
        if (!window_visible) return;
        sync_memory_ui();
        if (core_up) {
            if (!core_started_at) core_started_at = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - *core_started_at);
            ui->set_core_uptime(slint::SharedString(desktop_ui_helpers::format_uptime(elapsed)));
            poll_telemetry(std::string_view(ui->get_active_node()).empty());
            if (ui->get_active_tab() == 2 && !ui->get_connections_paused() && (++conn_poll_tick % 2 == 0) &&
                !conns_in_flight.exchange(true, std::memory_order_acq_rel)) {
                std::string filter(ui->get_connection_filter());
                bool posted = worker.post([&, weak_ui, filter = std::move(filter)] {
                    auto reply = http_ctrl.connections();
                    conns_in_flight.store(false, std::memory_order_release);
                    if (!reply.ok) return;
                    auto items = desktop_ui_helpers::build_ui_connection_items(desktop::parse_connections_json(reply.body), filter);
                    on_ui_thread(weak_ui, [items = std::move(items)](auto& s) mutable {
                        if (s->get_connections_paused()) return;
                        s->set_connections(std::make_shared<slint::VectorModel<nexus_ui::ActiveConnectionItem>>(std::move(items)));
                    });
                });
                if (!posted) conns_in_flight.store(false, std::memory_order_release);
            }
        }
    });

    if (!loaded_prefs.start_minimized || !tray.native_backend_active()) {
        ui->window().show();
        window_visible = true;
    } else {
        window_visible = false;
        desktop::reclaim_process_memory(client_db.get());
    }
    sync_tray();
    slint::run_event_loop(slint::EventLoopMode::RunUntilQuit);
    quit_once.store(true, std::memory_order_release);
    persist_prefs();
    tray.stop();
    probe_worker.stop();
    worker.stop();
    (void)sys_proxy.restore();
    supervisor.stop();
    return 0;
}
