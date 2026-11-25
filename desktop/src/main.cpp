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
#include <sys/wait.h>
#include <unistd.h>
#endif

import std;
import desktop.async_worker;
import desktop.core_supervisor;
import desktop.desktop_host_config;
import desktop.http_control;
import desktop.ipc_client;
import desktop.kdl_ops;
import desktop.profile_store;
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

#include "main_helpers.hpp"
#include "ui_redesign_helpers.hpp"
#include "ui_binding_helpers.hpp"
#include "tun_elevation_flow.hpp"
#include "workspace_ui_flow.hpp"
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
    auto prefs_path = cfg_dir / "ui-prefs.conf";
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
    if (!std::filesystem::exists(config_path, dir_ec)) {
        (void)write_file_atomic(config_path, desktop_ui_helpers::build_default_desktop_config(fallback_sock));
    }
    auto initial_kdl = read_file_text(config_path);
    auto ctl_cfg = desktop_ui_helpers::parse_control_config(initial_kdl, fallback_sock, cfg_dir);

    desktop::CoreSupervisor supervisor(binary_path);
    desktop::IpcClient ipc(ctl_cfg.socket);
    desktop::HttpControlClient http_ctrl(ctl_cfg.http_host, ctl_cfg.http_port, ctl_cfg.bearer_token);
    desktop::SystemProxyController sys_proxy;
    desktop::ProfileStore profile_store(cfg_dir);
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
    int conn_poll_tick = 0;
    desktop::AsyncWorker worker;

    ui->set_control_endpoint(slint::SharedString(ipc.endpoint()));
    ui->set_config_path(slint::SharedString(config_path.string()));
    auto loaded_prefs = desktop::load_ui_prefs(prefs_path);
    desktop_ui_helpers::apply_prefs_to_ui(*ui, loaded_prefs, desktop::detect_system_locale());
    desktop_ui_helpers::clear_telemetry_ui(*ui, is_en_ui(*ui));
    desktop_ui_helpers::apply_kdl_to_ui_state(*ui, initial_kdl);
    worker.post([weak_ui] {
        bool supported = desktop::SystemProxyController::supported();
        on_ui_thread(weak_ui, [supported](auto& s) { s->set_system_proxy_supported(supported); });
    });
    if (auto aid = profile_store.active_id(); !aid.empty()) {
        for (auto const& e : profile_store.list()) {
            if (e.id == aid) { ui->set_active_profile(slint::SharedString(e.name)); break; }
        }
    }

    bool window_visible = true;
    std::function<void()> sync_tray;
    std::atomic<bool> quit_once{false};
    desktop::TrayController tray(desktop_ui_helpers::make_tray_callbacks(weak_ui, window_visible, sync_tray, quit_once));
    sync_tray = [&] {
        desktop_ui_helpers::sync_tray_state(tray, supervisor, *ui, cached_groups, pinned_members, profile_store, window_visible);
    };
    show_window_from_ui = [&] {
        ui->window().show();
        window_visible = true;
        sync_tray();
    };
    ui->set_tray_native_active(tray.native_backend_active());

    auto poll_telemetry = [&](bool refresh_groups_too) {
        desktop_ui_helpers::poll_telemetry_async(
            weak_ui, worker, http_ctrl, cached_groups, pinned_members, member_models, rate_tracker, metrics_in_flight, is_en_ui(*ui), refresh_groups_too, sync_tray);
    };

    ui->on_toggle_system_proxy([&](bool on) {
        auto endpoint = on ? desktop::select_system_proxy_endpoint(desktop_ui_helpers::read_inbounds_from_ui(*ui))
                           : std::nullopt;
        if (on && !endpoint) {
            ui->set_system_proxy_enabled(false);
            ui->set_status_summary(slint::SharedString(tr(is_en_ui(*ui), "请先启用本地入站端口", "Enable a local inbound port first")));
            sync_tray();
            return;
        }
        worker.post([&, weak_ui, on, endpoint] {
            bool ok = on ? sys_proxy.enable(endpoint->first, endpoint->second) : sys_proxy.restore();
            on_ui_thread(weak_ui, [&sync_tray, active = ok && on](auto& s) {
                s->set_system_proxy_enabled(active);
                sync_tray();
            });
        });
    });
    ui->on_apply_inbound_proxy_config([&](slint::SharedString proto, bool enabled, slint::SharedString host, slint::SharedString port_s) {
        bool en = is_en_ui(*ui);
        auto port = desktop::parse_port_u16(std::string_view(port_s));
        if (enabled && !port) {
            ui->set_diagnostic_ok(false);
            ui->set_diagnostic_message(slint::SharedString(tr(en, "入站端口需为 1..65535", "Inbound port must be 1..65535")));
            return;
        }
        auto res = desktop::upsert_managed_inbound(
            std::string_view(ui->get_kdl_text()), std::string_view(proto), enabled, std::string_view(host), port.value_or(0));
        ui->set_diagnostic_ok(res.first);
        if (!res.first) { ui->set_diagnostic_message(slint::SharedString(res.second)); return; }
        ui->set_kdl_text(slint::SharedString(res.second));
        ui->set_kdl_line_count(desktop_ui_helpers::count_kdl_lines(res.second));
        ui->set_diagnostic_message(slint::SharedString(tr(en, "已更新入站: ", "Updated inbound: ") + std::string(proto)));
        ui->invoke_save_and_reload(slint::SharedString(res.second));
        if (ui->get_system_proxy_enabled()) ui->invoke_toggle_system_proxy(true);
        sync_tray();
    });
    ui->on_switch_outbound_mode([&](slint::SharedString mode) {
        bool en = is_en_ui(*ui);
        auto prev_mode = ui->get_outbound_mode();
        auto grp = std::string(ui->get_selected_group());
        std::string m(mode);
        if (supervisor.running()) {
            ui->set_outbound_mode(mode);
            bool posted = worker.post([&, weak_ui, en, m, grp, prev_mode] {
                auto reply = http_ctrl.set_mode(m, grp);
                on_ui_thread(weak_ui, [&sync_tray, ok = reply.ok, en, m, prev_mode, msg = std::move(reply.body)](auto& s) {
                    s->set_diagnostic_ok(ok);
                    if (ok) {
                        s->set_status_summary(slint::SharedString(tr(en, "运行模式已切换: ", "Mode switched: ") + m));
                    } else {
                        s->set_outbound_mode(prev_mode);
                        auto err = tr(en, "切换模式失败: ", "Mode switch failed: ") + msg;
                        s->set_diagnostic_message(slint::SharedString(err));
                        desktop_ui_helpers::push_toast(*s, err, "error");
                    }
                    sync_tray();
                });
            });
            if (!posted) ui->set_outbound_mode(prev_mode);
            return;
        }
        auto res = desktop::apply_outbound_mode(std::string_view(ui->get_kdl_text()), m, grp);
        ui->set_diagnostic_ok(res.first);
        if (!res.first) { ui->set_diagnostic_message(slint::SharedString(res.second)); return; }
        ui->set_outbound_mode(mode);
        ui->set_kdl_text(slint::SharedString(res.second));
        ui->set_kdl_line_count(desktop_ui_helpers::count_kdl_lines(res.second));
        ui->set_status_summary(slint::SharedString(tr(en, "路由模式: ", "Mode: ") + m));
        ui->invoke_save_and_reload(slint::SharedString(res.second));
        sync_tray();
    });

    desktop_ui_helpers::TunFlowContext tun_ctx{
        *ui, weak_ui, worker, supervisor, ipc, http_ctrl, rate_tracker, core_started_at,
        cfg_dir, config_path, prefs_path, fallback_sock, lifecycle_busy, sync_tray
    };
    desktop_ui_helpers::bind_tun_callbacks(tun_ctx);
    desktop_ui_helpers::WorkspaceUiContext ws_ctx{
        *ui, weak_ui, worker, supervisor, ipc, http_ctrl, rate_tracker, core_started_at, lifecycle_busy,
        cfg_dir, config_path, fallback_sock, sync_tray, {}, {}, {}, {}, {}, {}, {}, "proxy", {}, {}
    };
    desktop_ui_helpers::bind_workspace_callbacks(ws_ctx);

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
            ui->set_status_summary(slint::SharedString(tr(en, "核心未运行", "Core is not running")));
            return;
        }
        ui->set_status_summary(slint::SharedString(tr(en, "正在热重载...", "Reloading...")));
        worker.post([&, weak_ui, en] {
            auto reply = ipc.reload();
            if (!reply.ok) {
                if (auto hr = http_ctrl.reload(); hr.ok) reply = {true, "OK"};
            }
            auto msg = reply.ok ? tr(en, "热重载成功", "Reloaded") : (tr(en, "热重载失败: ", "Reload failed: ") + reply.body);
            on_ui_thread(weak_ui, [ok = reply.ok, msg = std::move(msg)](auto& s) {
                s->set_status_summary(slint::SharedString(msg));
                desktop_ui_helpers::push_toast(*s, msg, ok ? "success" : "error");
            });
        });
    });

    ui->on_kdl_edited([&](slint::SharedString text) {
        ui->set_kdl_line_count(desktop_ui_helpers::count_kdl_lines(std::string_view(text)));
    });

    ui->on_validate_kdl([&](slint::SharedString text) {
        bool en = is_en_ui(*ui);
        std::string payload(text);
        ui->set_kdl_line_count(desktop_ui_helpers::count_kdl_lines(payload));
        ui->set_diagnostic_message(slint::SharedString(tr(en, "正在调用内核校验...", "Validating config...")));
        worker.post([&, weak_ui, en, payload = std::move(payload)] {
            auto res = desktop_ui_helpers::validate_draft_config(cfg_dir, supervisor, payload, en);
            on_ui_thread(weak_ui, [ok = res.ok, msg = std::move(res.message)](auto& s) {
                s->set_diagnostic_ok(ok);
                s->set_diagnostic_message(slint::SharedString(msg));
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
                    s->set_diagnostic_ok(false);
                    s->set_diagnostic_message(slint::SharedString(msg));
                    if (!disk_kdl.empty()) desktop_ui_helpers::apply_kdl_to_ui_state(*s, disk_kdl);
                    sync_tray();
                    desktop_ui_helpers::push_toast(*s, msg, "error");
                });
                return;
            }
            bool saved = write_file_atomic(config_path, payload);
            std::string disk_kdl;
            if (!saved) disk_kdl = read_file_text(config_path);
            desktop::IpcReply reply{saved, saved ? tr(en, "已保存", "Saved") : tr(en, "写入失败", "Write failed")};
            std::string synced_sock;
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
                    synced_sock = next_ctl.socket;
                }
            }
            std::string msg = !saved ? tr(en, "写入配置文件失败", "Failed to write config file")
                : (reply.ok ? tr(en, "校验通过，已保存并热重载", "Saved & reloaded") : (tr(en, "已保存，但重载失败: ", "Saved; reload failed: ") + reply.body));
            on_ui_thread(weak_ui, [&sync_tray, ok = saved && reply.ok, saved, payload, disk_kdl = std::move(disk_kdl), synced_sock = std::move(synced_sock), msg = std::move(msg)](auto& s) {
                if (saved) {
                    desktop_ui_helpers::apply_kdl_to_ui_state(*s, payload);
                    if (!synced_sock.empty()) s->set_control_endpoint(slint::SharedString(synced_sock));
                } else {
                    s->set_tun_enabled(desktop_ui_helpers::kdl_has_tun_inbound(disk_kdl));
                }
                s->set_diagnostic_ok(ok);
                s->set_diagnostic_message(slint::SharedString(msg));
                sync_tray();
                desktop_ui_helpers::push_toast(*s, msg, ok ? "success" : "error");
            });
        });
    });

    ui->on_open_external_editor([&] { open_with_system_editor(config_path); });

    ui->on_refresh_metrics([&] { poll_telemetry(true); });
    ui->global<nexus_ui::ToastState>().set_has_endpoint_formatter(true);
    ui->global<nexus_ui::ToastState>().on_format_endpoint_cb([](slint::SharedString h, slint::SharedString p) {
        return slint::SharedString(desktop::format_host_port(std::string_view(h), std::string_view(p)));
    });
    ui->on_copy_text([&](slint::SharedString text) {
        std::string s(text);
        worker.post([s = std::move(s)] { (void)desktop_ui_helpers::copy_text_to_clipboard(s); });
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
    desktop_ui_helpers::bind_dash_layout_callbacks(*ui, prefs_path);

    ui->on_clear_cache([&] {
        bool en = is_en_ui(*ui);
        worker.post([&, weak_ui, en] {
            auto reply = http_ctrl.clear_cache();
            auto msg = reply.ok ? tr(en, "缓存已清空", "Cache cleared") : (tr(en, "清空缓存失败: ", "Clear cache failed: ") + reply.body);
            on_ui_thread(weak_ui, [ok = reply.ok, msg = std::move(msg)](auto& s) {
                s->set_status_summary(slint::SharedString(msg));
                desktop_ui_helpers::push_toast(*s, msg, ok ? "success" : "error");
            });
        });
    });

    ui->on_import_share_link([&](slint::SharedString raw_uri) {
        desktop_ui_helpers::import_share_uri_to_workspace(ws_ctx, std::string_view(raw_uri));
    });

    desktop_ui_helpers::DesktopCallbacksContext cb_ctx{
        *ui, weak_ui, worker, supervisor, ipc, http_ctrl, profile_store,
        cfg_dir, config_path, fallback_sock, cached_groups, pinned_members, member_models, cached_logs, logs_mu, sync_tray
    };
    struct ShutdownGuard {
        std::atomic<bool>& quit_once;
        desktop::TrayController& tray;
        desktop::AsyncWorker& worker;
        ~ShutdownGuard() {
            quit_once.store(true, std::memory_order_release);
            tray.stop();
            worker.stop();
        }
    } shutdown_guard{quit_once, tray, worker};
    desktop_ui_helpers::bind_secondary_callbacks(cb_ctx);
    ui->on_refresh_profiles([&] {
        desktop_ui_helpers::sync_profiles_to_ui(*ui, profile_store);
        desktop_ui_helpers::refresh_workspace_from_disk(ws_ctx);
    });
    ui->on_quit_requested([&] { if (!quit_once.exchange(true, std::memory_order_acq_rel)) slint::quit_event_loop(); });
    ui->window().on_close_requested([&] {
        if (ui->get_close_to_tray() && tray.native_backend_active() && !quit_once.load(std::memory_order_acquire)) {
            window_visible = false;
            sync_tray();
            return slint::CloseRequestResponse::HideWindow;
        }
        window_visible = false;
        if (!quit_once.exchange(true, std::memory_order_acq_rel)) slint::quit_event_loop();
        return slint::CloseRequestResponse::HideWindow;
    });

    auto sync_memory_ui = [&] {
        auto app_rss = desktop::current_process_memory_bytes();
        auto core_rss = supervisor.running() ? supervisor.memory_bytes() : 0ULL;
        auto total_rss = app_rss + core_rss;
        ui->set_app_memory_text(slint::SharedString(app_rss > 0 ? desktop_ui_helpers::format_bytes_human(app_rss) : "--"));
        ui->set_core_memory_text(slint::SharedString(core_rss > 0 ? desktop_ui_helpers::format_bytes_human(core_rss) : "--"));
        ui->set_total_memory_text(slint::SharedString(total_rss > 0 ? desktop_ui_helpers::format_bytes_human(total_rss) : "--"));
        ui->set_app_memory_ratio(total_rss > 0 ? static_cast<float>(static_cast<double>(app_rss) / static_cast<double>(total_rss)) : 1.0f);
    };
    desktop_ui_helpers::sync_profiles_to_ui(*ui, profile_store);
    sync_memory_ui();

    slint::Timer telemetry_timer(std::chrono::seconds(1), [&] {
        if (lifecycle_busy.load(std::memory_order_acquire)) return;
        sync_memory_ui();
        if (supervisor.running()) {
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
        } else if (core_started_at || ui->get_core_running()) {
            bool en = is_en_ui(*ui);
            core_started_at.reset();
            ws_ctx.running_selector_members.clear();
            rate_tracker.reset();
            ui->set_core_running(false);
            ui->set_system_proxy_enabled(false);
            worker.post([&sys_proxy] { (void)sys_proxy.restore(); });
            auto err = supervisor.last_error();
            auto msg = err.empty() ? tr(en, "核心意外退出", "Core exited unexpectedly") : (tr(en, "核心已退出: ", "Core exited: ") + err);
            ui->set_diagnostic_ok(false);
            ui->set_diagnostic_message(slint::SharedString(msg));
            ui->set_status_summary(slint::SharedString(msg));
            desktop_ui_helpers::push_toast(*ui, msg, "error");
            desktop_ui_helpers::clear_telemetry_ui(*ui, en);
            sync_tray();
        }
    });

    if (!loaded_prefs.start_minimized || !tray.native_backend_active()) {
        ui->window().show();
        window_visible = true;
    } else {
        window_visible = false;
    }
    sync_tray();
    slint::run_event_loop(slint::EventLoopMode::RunUntilQuit);
    quit_once.store(true, std::memory_order_release);
    (void)desktop::save_ui_prefs(prefs_path, desktop_ui_helpers::capture_prefs_from_ui(*ui));
    tray.stop();
    worker.stop();
    (void)sys_proxy.restore();
    supervisor.stop();
    return 0;
}
