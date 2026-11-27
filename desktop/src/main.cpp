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
import desktop.share_link;
import desktop.single_instance;
import desktop.system_proxy;
import desktop.telemetry_store;
import desktop.tray_controller;
import desktop.tun_privilege;
import desktop.ui_actions;
import desktop.ui_prefs;
import desktop.workspace_composer;
import desktop.workspace_models;
import desktop.workspace_store;
import desktop.workspace_sync;

#include "main_helpers.hpp"
#include "ui_redesign_helpers.hpp"
#include "ui_binding_helpers.hpp"
#include "workspace_ui_flow.hpp"
#include "tun_elevation_flow.hpp"
#include "main_quick_controls.hpp"
#include "main_callbacks.hpp"
#include "main_inspect_callbacks.hpp"
#include "main_palette_callbacks.hpp"

using desktop_ui_helpers::default_config_dir;
using desktop_ui_helpers::is_en_ui;
using desktop_ui_helpers::on_ui_thread;
using desktop_ui_helpers::tr;

auto main(int argc, char** argv) -> int {
    (void)argc;
#ifndef _WIN32
    std::signal(SIGPIPE, SIG_IGN);
#endif
    auto cfg_dir = default_config_dir();
    std::error_code dir_ec;
    std::filesystem::create_directories(cfg_dir, dir_ec);
    auto config_path = cfg_dir / "config.kdl";
    auto binary_path = desktop_ui_helpers::resolve_core_binary(argv[0]);
    slint::set_xdg_app_id("nexus-desktop");

    auto ui = nexus_ui::AppWindow::create();
    slint::ComponentWeakHandle<nexus_ui::AppWindow> weak_ui(ui);

    std::function<void()> show_window_from_ui;
    auto instance = desktop::SingleInstanceGuard::acquire("nexus-desktop", [weak_ui, &show_window_from_ui] {
        on_ui_thread(weak_ui, [&show_window_from_ui](auto& s) {
            if (show_window_from_ui) show_window_from_ui();
            else s->window().show();
        });
    });
    if (!instance) return 0;

    std::unique_ptr<desktop::ClientDatabase> client_db;
    std::string db_open_error;
    if (auto opened = desktop::ClientDatabase::open(cfg_dir / "nexus-client.db"); opened) {
        client_db = std::make_unique<desktop::ClientDatabase>(std::move(*opened));
    } else {
        db_open_error = opened.error();
    }

    desktop::CoreSupervisor supervisor(binary_path);
    desktop::HttpControlClient http_ctrl("127.0.0.1", 19090);
    desktop::SystemProxyController sys_proxy;
    std::vector<desktop::OutboundGroupSnapshot> cached_groups;
    std::unordered_set<std::string> pinned_members;
    desktop_ui_helpers::MemberModelPipeline member_models;
    desktop_ui_helpers::ConnectionsModelPipeline conn_models;
    desktop_ui_helpers::LogsModelPipeline log_models;
    ui->set_members(member_models.sorted);
    ui->set_connections(conn_models.model);
    ui->set_logs(log_models.model);
    std::vector<desktop::LogEntrySnapshot> cached_logs;
    std::mutex logs_mu;
    std::atomic<std::uint64_t> last_log_seq{0};
    desktop_ui_helpers::RateTracker rate_tracker;
    desktop_ui_helpers::CpuUsageTracker app_cpu_tracker;
    desktop_ui_helpers::CpuUsageTracker core_cpu_tracker;
    std::uint64_t last_core_pid = 0;
    std::optional<std::chrono::steady_clock::time_point> core_started_at;
    std::atomic<bool> metrics_in_flight{false};
    std::atomic<bool> conns_in_flight{false};
    std::atomic<bool> lifecycle_busy{false};
    std::uint64_t last_ledger_up = 0, last_ledger_down = 0;
    int conn_poll_tick = 0;
    int hidden_metrics_tick = 0;
    desktop::AsyncWorker worker;
    desktop::AsyncWorker probe_worker;

    auto loaded_prefs = (client_db ? desktop::load_ui_prefs_from_db(*client_db) : std::nullopt)
                            .value_or(desktop::UiPrefs{});
    desktop_ui_helpers::apply_prefs_to_ui(*ui, loaded_prefs, desktop::detect_system_locale());
    desktop_ui_helpers::clear_telemetry_ui(*ui);
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
        *ui, weak_ui, worker, supervisor, http_ctrl, rate_tracker, core_started_at, lifecycle_busy,
        cfg_dir, config_path, sync_tray, client_db.get(), {}, {}, {}, {}, {}, {}, "proxy", {}, {}
    };

    desktop::TrayController tray(desktop_ui_helpers::make_tray_callbacks(
        weak_ui, window_visible, sync_tray, on_window_shown, on_window_hidden, quit_once));
    sync_tray = [&] {
        desktop_ui_helpers::sync_tray_state(
            tray, supervisor, *ui, cached_groups, pinned_members, ws_ctx.doc, ws_ctx.telemetry.active_profile_id, window_visible);
    };
    ui->set_tray_native_active(tray.native_backend_active());

    auto sync_perf_ui = [&] {
        auto app_pid = desktop::current_process_id();
        auto app_priv = desktop::current_process_memory_bytes();
        auto app_cpu = app_cpu_tracker.record(desktop::current_process_cpu_time_ns());
        ui->set_app_pid_text(slint::SharedString(app_pid > 0 ? std::format("PID {}", app_pid) : "--"));
        ui->set_app_cpu_text(slint::SharedString(app_cpu.text));
        ui->set_app_cpu_ratio(app_cpu.ratio);
        ui->set_app_memory_text(slint::SharedString(app_priv > 0 ? desktop_ui_helpers::format_bytes_human(app_priv) : "--"));

        bool const core_up = supervisor.running();
        auto core_pid = core_up ? supervisor.process_id() : 0ULL;
        if (!core_up || core_pid != last_core_pid) {
            core_cpu_tracker.reset();
            last_core_pid = core_pid;
        }
        if (core_up) {
            auto core_priv = supervisor.memory_bytes();
            auto core_cpu = core_cpu_tracker.record(supervisor.cpu_time_ns());
            ui->set_core_pid_text(slint::SharedString(core_pid > 0 ? std::format("PID {}", core_pid) : ""));
            ui->set_core_cpu_text(slint::SharedString(core_cpu.text));
            ui->set_core_cpu_ratio(core_cpu.ratio);
            ui->set_core_memory_text(slint::SharedString(core_priv > 0 ? desktop_ui_helpers::format_bytes_human(core_priv) : "--"));
        } else {
            ui->set_core_pid_text(slint::SharedString(""));
            ui->set_core_cpu_text(slint::SharedString("--"));
            ui->set_core_cpu_ratio(0.0f);
            ui->set_core_memory_text(slint::SharedString("--"));
        }
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

    desktop_ui_helpers::LiveInspectController inspect_ctrl{
        *ui, weak_ui, worker, probe_worker, supervisor, http_ctrl, tray,
        cached_groups, pinned_members, member_models, conn_models, log_models, rate_tracker,
        cached_logs, logs_mu, last_log_seq, sync_tray, record_traffic_totals
    };

    on_window_shown = [&] {
        sync_perf_ui();
        if (supervisor.running()) {
            poll_telemetry(std::string_view(ui->get_active_node()).empty());
            if ((ui->get_active_tab() == 0 || ui->get_active_tab() == 2) && !ui->get_connections_paused()) ui->invoke_refresh_connections();
            if (ui->get_active_tab() == 4) ui->invoke_refresh_logs();
            inspect_ctrl.sync_log_stream(true);
        }
    };
    on_window_hidden = [&] {
        inspect_ctrl.stop_log_stream();
        ui->set_rule_modal_open(false);
        ui->set_outbound_modal_open(false);
        ui->global<nexus_ui::CommandPaletteState>().invoke_close_palette();
        ui->global<nexus_ui::TooltipState>().invoke_hide();
        if (!ui->get_tray_show_speed()) {
            ui->set_download_rate(slint::SharedString("0.0 KB/s"));
            ui->set_upload_rate(slint::SharedString("0.0 KB/s"));
        }
        { std::lock_guard lk(logs_mu); cached_logs.clear(); }
        log_models.clear();
        conn_models.clear();
        worker.post([db = client_db.get()] { desktop::reclaim_process_memory(db); });
    };
    show_window_from_ui = [&] {
        ui->window().show();
        window_visible = true;
        on_window_shown();
        sync_tray();
    };

    desktop_ui_helpers::bind_quick_control_callbacks(ws_ctx, sys_proxy, persist_prefs);
    desktop_ui_helpers::bind_workspace_callbacks(ws_ctx);
    desktop_ui_helpers::bind_tun_callbacks(ws_ctx, persist_prefs);

    ui->on_activate_profile([&](slint::SharedString id) {
        ui->global<nexus_ui::WorkspaceState>().invoke_activate_profile(id);
    });
    ui->on_toggle_core([&] {
        inspect_ctrl.reset_ws_fallback();
        if (!supervisor.running()) last_log_seq.store(0, std::memory_order_release);
        desktop_ui_helpers::toggle_core_with_workspace(ws_ctx, [&](std::string cfg_text, bool prefer_persistent, bool en) {
            desktop_ui_helpers::toggle_core_async(
                weak_ui, worker, supervisor, sys_proxy, http_ctrl, sync_tray, cached_groups, pinned_members, member_models, rate_tracker,
                core_started_at, metrics_in_flight, lifecycle_busy, cfg_dir, config_path, std::move(cfg_text), prefer_persistent, en);
        });
    });

    ui->on_reload_config([&] {
        bool en = is_en_ui(*ui);
        if (!supervisor.running()) {
            desktop_ui_helpers::push_toast(*ui, tr(en, "核心未运行", "Core is not running"), "warn");
            return;
        }
        worker.post([&, weak_ui, en] {
            auto hr = http_ctrl.reload();
            auto msg = hr.ok ? tr(en, "热重载成功", "Reloaded") : (tr(en, "热重载失败: ", "Reload failed: ") + hr.body);
            on_ui_thread(weak_ui, [&rate_tracker, en, ok = hr.ok, msg = std::move(msg)](auto& s) {
                if (ok) rate_tracker.mark_onset(tr(en, "重载", "Reload"));
                desktop_ui_helpers::push_toast(*s, msg, ok ? "success" : "error");
            });
        });
    });

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
    ui->on_ui_prefs_changed(persist_prefs);
    ui->on_clear_cache([&] {
        bool en = is_en_ui(*ui);
        bool const core_up = supervisor.running();
        worker.post([&, weak_ui, en, core_up, db = client_db.get()] {
            bool ok = true;
            std::string err;
            if (core_up) {
                auto reply = http_ctrl.clear_cache();
                ok = reply.ok;
                if (!ok) err = reply.body;
            }
            desktop::reclaim_process_memory(db);
            auto msg = ok ? tr(en, "缓存与内存已整理", "Cache cleared & memory trimmed")
                          : (tr(en, "清空缓存失败: ", "Clear cache failed: ") + err);
            on_ui_thread(weak_ui, [&sync_perf_ui, ok, msg = std::move(msg)](auto& s) {
                sync_perf_ui();
                desktop_ui_helpers::push_toast(*s, msg, ok ? "success" : "error");
            });
        });
    });
    ui->on_import_share_link([&](slint::SharedString raw_uri) {
        desktop_ui_helpers::import_share_uri_to_workspace(ws_ctx, std::string_view(raw_uri));
    });

    desktop_ui_helpers::DesktopCallbacksContext cb_ctx{
        *ui, weak_ui, worker, probe_worker, supervisor, http_ctrl, client_db.get(), ws_ctx,
        cfg_dir, config_path, cached_groups, pinned_members, member_models, conn_models, log_models,
        rate_tracker, cached_logs, logs_mu, last_log_seq, sync_tray
    };
    desktop_ui_helpers::CommandPaletteController palette_ctrl{
        *ui, weak_ui, probe_worker, supervisor, http_ctrl, ws_ctx,
        cfg_dir, config_path, cached_groups, persist_prefs
    };
    struct ShutdownGuard {
        std::atomic<bool>& quit_once;
        desktop_ui_helpers::LiveInspectController& inspect_ctrl;
        desktop::TrayController& tray;
        desktop::AsyncWorker& worker;
        desktop::AsyncWorker& probe_worker;
        ~ShutdownGuard() {
            quit_once.store(true, std::memory_order_release);
            inspect_ctrl.stop_log_stream();
            tray.stop();
            probe_worker.stop();
            worker.stop();
        }
    } shutdown_guard{quit_once, inspect_ctrl, tray, worker, probe_worker};
    desktop_ui_helpers::bind_secondary_callbacks(cb_ctx);
    inspect_ctrl.bind();
    palette_ctrl.bind();
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

    sync_perf_ui();

    // Trim transient startup allocations once initial UI layout settles.
    slint::Timer startup_trim_timer;
    startup_trim_timer.start(slint::TimerMode::SingleShot, std::chrono::milliseconds(2500), [&] {
        worker.post([db = client_db.get(), weak_ui, &sync_perf_ui] {
            desktop::reclaim_process_memory(db);
            on_ui_thread(weak_ui, [&sync_perf_ui](auto&) { sync_perf_ui(); });
        });
    });

    slint::Timer telemetry_timer(std::chrono::seconds(1), [&] {
        if (lifecycle_busy.load(std::memory_order_acquire)) return;
        bool const core_up = supervisor.running();
        if (!core_up && (core_started_at || ui->get_core_running())) {
            bool en = is_en_ui(*ui);
            inspect_ctrl.reset_ws_fallback();
            inspect_ctrl.stop_log_stream();
            last_log_seq.store(0, std::memory_order_release);
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
            (void)tray.notify_if_hidden("Nexus", msg, desktop::TrayNotificationUrgency::error);
            desktop_ui_helpers::clear_telemetry_ui(*ui);
            sync_tray();
            return;
        }
        if (!window_visible) {
            if (core_up && ui->get_tray_show_speed() && (++hidden_metrics_tick % 5 == 0)) {
                poll_telemetry(false);
            }
            return;
        }
        sync_perf_ui();
        inspect_ctrl.sync_log_stream(core_up);
        if (core_up) {
            if (!core_started_at) core_started_at = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - *core_started_at);
            ui->set_core_uptime(slint::SharedString(desktop_ui_helpers::format_uptime(elapsed)));
            bool const ws_up = inspect_ctrl.ws_live();
            if (!ws_up) {
                poll_telemetry(std::string_view(ui->get_active_node()).empty());
            }
            if (!ws_up && (ui->get_active_tab() == 0 || ui->get_active_tab() == 2) && !ui->get_connections_paused() && (++conn_poll_tick % 2 == 0) &&
                !conns_in_flight.exchange(true, std::memory_order_acq_rel)) {
                bool posted = worker.post([&, weak_ui] {
                    auto reply = http_ctrl.connections();
                    conns_in_flight.store(false, std::memory_order_release);
                    if (!reply.ok) return;
                    auto parsed = desktop::parse_connections_json(reply.body);
                    on_ui_thread(weak_ui, [&conn_models, parsed = std::move(parsed)](auto& s) mutable {
                        if (s->get_connections_paused()) return;
                        conn_models.replace(std::move(parsed));
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
    inspect_ctrl.stop_log_stream();
    tray.stop();
    probe_worker.stop();
    worker.stop();
    (void)sys_proxy.restore();
    supervisor.stop();
    return 0;
}
