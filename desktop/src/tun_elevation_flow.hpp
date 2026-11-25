// End-to-end TUN privilege probing, elevation, core start/stop, and rollback orchestration for desktop/src/main.cpp.
#pragma once

namespace desktop_ui_helpers {
    inline auto tun_status_to_ui_string(desktop::TunPrivilegeStatus st) noexcept -> std::string_view {
        switch (st) {
        case desktop::TunPrivilegeStatus::ready_root_or_admin: return "ready_root";
        case desktop::TunPrivilegeStatus::ready_persistent_cap: return "ready_persistent";
        case desktop::TunPrivilegeStatus::needs_elevation: return "needs_elevation";
        case desktop::TunPrivilegeStatus::unavailable: return "unavailable";
        }
        return "unavailable";
    }

    inline auto apply_tun_probe_to_ui(nexus_ui::AppWindow& ui, desktop::TunPrivilegeProbe const& p) -> void {
        ui.set_tun_privilege_status(slint::SharedString(tun_status_to_ui_string(p.status)));
        ui.set_tun_persistent_granted(p.has_persistent_grant);
        ui.set_tun_can_persist(p.supports_persistent);
    }

    inline auto probe_tun_privilege_async(
        slint::ComponentWeakHandle<nexus_ui::AppWindow> weak_ui,
        desktop::AsyncWorker& worker,
        std::filesystem::path binary_path) -> void {
        worker.post([weak_ui = std::move(weak_ui), binary_path = std::move(binary_path)]() mutable {
            auto probe = desktop::probe_tun_privilege(binary_path);
            on_ui_thread(weak_ui, [probe = std::move(probe)](auto& s) {
                apply_tun_probe_to_ui(*s, probe);
            });
        });
    }

    inline auto resolve_tun_elevation_for_start(
        std::filesystem::path const& binary_path,
        std::filesystem::path const& config_path,
        std::filesystem::path const& workdir,
        bool prefer_persistent,
        bool en,
        desktop::CoreStartOptions& out_opts,
        desktop::TunPrivilegeProbe& out_probe) -> desktop::ElevationResult {
        out_opts = {};
        out_probe = desktop::probe_tun_privilege(binary_path);
        if (out_probe.status == desktop::TunPrivilegeStatus::ready_root_or_admin) {
            return {true, false, {}};
        }
        if (out_probe.status == desktop::TunPrivilegeStatus::ready_persistent_cap) {
            out_opts.use_persistent_helper = out_probe.helper_required_for_persistent;
            return {true, false, {}};
        }
        if (out_probe.status == desktop::TunPrivilegeStatus::unavailable) {
            return {false, false, out_probe.detail.empty()
                ? tr(en, "当前环境不支持 TUN 提权", "TUN elevation is unavailable on this host")
                : out_probe.detail};
        }
        if (prefer_persistent && out_probe.supports_persistent) {
            auto grant = desktop::grant_persistent_tun_privilege(binary_path, en, config_path, workdir);
            out_probe = desktop::probe_tun_privilege(binary_path);
            if (!grant.ok) return grant;
            if (out_probe.status == desktop::TunPrivilegeStatus::ready_persistent_cap) {
                out_opts.use_persistent_helper = out_probe.helper_required_for_persistent;
                return {true, false, grant.message};
            }
            if (out_probe.status == desktop::TunPrivilegeStatus::ready_root_or_admin) {
                return {true, false, grant.message};
            }
            if (out_probe.supports_session_only) {
                out_opts.elevate_session = true;
                return {true, false, grant.message};
            }
            return {false, false, grant.message};
        }
        if (out_probe.supports_session_only) {
            out_opts.elevate_session = true;
            return {true, false, {}};
        }
        return {false, false, out_probe.detail.empty()
            ? tr(en, "缺少按次提权所需系统工具", "Session-only elevation helper unavailable on host")
            : out_probe.detail};
    }

    inline auto toggle_core_async(
        slint::ComponentWeakHandle<nexus_ui::AppWindow> weak_ui,
        desktop::AsyncWorker& worker,
        desktop::CoreSupervisor& supervisor,
        desktop::SystemProxyController& sys_proxy,
        desktop::IpcClient& ipc,
        desktop::HttpControlClient& http_ctrl,
        std::function<void()> on_tray_sync,
        std::vector<desktop::OutboundGroupSnapshot>& cached_groups,
        std::unordered_set<std::string> const& pinned_members,
        MemberModelPipeline& member_models,
        RateTracker& rate_tracker,
        std::optional<std::chrono::steady_clock::time_point>& core_started_at,
        std::atomic<bool>& metrics_in_flight,
        std::atomic<bool>& core_toggling,
        std::filesystem::path const& cfg_dir,
        std::filesystem::path const& config_path,
        std::string fallback_sock,
        std::string draft_kdl,
        bool prefer_persistent_tun,
        bool en) -> void {
        bool posted = worker.post([&, weak_ui, en, prefer_persistent_tun, on_tray_sync = std::move(on_tray_sync),
                                   draft_kdl = std::move(draft_kdl), fallback_sock = std::move(fallback_sock)]() mutable {
            bool running = false;
            bool cancelled = false;
            std::optional<desktop::TunPrivilegeProbe> refreshed_probe;
            std::string summary, diag_err, new_kdl, synced_sock;
            if (supervisor.running()) {
                (void)sys_proxy.restore();
                supervisor.stop();
                diag_err = supervisor.last_error();
                summary = diag_err.empty() ? tr(en, "已断开", "Disconnected")
                                           : (tr(en, "停止核心警告: ", "Stop warning: ") + diag_err);
            } else {
                auto prep = prepare_config_before_start(cfg_dir, config_path, supervisor, std::move(draft_kdl), fallback_sock, en);
                if (!prep.ok) {
                    diag_err = prep.error_message;
                    summary = tr(en, "配置校验未通过: ", "Config invalid: ") + diag_err;
                } else {
                    if (prep.synthesized_default) new_kdl = std::move(prep.kdl_text);
                    ipc.set_endpoint(prep.control.socket);
                    http_ctrl.set_endpoint(prep.control.http_host, prep.control.http_port);
                    http_ctrl.set_bearer_token(prep.control.bearer_token);
                    synced_sock = prep.control.socket;

                    desktop::CoreStartOptions start_opts{};
                    bool elev_ok = true;
                    auto const& active_kdl = prep.synthesized_default ? new_kdl : prep.kdl_text;
                    if (kdl_has_tun_inbound(active_kdl)) {
                        desktop::TunPrivilegeProbe p{};
                        auto elev = resolve_tun_elevation_for_start(
                            supervisor.binary_path(), config_path, cfg_dir, prefer_persistent_tun, en, start_opts, p);
                        refreshed_probe = std::move(p);
                        if (!elev.ok) {
                            elev_ok = false;
                            cancelled = elev.cancelled;
                            diag_err = elev.message;
                            summary = elev.cancelled ? elev.message : (tr(en, "TUN 提权失败: ", "TUN elevation failed: ") + elev.message);
                        }
                    }

                    if (elev_ok) {
                        if (supervisor.start(config_path, start_opts)) {
                            running = true;
                            summary = start_opts.elevate_session ? tr(en, "已连接 (按次提权 TUN)", "Connected (Session TUN)")
                                    : start_opts.use_persistent_helper ? tr(en, "已连接 (持久服务 TUN)", "Connected (Helper TUN)")
                                                                       : tr(en, "已连接", "Connected");
                        } else {
                            cancelled = supervisor.last_start_cancelled();
                            diag_err = supervisor.last_error();
                            summary = cancelled
                                ? tr(en, "已取消权限授权，核心未启动", "Authorization cancelled; core remained stopped")
                                : (diag_err.empty()
                                    ? tr(en, "启动失败：请检查内核与配置", "Start failed: check core and config")
                                    : (tr(en, "启动失败: ", "Start failed: ") + diag_err));
                        }
                    }
                }
            }
            slint::invoke_from_event_loop([&, weak_ui, running, cancelled, on_tray_sync = std::move(on_tray_sync),
                                           refreshed_probe = std::move(refreshed_probe),
                                           summary = std::move(summary), diag_err = std::move(diag_err),
                                           new_kdl = std::move(new_kdl), synced_sock = std::move(synced_sock), en]() mutable {
                if (auto strong = weak_ui.lock()) {
                    auto& s = **strong;
                    if (refreshed_probe) apply_tun_probe_to_ui(s, *refreshed_probe);
                    s.set_core_running(running);
                    if (!new_kdl.empty()) apply_kdl_to_ui_state(s, new_kdl);
                    if (!synced_sock.empty()) s.set_control_endpoint(slint::SharedString(synced_sock));
                    s.set_diagnostic_ok(diag_err.empty() || cancelled);
                    s.set_diagnostic_message(slint::SharedString(cancelled ? "" : diag_err));
                    if (running) {
                        core_started_at = std::chrono::steady_clock::now();
                        rate_tracker.reset();
                        s.set_core_uptime(slint::SharedString("00:00:00"));
                        poll_telemetry_async(weak_ui, worker, http_ctrl, cached_groups, pinned_members, member_models, rate_tracker,
                                             metrics_in_flight, en, true, on_tray_sync);
                    } else {
                        core_started_at.reset();
                        rate_tracker.reset();
                        s.set_system_proxy_enabled(false);
                        clear_telemetry_ui(s, en);
                    }
                    s.set_status_summary(slint::SharedString(summary));
                    s.set_core_toggling(false);
                    push_toast(s, summary, cancelled ? "warn" : !diag_err.empty() ? "error" : running ? "success" : "info");
                    if (on_tray_sync) on_tray_sync();
                }
                core_toggling.store(false, std::memory_order_release);
            });
        });
        if (!posted) {
            core_toggling.store(false, std::memory_order_release);
            on_ui_thread(weak_ui, [](auto& s) { s->set_core_toggling(false); });
        }
    }

    struct TunFlowContext {
        nexus_ui::AppWindow& ui;
        slint::ComponentWeakHandle<nexus_ui::AppWindow> weak_ui;
        desktop::AsyncWorker& worker;
        desktop::CoreSupervisor& supervisor;
        desktop::IpcClient& ipc;
        desktop::HttpControlClient& http_ctrl;
        RateTracker& rate_tracker;
        std::optional<std::chrono::steady_clock::time_point>& core_started_at;
        std::filesystem::path const& cfg_dir;
        std::filesystem::path const& config_path;
        std::filesystem::path const& prefs_path;
        std::string const& fallback_sock;
        std::atomic<bool>& lifecycle_busy;
        std::function<void()>& sync_tray;
    };

    inline auto bind_tun_callbacks(TunFlowContext& ctx) -> void {
        probe_tun_privilege_async(ctx.weak_ui, ctx.worker, ctx.supervisor.binary_path());

        ctx.ui.on_tray_prefs_changed([&ctx] {
            (void)desktop::save_ui_prefs(ctx.prefs_path, capture_prefs_from_ui(ctx.ui));
            if (ctx.sync_tray) ctx.sync_tray();
        });

        ctx.ui.on_toggle_tun([&ctx](bool on) {
            if (ctx.lifecycle_busy.exchange(true, std::memory_order_acq_rel)) {
                ctx.ui.set_tun_enabled(!on);
                return;
            }
            bool const en = is_en_ui(ctx.ui);
            bool const prefer_persistent = ctx.ui.get_tun_elevate_persistent();
            std::string prev_kdl(ctx.ui.get_kdl_text());
            ctx.ui.set_tun_privilege_busy(true);
            ctx.ui.set_core_toggling(true);
            ctx.ui.set_status_summary(slint::SharedString(
                on ? tr(en, "正在准备 TUN 权限与配置...", "Preparing TUN privileges & config...")
                   : tr(en, "正在关闭 TUN 模式...", "Disabling TUN mode...")));

            bool posted = ctx.worker.post([&ctx, on, en, prefer_persistent, prev_kdl = std::move(prev_kdl)]() mutable {
                auto finish_err = [&](std::string msg, std::string tone, std::optional<desktop::TunPrivilegeProbe> probe = std::nullopt,
                                      std::optional<bool> core_running_override = std::nullopt) {
                    on_ui_thread(ctx.weak_ui, [&ctx, on, msg = std::move(msg), tone = std::move(tone),
                                               prev_kdl, probe = std::move(probe), core_running_override](auto& s) {
                        if (probe) apply_tun_probe_to_ui(*s, *probe);
                        apply_kdl_to_ui_state(*s, prev_kdl);
                        s->set_tun_enabled(!on);
                        if (core_running_override) {
                            s->set_core_running(*core_running_override);
                            if (*core_running_override) {
                                ctx.core_started_at = std::chrono::steady_clock::now();
                                ctx.rate_tracker.reset();
                                s->set_core_uptime(slint::SharedString("00:00:00"));
                            } else {
                                ctx.core_started_at.reset();
                                ctx.rate_tracker.reset();
                            }
                        }
                        s->set_diagnostic_ok(tone == "warn" || tone == "info");
                        s->set_diagnostic_message(slint::SharedString(msg));
                        s->set_status_summary(slint::SharedString(msg));
                        s->set_tun_privilege_busy(false);
                        s->set_core_toggling(false);
                        push_toast(*s, msg, tone);
                        if (ctx.sync_tray) ctx.sync_tray();
                        ctx.lifecycle_busy.store(false, std::memory_order_release);
                    });
                };

                auto next_res = toggle_tun_in_kdl(prev_kdl, on, en);
                if (!next_res.first) { finish_err(next_res.second, "error"); return; }

                auto val = validate_draft_config(ctx.cfg_dir, ctx.supervisor, next_res.second, en);
                if (!val.ok) {
                    finish_err(tr(en, "TUN 配置校验未通过: ", "TUN config invalid: ") + val.message, "error");
                    return;
                }

                if (on) {
                    desktop::CoreStartOptions start_opts{};
                    desktop::TunPrivilegeProbe probe{};
                    auto elev = resolve_tun_elevation_for_start(
                        ctx.supervisor.binary_path(), ctx.config_path, ctx.cfg_dir, prefer_persistent, en, start_opts, probe);
                    if (!elev.ok) {
                        finish_err(elev.message, elev.cancelled ? "warn" : "error", probe);
                        return;
                    }
                    if (!write_file_atomic(ctx.config_path, next_res.second)) {
                        finish_err(tr(en, "写入配置文件失败", "Failed to write config file"), "error", probe);
                        return;
                    }
                    bool const was_running = ctx.supervisor.running();
                    std::string synced_sock;
                    if (was_running) {
                        ctx.supervisor.stop();
                        if (!ctx.supervisor.start(ctx.config_path, start_opts)) {
                            bool const cancelled = ctx.supervisor.last_start_cancelled();
                            auto reason = cancelled
                                ? tr(en, "已取消提权，已回滚并恢复原有连接", "Elevation cancelled; rolled back to previous connection")
                                : (tr(en, "TUN 启动失败，已回滚配置: ", "TUN start failed, rolled back: ") + ctx.supervisor.last_error());
                            (void)write_file_atomic(ctx.config_path, prev_kdl);
                            bool recovered = ctx.supervisor.start(ctx.config_path, {});
                            finish_err(std::move(reason), cancelled ? "warn" : "error", probe, recovered);
                            return;
                        }
                        auto next_ctl = parse_control_config(next_res.second, ctx.fallback_sock, ctx.cfg_dir);
                        ctx.ipc.set_endpoint(next_ctl.socket);
                        ctx.http_ctrl.set_endpoint(next_ctl.http_host, next_ctl.http_port);
                        ctx.http_ctrl.set_bearer_token(next_ctl.bearer_token);
                        synced_sock = std::move(next_ctl.socket);
                    }
                    auto ok_msg = was_running
                        ? (start_opts.elevate_session ? tr(en, "已按次提权并启用 TUN 模式", "TUN enabled (session elevation)")
                           : start_opts.use_persistent_helper ? tr(en, "已通过持久服务启用 TUN 模式", "TUN enabled (persistent helper)")
                                                              : tr(en, "已启用 TUN 模式并重启核心", "TUN enabled & core restarted"))
                        : tr(en, "已保存 TUN 配置，启动核心时生效", "TUN saved; activates when core starts");
                    on_ui_thread(ctx.weak_ui, [&ctx, kdl = std::move(next_res.second), synced_sock = std::move(synced_sock),
                                               probe, was_running, ok_msg = std::move(ok_msg)](auto& s) {
                        apply_tun_probe_to_ui(*s, probe);
                        apply_kdl_to_ui_state(*s, kdl);
                        if (!synced_sock.empty()) s->set_control_endpoint(slint::SharedString(synced_sock));
                        s->set_tun_enabled(true);
                        if (was_running) {
                            s->set_core_running(true);
                            ctx.core_started_at = std::chrono::steady_clock::now();
                            ctx.rate_tracker.reset();
                            s->set_core_uptime(slint::SharedString("00:00:00"));
                        }
                        s->set_diagnostic_ok(true);
                        s->set_diagnostic_message(slint::SharedString(ok_msg));
                        s->set_status_summary(slint::SharedString(ok_msg));
                        s->set_tun_privilege_busy(false);
                        s->set_core_toggling(false);
                        push_toast(*s, ok_msg, "success");
                        if (ctx.sync_tray) ctx.sync_tray();
                        ctx.lifecycle_busy.store(false, std::memory_order_release);
                    });
                    return;
                }

                // Disabling TUN
                if (!write_file_atomic(ctx.config_path, next_res.second)) {
                    finish_err(tr(en, "写入配置文件失败", "Failed to write config file"), "error");
                    return;
                }
                bool running_after = ctx.supervisor.running();
                bool op_ok = true;
                bool restarted = false;
                std::string ok_msg;
                if (running_after) {
                    if (ctx.supervisor.elevated_session() || ctx.supervisor.using_persistent_helper()) {
                        bool const was_helper = ctx.supervisor.using_persistent_helper();
                        restarted = true;
                        ctx.supervisor.stop();
                        running_after = ctx.supervisor.start(ctx.config_path, {});
                        op_ok = running_after;
                        ok_msg = running_after
                            ? (was_helper ? tr(en, "已关闭 TUN 并切换回普通模式", "TUN disabled & switched to unprivileged mode")
                                          : tr(en, "已关闭 TUN 并收回临时提权", "TUN disabled & session elevation dropped"))
                            : (tr(en, "已关闭 TUN，但普通模式重启失败: ", "TUN disabled; unprivileged restart failed: ") + ctx.supervisor.last_error());
                    } else {
                        auto r = ctx.ipc.reload();
                        if (!r.ok) {
                            auto hr = ctx.http_ctrl.reload();
                            if (hr.ok) r = {true, "OK"};
                            else if (!hr.body.empty()) r.body = hr.body;
                        }
                        op_ok = r.ok;
                        ok_msg = op_ok
                            ? tr(en, "已关闭 TUN 模式", "TUN mode disabled")
                            : (tr(en, "已保存配置，但关闭 TUN 热重载失败: ", "Config saved; reload failed disabling TUN: ") + r.body);
                    }
                } else {
                    ok_msg = tr(en, "已关闭 TUN 配置", "TUN config disabled");
                }
                auto probe = desktop::probe_tun_privilege(ctx.supervisor.binary_path());
                on_ui_thread(ctx.weak_ui, [&ctx, kdl = std::move(next_res.second), probe, running_after,
                                           op_ok, restarted, en, ok_msg = std::move(ok_msg)](auto& s) {
                    apply_tun_probe_to_ui(*s, probe);
                    apply_kdl_to_ui_state(*s, kdl);
                    s->set_tun_enabled(false);
                    s->set_core_running(running_after);
                    if (restarted) {
                        if (running_after) {
                            ctx.core_started_at = std::chrono::steady_clock::now();
                            ctx.rate_tracker.reset();
                            s->set_core_uptime(slint::SharedString("00:00:00"));
                        } else {
                            ctx.core_started_at.reset();
                            ctx.rate_tracker.reset();
                            clear_telemetry_ui(*s, en);
                        }
                    }
                    s->set_diagnostic_ok(op_ok);
                    s->set_diagnostic_message(slint::SharedString(ok_msg));
                    s->set_status_summary(slint::SharedString(ok_msg));
                    s->set_tun_privilege_busy(false);
                    s->set_core_toggling(false);
                    push_toast(*s, ok_msg, op_ok ? "info" : "error");
                    if (ctx.sync_tray) ctx.sync_tray();
                    ctx.lifecycle_busy.store(false, std::memory_order_release);
                });
            });
            if (!posted) {
                ctx.ui.set_tun_enabled(!on);
                ctx.ui.set_tun_privilege_busy(false);
                ctx.ui.set_core_toggling(false);
                ctx.lifecycle_busy.store(false, std::memory_order_release);
            }
        });

        ctx.ui.on_grant_tun_privilege([&ctx] {
            if (ctx.lifecycle_busy.exchange(true, std::memory_order_acq_rel)) return;
            bool const en = is_en_ui(ctx.ui);
            ctx.ui.set_tun_privilege_busy(true);
            ctx.ui.set_core_toggling(true);
            bool posted = ctx.worker.post([&ctx, en] {
                auto res = desktop::grant_persistent_tun_privilege(ctx.supervisor.binary_path(), en, ctx.config_path, ctx.cfg_dir);
                auto probe = desktop::probe_tun_privilege(ctx.supervisor.binary_path());
                on_ui_thread(ctx.weak_ui, [&ctx, res = std::move(res), probe = std::move(probe)](auto& s) {
                    apply_tun_probe_to_ui(*s, probe);
                    s->set_tun_privilege_busy(false);
                    s->set_core_toggling(false);
                    push_toast(*s, res.message, res.ok ? "success" : res.cancelled ? "warn" : "error");
                    ctx.lifecycle_busy.store(false, std::memory_order_release);
                });
            });
            if (!posted) {
                ctx.ui.set_tun_privilege_busy(false);
                ctx.ui.set_core_toggling(false);
                ctx.lifecycle_busy.store(false, std::memory_order_release);
            }
        });

        ctx.ui.on_revoke_tun_privilege([&ctx] {
            if (ctx.lifecycle_busy.exchange(true, std::memory_order_acq_rel)) return;
            bool const en = is_en_ui(ctx.ui);
            bool const tun_active = ctx.ui.get_tun_enabled();
            ctx.ui.set_tun_privilege_busy(true);
            ctx.ui.set_core_toggling(true);
            bool posted = ctx.worker.post([&ctx, en, tun_active] {
                bool const stopped_helper = ctx.supervisor.using_persistent_helper();
                if (stopped_helper) ctx.supervisor.stop();
                auto res = desktop::revoke_persistent_tun_privilege(ctx.supervisor.binary_path(), en);
                auto probe = desktop::probe_tun_privilege(ctx.supervisor.binary_path());
                bool const core_up = ctx.supervisor.running();
                auto msg = (res.ok && stopped_helper)
                    ? tr(en, "已停止核心并卸载 TUN 持久授权", "Core stopped & persistent TUN grant revoked")
                    : (res.ok && core_up && tun_active)
                        ? tr(en, "已撤销持久授权，将在下次重启核心后生效", "Persistent grant revoked; takes effect on next core restart")
                        : res.message;
                on_ui_thread(ctx.weak_ui, [&ctx, en, stopped_helper, ok = res.ok, cancelled = res.cancelled,
                                           msg = std::move(msg), probe = std::move(probe)](auto& s) {
                    apply_tun_probe_to_ui(*s, probe);
                    if (stopped_helper) {
                        s->set_core_running(false);
                        ctx.core_started_at.reset();
                        ctx.rate_tracker.reset();
                        clear_telemetry_ui(*s, en);
                    }
                    s->set_tun_privilege_busy(false);
                    s->set_core_toggling(false);
                    push_toast(*s, msg, ok ? "success" : cancelled ? "warn" : "error");
                    if (stopped_helper && ctx.sync_tray) ctx.sync_tray();
                    ctx.lifecycle_busy.store(false, std::memory_order_release);
                });
            });
            if (!posted) {
                ctx.ui.set_tun_privilege_busy(false);
                ctx.ui.set_core_toggling(false);
                ctx.lifecycle_busy.store(false, std::memory_order_release);
            }
        });
    }
}
