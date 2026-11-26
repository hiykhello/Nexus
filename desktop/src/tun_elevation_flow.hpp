// End-to-end Workspace-native TUN elevation, core start/stop, and rollback orchestration for desktop/src/main.cpp.
#pragma once

namespace desktop_ui_helpers {
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

    inline auto toggle_core_async(
        slint::ComponentWeakHandle<nexus_ui::AppWindow> weak_ui,
        desktop::AsyncWorker& worker,
        desktop::CoreSupervisor& supervisor,
        desktop::SystemProxyController& sys_proxy,
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
        std::string composed_text,
        bool prefer_persistent_tun,
        bool en) -> void {
        bool posted = worker.post([&, weak_ui, en, prefer_persistent_tun, on_tray_sync = std::move(on_tray_sync),
                                   composed_text = std::move(composed_text)]() mutable {
            bool running = false;
            bool cancelled = false;
            std::optional<desktop::TunPrivilegeProbe> refreshed_probe;
            std::string summary, diag_err;
            if (supervisor.running()) {
                (void)sys_proxy.restore();
                supervisor.stop();
                diag_err = supervisor.last_error();
                summary = diag_err.empty() ? tr(en, "已断开", "Disconnected")
                                           : (tr(en, "停止核心警告: ", "Stop warning: ") + diag_err);
            } else {
                auto prep = prepare_config_before_start(cfg_dir, config_path, supervisor, std::move(composed_text), en);
                if (!prep.ok) {
                    diag_err = prep.error_message;
                    summary = tr(en, "配置校验未通过: ", "Config invalid: ") + diag_err;
                } else {
                    http_ctrl.set_endpoint(prep.control.http_host, prep.control.http_port);
                    http_ctrl.set_bearer_token(prep.control.bearer_token);

                    desktop::CoreStartOptions start_opts{};
                    bool elev_ok = true;
                    if (config_has_tun_inbound(prep.composed_text)) {
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
                                           summary = std::move(summary), diag_err = std::move(diag_err)]() mutable {
                if (auto strong = weak_ui.lock()) {
                    auto& s = **strong;
                    if (refreshed_probe) apply_tun_probe_to_ui(s, *refreshed_probe);
                    s.set_core_running(running);
                    s.set_diagnostic_ok(diag_err.empty() || cancelled);
                    s.set_diagnostic_message(slint::SharedString(cancelled ? "" : diag_err));
                    if (running) {
                        core_started_at = std::chrono::steady_clock::now();
                        rate_tracker.reset();
                        s.set_core_uptime(slint::SharedString("00:00:00"));
                        poll_telemetry_async(weak_ui, worker, http_ctrl, cached_groups, pinned_members, member_models, rate_tracker,
                                             metrics_in_flight, true, on_tray_sync);
                    } else {
                        core_started_at.reset();
                        rate_tracker.reset();
                        s.set_system_proxy_enabled(false);
                        clear_telemetry_ui(s);
                    }
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

    inline auto bind_tun_callbacks(WorkspaceUiContext& ws_ctx, std::function<void()> persist_prefs) -> void {
        probe_tun_privilege_async(ws_ctx.weak_ui, ws_ctx.worker, ws_ctx.supervisor.binary_path());

        ws_ctx.ui.on_tray_prefs_changed([&ws_ctx, persist_prefs = std::move(persist_prefs)] {
            if (persist_prefs) persist_prefs();
            if (ws_ctx.sync_tray) ws_ctx.sync_tray();
        });

        ws_ctx.ui.on_toggle_tun([&ws_ctx](bool on) {
            if (ws_ctx.lifecycle_busy.exchange(true, std::memory_order_acq_rel)) {
                ws_ctx.ui.set_tun_enabled(!on);
                return;
            }
            bool const en = is_en_ui(ws_ctx.ui);
            bool const prefer_persistent = ws_ctx.ui.get_tun_elevate_persistent();
            if (ensure_default_workspace_profile(ws_ctx.doc, ws_ctx.telemetry)) {
                (void)persist_workspace_db(ws_ctx);
                (void)persist_telemetry_db(ws_ctx);
            }
            auto next_host = ws_ctx.host;
            next_host.enable_tun = on;
            auto notices = desktop::normalize_desktop_host_config(next_host, en);
            auto doc_snap = ws_ctx.doc;
            auto active_id = resolve_effective_active_profile_id(ws_ctx);
            ws_ctx.ui.set_tun_privilege_busy(true);
            ws_ctx.ui.set_core_toggling(true);

            bool posted = ws_ctx.worker.post([&ws_ctx, on, en, prefer_persistent,
                                              doc_snap = std::move(doc_snap), next_host = std::move(next_host),
                                              notices = std::move(notices), active_id = std::move(active_id)]() mutable {
                auto finish_err = [&](std::string msg, std::string tone, std::optional<desktop::TunPrivilegeProbe> probe = std::nullopt,
                                      std::optional<bool> core_running_override = std::nullopt) {
                    on_ui_thread(ws_ctx.weak_ui, [&ws_ctx, on, msg = std::move(msg), tone = std::move(tone),
                                                  probe = std::move(probe), core_running_override](auto& s) {
                        if (probe) apply_tun_probe_to_ui(*s, *probe);
                        sync_workspace_to_ui(ws_ctx);
                        s->set_tun_enabled(!on);
                        if (core_running_override) {
                            s->set_core_running(*core_running_override);
                            if (*core_running_override) {
                                ws_ctx.core_started_at = std::chrono::steady_clock::now();
                                ws_ctx.rate_tracker.reset();
                                s->set_core_uptime(slint::SharedString("00:00:00"));
                            } else {
                                ws_ctx.core_started_at.reset();
                                ws_ctx.rate_tracker.reset();
                            }
                        }
                        s->set_diagnostic_ok(tone == "warn" || tone == "info");
                        s->set_diagnostic_message(slint::SharedString(msg));
                        s->set_tun_privilege_busy(false);
                        s->set_core_toggling(false);
                        push_toast(*s, msg, tone);
                        if (ws_ctx.sync_tray) ws_ctx.sync_tray();
                        ws_ctx.lifecycle_busy.store(false, std::memory_order_release);
                    });
                };

                auto ws_tmp = make_temp_compose_workspace(ws_ctx.cfg_dir, doc_snap);
                auto host_tmp = make_temp_compose_host(ws_ctx.cfg_dir, next_host);
                if (!ws_tmp.ok || !host_tmp.ok) {
                    ws_tmp.wipe_and_remove(); host_tmp.wipe_and_remove();
                    finish_err(tr(en, "准备 TUN 配置失败", "Failed to prepare TUN configuration"), "error");
                    return;
                }
                auto composed = desktop::compose_workspace_via_core(
                    ws_ctx.supervisor.binary_path(), ws_tmp.path, host_tmp.path, ws_ctx.secrets_dir, active_id, {});
                ws_tmp.wipe_and_remove(); host_tmp.wipe_and_remove();
                if (!composed.ok || composed.kdl.empty()) {
                    finish_err(composed.errors.empty() ? tr(en, "生成 TUN 配置失败", "Failed to build TUN configuration") : composed.errors.front(), "error");
                    return;
                }
                auto val = validate_draft_config(ws_ctx.cfg_dir, ws_ctx.supervisor, composed.kdl, en);
                if (!val.ok) {
                    finish_err(tr(en, "TUN 配置校验未通过: ", "TUN config invalid: ") + val.message, "error");
                    return;
                }
                auto const prev_cfg = read_file_text(ws_ctx.config_path);

                if (on) {
                    desktop::CoreStartOptions start_opts{};
                    desktop::TunPrivilegeProbe probe{};
                    auto elev = resolve_tun_elevation_for_start(
                        ws_ctx.supervisor.binary_path(), ws_ctx.config_path, ws_ctx.cfg_dir, prefer_persistent, en, start_opts, probe);
                    if (!elev.ok) {
                        finish_err(elev.message, elev.cancelled ? "warn" : "error", probe);
                        return;
                    }
                    if (!write_file_atomic(ws_ctx.config_path, composed.kdl)) {
                        finish_err(tr(en, "写入运行配置失败", "Failed to write runtime configuration"), "error", probe);
                        return;
                    }
                    bool const was_running = ws_ctx.supervisor.running();
                    if (was_running) {
                        ws_ctx.supervisor.stop();
                        if (!ws_ctx.supervisor.start(ws_ctx.config_path, start_opts)) {
                            bool const cancelled = ws_ctx.supervisor.last_start_cancelled();
                            auto reason = cancelled
                                ? tr(en, "已取消提权，已回滚并恢复原有连接", "Elevation cancelled; rolled back to previous connection")
                                : (tr(en, "TUN 启动失败，已回滚配置: ", "TUN start failed, rolled back: ") + ws_ctx.supervisor.last_error());
                            if (!prev_cfg.empty()) (void)write_file_atomic(ws_ctx.config_path, prev_cfg);
                            bool recovered = ws_ctx.supervisor.start(ws_ctx.config_path, {});
                            finish_err(std::move(reason), cancelled ? "warn" : "error", probe, recovered);
                            return;
                        }
                        auto next_ctl = parse_control_config(composed.kdl, ws_ctx.cfg_dir);
                        ws_ctx.http_ctrl.set_endpoint(next_ctl.http_host, next_ctl.http_port);
                        ws_ctx.http_ctrl.set_bearer_token(next_ctl.bearer_token);
                    }
                    auto ok_msg = was_running
                        ? (start_opts.elevate_session ? tr(en, "已按次提权并启用 TUN 模式", "TUN enabled (session elevation)")
                           : start_opts.use_persistent_helper ? tr(en, "已通过持久服务启用 TUN 模式", "TUN enabled (persistent helper)")
                                                              : tr(en, "已启用 TUN 模式并重启核心", "TUN enabled & core restarted"))
                        : tr(en, "已保存 TUN 设置，启动核心时生效", "TUN saved; activates when core starts");
                    on_ui_thread(ws_ctx.weak_ui, [&ws_ctx, composed = std::move(composed), next_host = std::move(next_host),
                                                  notices = std::move(notices), probe, was_running, ok_msg = std::move(ok_msg)](auto& s) mutable {
                        ws_ctx.host = std::move(next_host);
                        (void)persist_host_db(ws_ctx);
                        ws_ctx.running_selector_tag = composed.selector_tag;
                        ws_ctx.running_selector_members = std::move(composed.selector_members);
                        ws_ctx.last_secret_files = std::move(composed.secret_files);
                        apply_tun_probe_to_ui(*s, probe);
                        sync_workspace_to_ui(ws_ctx);
                        s->template global<nexus_ui::WorkspaceState>().set_host_strict_route_notice(
                            slint::SharedString(notices.empty() ? "" : notices.front()));
                        if (was_running) {
                            s->set_core_running(true);
                            ws_ctx.core_started_at = std::chrono::steady_clock::now();
                            ws_ctx.rate_tracker.reset();
                            s->set_core_uptime(slint::SharedString("00:00:00"));
                        }
                        s->set_diagnostic_ok(true);
                        s->set_diagnostic_message(slint::SharedString(ok_msg));
                        s->set_tun_privilege_busy(false);
                        s->set_core_toggling(false);
                        push_toast(*s, ok_msg, "success");
                        if (ws_ctx.sync_tray) ws_ctx.sync_tray();
                        ws_ctx.lifecycle_busy.store(false, std::memory_order_release);
                    });
                    return;
                }

                // Disabling TUN
                if (!write_file_atomic(ws_ctx.config_path, composed.kdl)) {
                    finish_err(tr(en, "写入运行配置失败", "Failed to write runtime configuration"), "error");
                    return;
                }
                bool running_after = ws_ctx.supervisor.running();
                bool op_ok = true;
                bool restarted = false;
                std::string ok_msg;
                if (running_after) {
                    if (ws_ctx.supervisor.elevated_session() || ws_ctx.supervisor.using_persistent_helper()) {
                        bool const was_helper = ws_ctx.supervisor.using_persistent_helper();
                        restarted = true;
                        ws_ctx.supervisor.stop();
                        running_after = ws_ctx.supervisor.start(ws_ctx.config_path, {});
                        op_ok = running_after;
                        ok_msg = running_after
                            ? (was_helper ? tr(en, "已关闭 TUN 并切换回普通模式", "TUN disabled & switched to unprivileged mode")
                                          : tr(en, "已关闭 TUN 并收回临时提权", "TUN disabled & session elevation dropped"))
                            : (tr(en, "已关闭 TUN，但普通模式重启失败: ", "TUN disabled; unprivileged restart failed: ") + ws_ctx.supervisor.last_error());
                    } else {
                        auto hr = ws_ctx.http_ctrl.reload();
                        op_ok = hr.ok;
                        ok_msg = op_ok
                            ? tr(en, "已关闭 TUN 模式", "TUN mode disabled")
                            : (tr(en, "已保存设置，但关闭 TUN 热重载失败: ", "Saved; reload failed disabling TUN: ") + hr.body);
                    }
                    if (op_ok) {
                        auto next_ctl = parse_control_config(composed.kdl, ws_ctx.cfg_dir);
                        ws_ctx.http_ctrl.set_endpoint(next_ctl.http_host, next_ctl.http_port);
                        ws_ctx.http_ctrl.set_bearer_token(next_ctl.bearer_token);
                    }
                } else {
                    ok_msg = tr(en, "已关闭 TUN 模式", "TUN mode disabled");
                }
                auto probe = desktop::probe_tun_privilege(ws_ctx.supervisor.binary_path());
                on_ui_thread(ws_ctx.weak_ui, [&ws_ctx, composed = std::move(composed), next_host = std::move(next_host),
                                              notices = std::move(notices), probe, running_after,
                                              op_ok, restarted, ok_msg = std::move(ok_msg)](auto& s) mutable {
                    ws_ctx.host = std::move(next_host);
                    (void)persist_host_db(ws_ctx);
                    ws_ctx.running_selector_tag = composed.selector_tag;
                    ws_ctx.running_selector_members = std::move(composed.selector_members);
                    ws_ctx.last_secret_files = std::move(composed.secret_files);
                    apply_tun_probe_to_ui(*s, probe);
                    sync_workspace_to_ui(ws_ctx);
                    s->template global<nexus_ui::WorkspaceState>().set_host_strict_route_notice(
                        slint::SharedString(notices.empty() ? "" : notices.front()));
                    s->set_core_running(running_after);
                    if (restarted) {
                        if (running_after) {
                            ws_ctx.core_started_at = std::chrono::steady_clock::now();
                            ws_ctx.rate_tracker.reset();
                            s->set_core_uptime(slint::SharedString("00:00:00"));
                        } else {
                            ws_ctx.core_started_at.reset();
                            ws_ctx.rate_tracker.reset();
                            clear_telemetry_ui(*s);
                        }
                    }
                    s->set_diagnostic_ok(op_ok);
                    s->set_diagnostic_message(slint::SharedString(ok_msg));
                    s->set_tun_privilege_busy(false);
                    s->set_core_toggling(false);
                    push_toast(*s, ok_msg, op_ok ? "info" : "error");
                    if (ws_ctx.sync_tray) ws_ctx.sync_tray();
                    ws_ctx.lifecycle_busy.store(false, std::memory_order_release);
                });
            });
            if (!posted) {
                ws_ctx.ui.set_tun_enabled(!on);
                ws_ctx.ui.set_tun_privilege_busy(false);
                ws_ctx.ui.set_core_toggling(false);
                ws_ctx.lifecycle_busy.store(false, std::memory_order_release);
            }
        });

        ws_ctx.ui.on_grant_tun_privilege([&ws_ctx] {
            if (ws_ctx.lifecycle_busy.exchange(true, std::memory_order_acq_rel)) return;
            bool const en = is_en_ui(ws_ctx.ui);
            ws_ctx.ui.set_tun_privilege_busy(true);
            ws_ctx.ui.set_core_toggling(true);
            bool posted = ws_ctx.worker.post([&ws_ctx, en] {
                auto res = desktop::grant_persistent_tun_privilege(ws_ctx.supervisor.binary_path(), en, ws_ctx.config_path, ws_ctx.cfg_dir);
                auto probe = desktop::probe_tun_privilege(ws_ctx.supervisor.binary_path());
                on_ui_thread(ws_ctx.weak_ui, [&ws_ctx, res = std::move(res), probe = std::move(probe)](auto& s) {
                    apply_tun_probe_to_ui(*s, probe);
                    s->set_tun_privilege_busy(false);
                    s->set_core_toggling(false);
                    push_toast(*s, res.message, res.ok ? "success" : res.cancelled ? "warn" : "error");
                    ws_ctx.lifecycle_busy.store(false, std::memory_order_release);
                });
            });
            if (!posted) {
                ws_ctx.ui.set_tun_privilege_busy(false);
                ws_ctx.ui.set_core_toggling(false);
                ws_ctx.lifecycle_busy.store(false, std::memory_order_release);
            }
        });

        ws_ctx.ui.on_revoke_tun_privilege([&ws_ctx] {
            if (ws_ctx.lifecycle_busy.exchange(true, std::memory_order_acq_rel)) return;
            bool const en = is_en_ui(ws_ctx.ui);
            bool const tun_active = ws_ctx.ui.get_tun_enabled();
            ws_ctx.ui.set_tun_privilege_busy(true);
            ws_ctx.ui.set_core_toggling(true);
            bool posted = ws_ctx.worker.post([&ws_ctx, en, tun_active] {
                bool const stopped_helper = ws_ctx.supervisor.using_persistent_helper();
                if (stopped_helper) ws_ctx.supervisor.stop();
                auto res = desktop::revoke_persistent_tun_privilege(ws_ctx.supervisor.binary_path(), en);
                auto probe = desktop::probe_tun_privilege(ws_ctx.supervisor.binary_path());
                bool const core_up = ws_ctx.supervisor.running();
                auto msg = (res.ok && stopped_helper)
                    ? tr(en, "已停止核心并卸载 TUN 持久授权", "Core stopped & persistent TUN grant revoked")
                    : (res.ok && core_up && tun_active)
                        ? tr(en, "已撤销持久授权，将在下次重启核心后生效", "Persistent grant revoked; takes effect on next core restart")
                        : res.message;
                on_ui_thread(ws_ctx.weak_ui, [&ws_ctx, stopped_helper, ok = res.ok, cancelled = res.cancelled,
                                              msg = std::move(msg), probe = std::move(probe)](auto& s) {
                    apply_tun_probe_to_ui(*s, probe);
                    if (stopped_helper) {
                        s->set_core_running(false);
                        ws_ctx.core_started_at.reset();
                        ws_ctx.rate_tracker.reset();
                        clear_telemetry_ui(*s);
                    }
                    s->set_tun_privilege_busy(false);
                    s->set_core_toggling(false);
                    push_toast(*s, msg, ok ? "success" : cancelled ? "warn" : "error");
                    if (stopped_helper && ws_ctx.sync_tray) ws_ctx.sync_tray();
                    ws_ctx.lifecycle_busy.store(false, std::memory_order_release);
                });
            });
            if (!posted) {
                ws_ctx.ui.set_tun_privilege_busy(false);
                ws_ctx.ui.set_core_toggling(false);
                ws_ctx.lifecycle_busy.store(false, std::memory_order_release);
            }
        });
    }
}
