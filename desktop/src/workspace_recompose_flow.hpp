// Workspace runtime KDL recomposition, live TUN elevation/reload, and Core start/stop toggle hook.
#pragma once

namespace desktop_ui_helpers {
    inline auto resolve_effective_active_profile_id(WorkspaceUiContext const& ctx) -> std::string {
        if (!ctx.telemetry.active_profile_id.empty()) {
            for (auto const& p : ctx.doc.profiles) if (p.id == ctx.telemetry.active_profile_id) return p.id;
        }
        return ctx.doc.profiles.empty() ? std::string{} : ctx.doc.profiles.front().id;
    }

    inline auto persist_workspace_and_host(WorkspaceUiContext& ctx, bool en) -> std::vector<std::string> {
        auto notices = desktop::normalize_desktop_host_config(ctx.host, en);
        (void)persist_workspace_db(ctx);
        (void)persist_host_db(ctx);
        return notices;
    }

    inline auto compose_workspace_with_overlay(
        std::filesystem::path const& cfg_dir,
        std::filesystem::path const& binary_path,
        std::filesystem::path const& secrets_dir,
        desktop::WorkspaceDocument const& doc_snap,
        desktop::DesktopHostConfig const& host_snap,
        std::string_view active_id,
        bool en) -> std::expected<desktop::WorkspaceComposeResult, std::string> {
        auto ws_tmp = make_temp_compose_workspace(cfg_dir, doc_snap);
        auto host_tmp = make_temp_compose_host(cfg_dir, host_snap);
        if (!ws_tmp.ok || !host_tmp.ok) {
            ws_tmp.wipe_and_remove();
            host_tmp.wipe_and_remove();
            return std::unexpected(tr(en, "准备运行配置失败", "Failed to prepare runtime inputs"));
        }
        auto composed = desktop::compose_workspace_via_core(
            binary_path, ws_tmp.path, host_tmp.path, secrets_dir, active_id, {});
        ws_tmp.wipe_and_remove();
        host_tmp.wipe_and_remove();
        if (!composed.ok || composed.kdl.empty()) {
            return std::unexpected(composed.errors.empty()
                ? tr(en, "生成运行配置失败", "Failed to build runtime configuration")
                : composed.errors.front());
        }
        bool skip_inb_overlay = doc_snap.full_template.enabled;
        for (auto const& p : doc_snap.profiles) {
            if (p.id == active_id && p.kind == "full_custom_kdl") skip_inb_overlay = true;
        }
        if (!skip_inb_overlay) {
            auto overlaid = desktop::apply_desktop_inbounds_overlay(composed.kdl, host_snap, secrets_dir, composed.secret_files);
            if (!overlaid) return std::unexpected(overlaid.error());
            composed.kdl = std::move(*overlaid);
        }
        return composed;
    }

    inline auto sync_system_proxy_with_inbounds(WorkspaceUiContext& ctx, bool en) -> void {
        if (!ctx.sys_proxy || !ctx.ui.get_system_proxy_enabled()) return;
        auto endpoint = desktop::select_system_proxy_endpoint(read_inbounds_from_ui(ctx.ui));
        if (!endpoint) {
            ctx.ui.set_system_proxy_enabled(false);
            push_toast(ctx.ui, tr(en, "无可用本地代理端口，已自动恢复系统代理", "No local proxy port active; restored system proxy"), "info");
            if (ctx.sync_tray) ctx.sync_tray();
            ctx.worker.post([sp = ctx.sys_proxy] { (void)sp->restore(); });
            return;
        }
        ctx.worker.post([&ctx, sp = ctx.sys_proxy, ep = *endpoint] {
            bool ok = sp->enable(ep.first, ep.second);
            on_ui_thread(ctx.weak_ui, [&ctx, ok](auto& s) {
                s->set_system_proxy_enabled(ok);
                if (ctx.sync_tray) ctx.sync_tray();
            });
        });
    }

    inline auto recompose_active_workspace(WorkspaceUiContext& ctx, std::string target_profile_id = {}) -> void {
        if (ctx.doc.profiles.empty()) return;
        bool const en = is_en_ui(ctx.ui);
        bool const prefer_persistent = ctx.ui.get_tun_elevate_persistent();
        if (target_profile_id.empty()) target_profile_id = resolve_effective_active_profile_id(ctx);
        if (target_profile_id.empty()) return;
        (void)persist_workspace_and_host(ctx, en);
        auto doc_snap = ctx.doc;
        auto host_snap = ctx.host;
        ctx.ui.set_diagnostic_message(slint::SharedString(tr(en, "正在应用工作区配置...", "Applying workspace configuration...")));

        ctx.worker.post([&ctx, doc_snap = std::move(doc_snap), host_snap = std::move(host_snap), id = std::move(target_profile_id), prefer_persistent, en]() mutable {
            auto fail_compose = [&](std::string err) {
                on_ui_thread(ctx.weak_ui, [&ctx, err = std::move(err)](auto& s) {
                    s->set_diagnostic_ok(false);
                    s->set_diagnostic_message(slint::SharedString(err));
                    push_toast(*s, err, "error");
                    if (ctx.sync_tray) ctx.sync_tray();
                });
            };
            auto composed_exp = compose_workspace_with_overlay(
                ctx.cfg_dir, ctx.supervisor.binary_path(), ctx.secrets_dir, doc_snap, host_snap, id, en);
            if (!composed_exp) {
                fail_compose(composed_exp.error());
                return;
            }
            auto composed = std::move(*composed_exp);
            auto val = validate_draft_config(ctx.cfg_dir, ctx.supervisor, composed.kdl, en);
            if (!val.ok) {
                fail_compose(tr(en, "配置校验未通过: ", "Configuration invalid: ") + val.message);
                return;
            }

            bool const was_running = ctx.supervisor.running();
            auto const prev_cfg = read_file_text(ctx.config_path);
            bool const prev_tun = config_has_tun_inbound(prev_cfg);
            bool const next_tun = config_has_tun_inbound(composed.kdl);

            if (was_running && prev_tun != next_tun) {
                if (ctx.lifecycle_busy.exchange(true, std::memory_order_acq_rel)) {
                    auto msg = tr(en, "核心正在切换状态，请稍后重试", "Core is busy; try again shortly");
                    on_ui_thread(ctx.weak_ui, [msg = std::move(msg)](auto& s) {
                        s->set_diagnostic_ok(false); s->set_diagnostic_message(slint::SharedString(msg));
                        push_toast(*s, msg, "warn");
                    });
                    return;
                }
                desktop::CoreStartOptions opts{};
                desktop::TunPrivilegeProbe probe{};
                if (next_tun) {
                    auto elev = resolve_tun_elevation_for_start(
                        ctx.supervisor.binary_path(), ctx.config_path, ctx.cfg_dir, prefer_persistent, en, opts, probe);
                    if (!elev.ok) {
                        ctx.lifecycle_busy.store(false, std::memory_order_release);
                        on_ui_thread(ctx.weak_ui, [probe, msg = std::move(elev.message), tone = elev.cancelled ? "warn" : "error"](auto& s) {
                            apply_tun_probe_to_ui(*s, probe);
                            s->set_diagnostic_ok(false); s->set_diagnostic_message(slint::SharedString(msg));
                            push_toast(*s, msg, tone);
                        });
                        return;
                    }
                }
                bool wrote = write_file_atomic(ctx.config_path, composed.kdl);
                ctx.supervisor.stop();
                bool started = wrote && ctx.supervisor.start(ctx.config_path, opts);
                if (!started) {
                    if (!prev_cfg.empty()) (void)write_file_atomic(ctx.config_path, prev_cfg);
                    bool recovered = ctx.supervisor.start(ctx.config_path, {});
                    ctx.lifecycle_busy.store(false, std::memory_order_release);
                    auto err = tr(en, "应用配置并重启核心失败，已回滚: ", "Failed to restart Core; rolled back: ") + ctx.supervisor.last_error();
                    on_ui_thread(ctx.weak_ui, [&ctx, recovered, err = std::move(err)](auto& s) {
                        s->set_core_running(recovered);
                        if (!recovered) ctx.running_selector_members.clear();
                        s->set_diagnostic_ok(false); s->set_diagnostic_message(slint::SharedString(err));
                        push_toast(*s, err, "error");
                        if (ctx.sync_tray) ctx.sync_tray();
                    });
                    return;
                }
                auto next_ctl = parse_control_config(composed.kdl, ctx.cfg_dir);
                ctx.http_ctrl.set_endpoint(next_ctl.http_host, next_ctl.http_port);
                ctx.http_ctrl.set_bearer_token(next_ctl.bearer_token);
                ctx.lifecycle_busy.store(false, std::memory_order_release);
                auto ok_msg = next_tun ? tr(en, "配置已生效并启用 TUN", "Applied with TUN enabled")
                                       : tr(en, "配置已生效并关闭 TUN", "Applied with TUN disabled");
                on_ui_thread(ctx.weak_ui, [&ctx, composed = std::move(composed), ok_msg = std::move(ok_msg), next_tun](auto& s) mutable {
                    ctx.running_selector_tag = composed.selector_tag;
                    ctx.running_selector_members = std::move(composed.selector_members);
                    ctx.last_secret_files = std::move(composed.secret_files);
                    s->set_tun_enabled(next_tun);
                    s->set_core_running(true);
                    ctx.core_started_at = std::chrono::steady_clock::now();
                    ctx.rate_tracker.reset();
                    s->set_diagnostic_ok(true);
                    s->set_diagnostic_message(slint::SharedString(ok_msg));
                    push_toast(*s, ok_msg, "success");
                    if (ctx.sync_tray) ctx.sync_tray();
                });
                return;
            }

            bool saved = write_file_atomic(ctx.config_path, composed.kdl);
            bool reload_ok = saved;
            std::string reload_err;
            if (saved) {
                if (was_running) {
                    auto hr = ctx.http_ctrl.reload();
                    reload_ok = hr.ok;
                    if (!hr.ok) reload_err = hr.body;
                }
                if (!was_running || reload_ok) {
                    auto next_ctl = parse_control_config(composed.kdl, ctx.cfg_dir);
                    ctx.http_ctrl.set_endpoint(next_ctl.http_host, next_ctl.http_port);
                    ctx.http_ctrl.set_bearer_token(next_ctl.bearer_token);
                }
            }
            auto msg = !saved ? tr(en, "写入运行配置失败", "Failed to write runtime configuration")
                : (reload_ok
                    ? (was_running ? tr(en, "配置已保存并热重载", "Saved & reloaded")
                                   : tr(en, "配置已保存，启动核心时生效", "Saved; activates on start"))
                    : (tr(en, "已保存，但热重载失败: ", "Saved; reload failed: ") + reload_err));
            on_ui_thread(ctx.weak_ui, [&ctx, composed = std::move(composed), ok = saved && reload_ok, msg = std::move(msg), next_tun](auto& s) mutable {
                ctx.running_selector_tag = composed.selector_tag;
                ctx.running_selector_members = std::move(composed.selector_members);
                ctx.last_secret_files = std::move(composed.secret_files);
                s->set_tun_enabled(next_tun);
                s->set_diagnostic_ok(ok);
                s->set_diagnostic_message(slint::SharedString(msg));
                push_toast(*s, msg, ok ? "success" : "error");
                if (ctx.sync_tray) ctx.sync_tray();
            });
        });
    }

    template <typename ToggleFn>
    inline auto toggle_core_with_workspace(WorkspaceUiContext& ctx, ToggleFn&& run_toggle) -> void {
        if (ctx.lifecycle_busy.exchange(true, std::memory_order_acq_rel)) return;
        bool const en = is_en_ui(ctx.ui);
        bool const prefer_persistent = ctx.ui.get_tun_elevate_persistent();
        ctx.ui.set_core_toggling(true);
        if (ctx.supervisor.running()) {
            ctx.running_selector_members.clear();
            run_toggle(std::string{}, prefer_persistent, en);
            return;
        }
        if (ensure_default_workspace_profile(ctx.doc, ctx.telemetry)) {
            (void)persist_workspace_db(ctx);
            (void)persist_telemetry_db(ctx);
            sync_workspace_to_ui(ctx);
        }
        auto active_id = resolve_effective_active_profile_id(ctx);
        (void)persist_workspace_and_host(ctx, en);
        auto doc_snap = ctx.doc;
        auto host_snap = ctx.host;
        bool posted = ctx.worker.post([&ctx, run_toggle = std::forward<ToggleFn>(run_toggle),
                                       doc_snap = std::move(doc_snap), host_snap = std::move(host_snap),
                                       active_id = std::move(active_id), prefer_persistent, en]() mutable {
            auto fail_toggle = [&](std::string err) {
                on_ui_thread(ctx.weak_ui, [&ctx, err = std::move(err)](auto& s) {
                    s->set_core_toggling(false);
                    s->set_diagnostic_ok(false); s->set_diagnostic_message(slint::SharedString(err));
                    push_toast(*s, err, "error");
                    if (ctx.sync_tray) ctx.sync_tray();
                    ctx.lifecycle_busy.store(false, std::memory_order_release);
                });
            };
            auto composed_exp = compose_workspace_with_overlay(
                ctx.cfg_dir, ctx.supervisor.binary_path(), ctx.secrets_dir, doc_snap, host_snap, active_id, en);
            if (!composed_exp) {
                fail_toggle(composed_exp.error());
                return;
            }
            auto composed = std::move(*composed_exp);
            std::string cfg_text = composed.kdl;
            on_ui_thread(ctx.weak_ui, [&ctx, composed = std::move(composed)](auto&) mutable {
                ctx.running_selector_tag = composed.selector_tag;
                ctx.running_selector_members = std::move(composed.selector_members);
                ctx.last_secret_files = std::move(composed.secret_files);
            });
            run_toggle(std::move(cfg_text), prefer_persistent, en);
        });
        if (!posted) {
            ctx.ui.set_core_toggling(false);
            ctx.lifecycle_busy.store(false, std::memory_order_release);
        }
    }
}
