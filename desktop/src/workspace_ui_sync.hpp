// Workspace UI state synchronization, Core composer commit (with TUN elevation/rollback), and Core start hook.
#pragma once

#include "workspace_ui_helpers.hpp"

namespace desktop_ui_helpers {
    struct WorkspaceUiContext {
        nexus_ui::AppWindow& ui;
        slint::ComponentWeakHandle<nexus_ui::AppWindow> weak_ui;
        desktop::AsyncWorker& worker;
        desktop::CoreSupervisor& supervisor;
        desktop::IpcClient& ipc;
        desktop::HttpControlClient& http_ctrl;
        RateTracker& rate_tracker;
        std::optional<std::chrono::steady_clock::time_point>& core_started_at;
        std::atomic<bool>& lifecycle_busy;
        std::filesystem::path const& cfg_dir;
        std::filesystem::path const& config_path;
        std::string const& fallback_sock;
        std::function<void()>& sync_tray;

        std::filesystem::path workspace_path;
        std::filesystem::path host_path;
        std::filesystem::path telemetry_path;
        std::filesystem::path secrets_dir;

        desktop::WorkspaceDocument doc;
        desktop::DesktopHostConfig host;
        desktop::TelemetryStoreData telemetry;
        std::string running_selector_tag = "proxy";
        std::vector<std::string> running_selector_members;
        std::vector<std::string> last_secret_files;
    };

    inline auto format_quota_human(std::int64_t used, std::int64_t total) -> std::string {
        if (total <= 0) return used > 0 ? format_bytes_human(static_cast<std::uint64_t>(used)) : std::string{};
        return format_bytes_human(static_cast<std::uint64_t>(std::max<std::int64_t>(0, used))) + " / " +
               format_bytes_human(static_cast<std::uint64_t>(total));
    }

    inline auto sync_workspace_to_ui(WorkspaceUiContext& ctx) -> void {
        auto const& ws = ctx.ui.global<nexus_ui::WorkspaceState>();
        std::unordered_map<std::string, std::string> sub_names;
        std::unordered_map<std::string, int> sub_counts;
        for (auto const& s : ctx.doc.subscriptions) sub_names[s.id] = s.remarks.empty() ? s.id : s.remarks;

        std::unordered_map<std::string, int> delays;
        for (auto const& e : ctx.telemetry.entries) delays[e.profile_id] = static_cast<int>(e.delay_ms);

        std::vector<nexus_ui::WorkspaceProfileRow> p_rows;
        p_rows.reserve(ctx.doc.profiles.size());
        std::string active_kind = "node";
        for (auto const& p : ctx.doc.profiles) {
            ++sub_counts[p.subscription_id];
            bool const active = (p.id == ctx.telemetry.active_profile_id);
            if (active) active_kind = p.kind;
            std::string subtitle;
            if (p.kind == "node") {
                subtitle = p.node.protocol.empty() ? p.node.server : std::format("{} · {}:{}", p.node.protocol, p.node.server, p.node.port);
            } else if (p.kind == "policy_group") {
                subtitle = std::format("{} · {} members", p.policy_group.strategy, p.policy_group.member_ids.size());
            } else if (p.kind == "proxy_chain") {
                subtitle = std::format("{} hops", p.proxy_chain.hop_ids.size());
            } else if (p.kind == "custom_outbound") {
                subtitle = "custom outbound KDL";
            } else {
                subtitle = "full custom KDL";
            }
            auto sub_it = sub_names.find(p.subscription_id);
            auto d_it = delays.find(p.id);
            p_rows.push_back({
                slint::SharedString(p.id),
                slint::SharedString(p.remarks.empty() ? p.id : p.remarks),
                slint::SharedString(p.kind),
                slint::SharedString(subtitle),
                slint::SharedString(sub_it != sub_names.end() ? sub_it->second : p.subscription_id),
                d_it != delays.end() ? d_it->second : -1,
                active,
            });
        }
        ws.set_active_profile_id(slint::SharedString(ctx.telemetry.active_profile_id));
        ws.set_active_profile_kind(slint::SharedString(active_kind));
        ws.set_profiles(std::make_shared<slint::VectorModel<nexus_ui::WorkspaceProfileRow>>(std::move(p_rows)));

        std::vector<nexus_ui::WorkspaceSubRow> s_rows;
        s_rows.reserve(ctx.doc.subscriptions.size());
        for (auto const& s : ctx.doc.subscriptions) {
            std::int64_t used = s.usage.upload_bytes + s.usage.download_bytes;
            float ratio = (s.usage.total_bytes > 0)
                ? static_cast<float>(std::clamp(static_cast<double>(used) / static_cast<double>(s.usage.total_bytes), 0.0, 1.0))
                : 0.0f;
            std::string exp = s.usage.expire_unix_sec > 0 ? std::format("exp:{}", s.usage.expire_unix_sec) : std::string{};
            s_rows.push_back({
                slint::SharedString(s.id),
                slint::SharedString(s.remarks.empty() ? s.id : s.remarks),
                slint::SharedString(s.url),
                sub_counts[s.id],
                slint::SharedString(format_quota_human(used, s.usage.total_bytes)),
                ratio,
                slint::SharedString(exp),
                slint::SharedString(s.prev_profile_id),
                slint::SharedString(s.next_profile_id),
                s.enabled,
            });
        }
        ws.set_subscriptions(std::make_shared<slint::VectorModel<nexus_ui::WorkspaceSubRow>>(std::move(s_rows)));

        std::vector<nexus_ui::WorkspaceRoutingRow> r_rows;
        std::vector<nexus_ui::WorkspaceRuleRow> rule_rows;
        for (auto const& rp : ctx.doc.routing_profiles) {
            r_rows.push_back({
                slint::SharedString(rp.id), slint::SharedString(rp.name),
                slint::SharedString(rp.default_outbound), static_cast<int>(rp.rules.size()), rp.is_active,
            });
            if (rp.is_active) {
                for (auto const& r : rp.rules) {
                    std::string tgt = (r.target_type == "profile_id" && !r.target_profile_id.empty())
                        ? ("@" + r.target_profile_id) : r.target_type;
                    std::string match = !r.domains.empty() ? join_csv(r.domains)
                        : !r.ips.empty() ? join_csv(r.ips) : join_csv(r.rule_sets);
                    rule_rows.push_back({
                        slint::SharedString(r.id), slint::SharedString(r.scope), slint::SharedString(tgt),
                        slint::SharedString(match), slint::SharedString(join_csv(r.desktop_process)), r.enabled,
                    });
                }
            }
        }
        ws.set_routing_profiles(std::make_shared<slint::VectorModel<nexus_ui::WorkspaceRoutingRow>>(std::move(r_rows)));
        ws.set_routing_rules(std::make_shared<slint::VectorModel<nexus_ui::WorkspaceRuleRow>>(std::move(rule_rows)));

        ws.set_dns_mode(slint::SharedString(ctx.doc.dns.mode));
        ws.set_dns_direct(slint::SharedString(join_csv(ctx.doc.dns.simple.direct_dns)));
        ws.set_dns_remote(slint::SharedString(join_csv(ctx.doc.dns.simple.remote_dns)));
        ws.set_dns_fakeip(ctx.doc.dns.simple.fake_ip_enabled);
        ws.set_dns_raw_kdl(slint::SharedString(ctx.doc.dns.raw_kdl));

        ws.set_host_is_linux(ctx.host.platform == "desktop-linux");
        ws.set_host_enable_mixed(ctx.host.enable_mixed);
        ws.set_host_mixed_listen(slint::SharedString(ctx.host.mixed_listen));
        ws.set_host_lan_listen(slint::SharedString(ctx.host.lan_listen));
        ws.set_host_enable_tun(ctx.host.enable_tun);
        ws.set_host_tun_mtu(slint::SharedString(std::to_string(ctx.host.tun_mtu)));
        ws.set_host_tun_strict_route(ctx.host.tun_strict_route);
        ws.set_host_sys_proxy_mode(slint::SharedString(ctx.host.system_proxy_mode));
    }

    inline auto resolve_effective_active_profile_id(WorkspaceUiContext const& ctx) -> std::string {
        if (!ctx.telemetry.active_profile_id.empty()) {
            for (auto const& p : ctx.doc.profiles) if (p.id == ctx.telemetry.active_profile_id) return p.id;
        }
        return ctx.doc.profiles.empty() ? std::string{} : ctx.doc.profiles.front().id;
    }

    inline auto persist_workspace_and_host(WorkspaceUiContext& ctx, bool en) -> std::vector<std::string> {
        auto notices = desktop::normalize_desktop_host_config(ctx.host, en);
        (void)desktop::save_workspace_atomic(ctx.workspace_path, ctx.doc);
        (void)desktop::save_desktop_host_config(ctx.host_path, ctx.host);
        return notices;
    }

    // Shared Core composer commit flow: NEVER overwrites config.kdl before validation/rollback,
    // handles TUN elevation transitions when Core is running, and fails closed on compose errors.
    inline auto recompose_active_workspace(WorkspaceUiContext& ctx, std::string target_profile_id = {}) -> void {
        if (ctx.doc.profiles.empty()) return;
        bool const en = is_en_ui(ctx.ui);
        bool const prefer_persistent = ctx.ui.get_tun_elevate_persistent();
        if (target_profile_id.empty()) target_profile_id = resolve_effective_active_profile_id(ctx);
        if (target_profile_id.empty()) return;
        (void)persist_workspace_and_host(ctx, en);
        ctx.ui.set_diagnostic_message(slint::SharedString(tr(en, "正在由核心编译工作区...", "Composing workspace via Core...")));

        ctx.worker.post([&ctx, id = std::move(target_profile_id), prefer_persistent, en]() mutable {
            auto composed = desktop::compose_workspace_via_core(
                ctx.supervisor.binary_path(), ctx.workspace_path, ctx.host_path, ctx.secrets_dir, id, {});
            if (!composed.ok || composed.kdl.empty()) {
                auto err = composed.errors.empty() ? tr(en, "核心编译工作区失败", "Workspace compose failed") : composed.errors.front();
                on_ui_thread(ctx.weak_ui, [&ctx, err = std::move(err)](auto& s) {
                    s->set_diagnostic_ok(false);
                    s->set_diagnostic_message(slint::SharedString(err));
                    push_toast(*s, err, "error");
                    if (ctx.sync_tray) ctx.sync_tray();
                });
                return;
            }

            bool const was_running = ctx.supervisor.running();
            auto const prev_kdl = read_file_text(ctx.config_path);
            bool const prev_tun = kdl_has_tun_inbound(prev_kdl);
            bool const next_tun = kdl_has_tun_inbound(composed.kdl);

            if (was_running && prev_tun != next_tun && !ctx.lifecycle_busy.exchange(true, std::memory_order_acq_rel)) {
                auto val = validate_draft_config(ctx.cfg_dir, ctx.supervisor, composed.kdl, en);
                if (!val.ok) {
                    ctx.lifecycle_busy.store(false, std::memory_order_release);
                    auto err = tr(en, "编译结果校验未通过: ", "Composed KDL invalid: ") + val.message;
                    on_ui_thread(ctx.weak_ui, [err = std::move(err)](auto& s) {
                        s->set_diagnostic_ok(false); s->set_diagnostic_message(slint::SharedString(err));
                        push_toast(*s, err, "error");
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
                    if (!prev_kdl.empty()) (void)write_file_atomic(ctx.config_path, prev_kdl);
                    bool recovered = ctx.supervisor.start(ctx.config_path, {});
                    ctx.lifecycle_busy.store(false, std::memory_order_release);
                    auto err = tr(en, "应用工作区并重启核心失败，已回滚: ", "Failed to restart Core for workspace; rolled back: ") + ctx.supervisor.last_error();
                    on_ui_thread(ctx.weak_ui, [&ctx, recovered, err = std::move(err)](auto& s) {
                        s->set_core_running(recovered);
                        if (!recovered) ctx.running_selector_members.clear();
                        s->set_diagnostic_ok(false); s->set_diagnostic_message(slint::SharedString(err));
                        push_toast(*s, err, "error");
                        if (ctx.sync_tray) ctx.sync_tray();
                    });
                    return;
                }
                auto next_ctl = parse_control_config(composed.kdl, ctx.fallback_sock, ctx.cfg_dir);
                ctx.ipc.set_endpoint(next_ctl.socket);
                ctx.http_ctrl.set_endpoint(next_ctl.http_host, next_ctl.http_port);
                ctx.http_ctrl.set_bearer_token(next_ctl.bearer_token);
                ctx.lifecycle_busy.store(false, std::memory_order_release);
                auto ok_msg = next_tun ? tr(en, "工作区已编译并启用 TUN 重启生效", "Workspace applied with TUN elevation")
                                       : tr(en, "工作区已编译并关闭 TUN 重启生效", "Workspace applied with TUN disabled");
                on_ui_thread(ctx.weak_ui, [&ctx, composed = std::move(composed), sock = std::move(next_ctl.socket), ok_msg = std::move(ok_msg), next_tun](auto& s) mutable {
                    ctx.running_selector_tag = composed.selector_tag;
                    ctx.running_selector_members = std::move(composed.selector_members);
                    ctx.last_secret_files = std::move(composed.secret_files);
                    apply_kdl_to_ui_state(*s, composed.kdl);
                    s->set_control_endpoint(slint::SharedString(sock));
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

            on_ui_thread(ctx.weak_ui, [&ctx, composed = std::move(composed)](auto& s) mutable {
                ctx.running_selector_tag = composed.selector_tag;
                ctx.running_selector_members = std::move(composed.selector_members);
                ctx.last_secret_files = std::move(composed.secret_files);
                s->invoke_save_and_reload(slint::SharedString(composed.kdl));
            });
        });
    }

    template <typename ToggleFn>
    inline auto toggle_core_with_workspace(WorkspaceUiContext& ctx, ToggleFn&& run_toggle) -> void {
        if (ctx.lifecycle_busy.exchange(true, std::memory_order_acq_rel)) return;
        bool const en = is_en_ui(ctx.ui);
        bool const prefer_persistent = ctx.ui.get_tun_elevate_persistent();
        ctx.ui.set_core_toggling(true);
        ctx.ui.set_status_summary(slint::SharedString(tr(en, "正在切换连接状态...", "Switching connection...")));
        if (ctx.supervisor.running() || ctx.doc.profiles.empty()) {
            if (ctx.supervisor.running()) ctx.running_selector_members.clear();
            run_toggle(std::string(ctx.ui.get_kdl_text()), prefer_persistent, en);
            return;
        }
        auto active_id = resolve_effective_active_profile_id(ctx);
        (void)persist_workspace_and_host(ctx, en);
        bool posted = ctx.worker.post([&ctx, run_toggle = std::forward<ToggleFn>(run_toggle),
                                       active_id = std::move(active_id), prefer_persistent, en]() mutable {
            auto composed = desktop::compose_workspace_via_core(
                ctx.supervisor.binary_path(), ctx.workspace_path, ctx.host_path, ctx.secrets_dir, active_id, {});
            if (!composed.ok || composed.kdl.empty()) {
                auto err = composed.errors.empty() ? tr(en, "核心编译工作区失败", "Workspace compose failed") : composed.errors.front();
                on_ui_thread(ctx.weak_ui, [&ctx, err = std::move(err)](auto& s) {
                    s->set_core_toggling(false);
                    s->set_diagnostic_ok(false);
                    s->set_diagnostic_message(slint::SharedString(err));
                    s->set_status_summary(slint::SharedString(err));
                    push_toast(*s, err, "error");
                    if (ctx.sync_tray) ctx.sync_tray();
                    ctx.lifecycle_busy.store(false, std::memory_order_release);
                });
                return;
            }
            std::string kdl = composed.kdl;
            on_ui_thread(ctx.weak_ui, [&ctx, composed = std::move(composed)](auto& s) mutable {
                ctx.running_selector_tag = composed.selector_tag;
                ctx.running_selector_members = std::move(composed.selector_members);
                ctx.last_secret_files = std::move(composed.secret_files);
                apply_kdl_to_ui_state(*s, composed.kdl);
            });
            run_toggle(std::move(kdl), prefer_persistent, en);
        });
        if (!posted) {
            ctx.ui.set_core_toggling(false);
            ctx.lifecycle_busy.store(false, std::memory_order_release);
        }
    }
}
