// Quick-Settings Tile Bar & Outbound Mode UI callback bindings included by desktop/src/main.cpp.
#pragma once

namespace desktop_ui_helpers {
    inline auto bind_quick_control_callbacks(
        WorkspaceUiContext& ws_ctx,
        desktop::SystemProxyController& sys_proxy,
        std::function<void()> const& persist_prefs) -> void {
        auto& ui = ws_ctx.ui;

        ui.on_toggle_system_proxy([&ws_ctx, &sys_proxy](bool on) {
            auto& u = ws_ctx.ui;
            bool const en = is_en_ui(u);
            auto endpoint = on ? desktop::select_system_proxy_endpoint(read_inbounds_from_ui(u)) : std::nullopt;
            if (on && !endpoint) {
                u.set_system_proxy_enabled(false);
                push_toast(u, tr(en, "请先启用本地入站端口 (Mixed / HTTP / SOCKS5)", "Enable a local inbound port first"), "warn");
                if (ws_ctx.sync_tray) ws_ctx.sync_tray();
                return;
            }
            bool const core_up = ws_ctx.supervisor.running();
            ws_ctx.worker.post([&ws_ctx, &sys_proxy, on, endpoint, en, core_up] {
                bool ok = on ? sys_proxy.enable(endpoint->first, endpoint->second) : sys_proxy.restore();
                on_ui_thread(ws_ctx.weak_ui, [&ws_ctx, active = ok && on, on, ok, en, core_up, endpoint](auto& s) {
                    s->set_system_proxy_enabled(active);
                    if (!ok) {
                        push_toast(*s, tr(en, "设置系统代理失败", "Failed to update system proxy"), "error");
                    } else if (on && !core_up) {
                        push_toast(*s, tr(en, "系统代理已就绪，请启动核心以开始转发", "System proxy set; start Core to forward traffic"), "warn");
                    } else if (on && endpoint) {
                        push_toast(*s, tr(en, "已启用系统代理 → ", "System proxy → ")
                            + desktop::format_host_port(endpoint->first, std::to_string(endpoint->second)), "success");
                    } else {
                        push_toast(*s, tr(en, "已关闭系统代理", "System proxy disabled"), "info");
                    }
                    if (ws_ctx.sync_tray) ws_ctx.sync_tray();
                });
            });
        });

        auto apply_host_inbound_update = [&ws_ctx](desktop::DesktopHostConfig prev_host, bool en) {
            if (!has_any_enabled_inbound(ws_ctx.host)) {
                ws_ctx.host = std::move(prev_host);
                sync_workspace_to_ui(ws_ctx);
                push_toast(ws_ctx.ui, tr(en, "请至少保留一个活动入站 (Mixed / HTTP / SOCKS5 / TUN)", "Keep at least one inbound enabled (Mixed / HTTP / SOCKS5 / TUN)"), "warn");
                if (ws_ctx.sync_tray) ws_ctx.sync_tray();
                return;
            }
            auto notices = persist_workspace_and_host(ws_ctx, en);
            sync_workspace_to_ui(ws_ctx);
            ws_ctx.ui.global<nexus_ui::WorkspaceState>().set_host_strict_route_notice(
                slint::SharedString(notices.empty() ? "" : notices.front()));
            if (!notices.empty()) push_toast(ws_ctx.ui, notices.front(), "warn");
            if (!ws_ctx.doc.profiles.empty()) recompose_active_workspace(ws_ctx);
            sync_system_proxy_with_inbounds(ws_ctx, en);
            if (ws_ctx.sync_tray) ws_ctx.sync_tray();
        };

        ui.on_toggle_mixed_port([&ws_ctx, apply_host_inbound_update](bool on) {
            auto prev = ws_ctx.host;
            ws_ctx.host.enable_mixed = on;
            if (on && ws_ctx.host.mixed_listen.empty()) ws_ctx.host.mixed_listen = "127.0.0.1:7890";
            apply_host_inbound_update(std::move(prev), is_en_ui(ws_ctx.ui));
        });

        ui.on_toggle_http_port([&ws_ctx, apply_host_inbound_update](bool on) {
            auto prev = ws_ctx.host;
            ws_ctx.host.enable_http = on;
            if (on && ws_ctx.host.http_listen.empty()) ws_ctx.host.http_listen = "127.0.0.1:10809";
            apply_host_inbound_update(std::move(prev), is_en_ui(ws_ctx.ui));
        });

        ui.on_toggle_socks_port([&ws_ctx, apply_host_inbound_update](bool on) {
            auto prev = ws_ctx.host;
            ws_ctx.host.enable_socks = on;
            ws_ctx.host.second_local_listen.clear();
            if (on && ws_ctx.host.socks_listen.empty()) ws_ctx.host.socks_listen = "127.0.0.1:10808";
            apply_host_inbound_update(std::move(prev), is_en_ui(ws_ctx.ui));
        });

        ui.on_toggle_lan_share([&ws_ctx, apply_host_inbound_update](bool on) {
            auto prev = ws_ctx.host;
            ws_ctx.host.allow_lan = on;
            if (!on) ws_ctx.host.lan_listen.clear();
            apply_host_inbound_update(std::move(prev), is_en_ui(ws_ctx.ui));
        });

        ui.on_switch_outbound_mode([&ws_ctx, persist_prefs](slint::SharedString mode) {
            bool const en = is_en_ui(ws_ctx.ui);
            auto prev_mode = ws_ctx.ui.get_outbound_mode();
            auto grp = std::string(ws_ctx.ui.get_selected_group());
            std::string m(mode);
            if (m != "rule" && m != "global" && m != "direct") return;
            ws_ctx.ui.set_outbound_mode(mode);
            ws_ctx.rate_tracker.mark_onset(
                m == "global" ? tr(en, "全局", "Global") : m == "direct" ? tr(en, "直连", "Direct") : tr(en, "规则", "Rule"));
            if (persist_prefs) persist_prefs();
            if (ws_ctx.supervisor.running()) {
                bool posted = ws_ctx.worker.post([&ws_ctx, persist_prefs, en, m, grp, prev_mode] {
                    auto reply = ws_ctx.http_ctrl.set_mode(m, grp);
                    on_ui_thread(ws_ctx.weak_ui, [&ws_ctx, persist_prefs, ok = reply.ok, en, prev_mode, msg = std::move(reply.body)](auto& s) {
                        s->set_diagnostic_ok(ok);
                        if (!ok) {
                            s->set_outbound_mode(prev_mode);
                            if (persist_prefs) persist_prefs();
                            auto err = tr(en, "切换模式失败: ", "Mode switch failed: ") + msg;
                            s->set_diagnostic_message(slint::SharedString(err));
                            push_toast(*s, err, "error");
                        }
                        if (ws_ctx.sync_tray) ws_ctx.sync_tray();
                    });
                });
                if (!posted) ws_ctx.ui.set_outbound_mode(prev_mode);
                return;
            }
            if (ws_ctx.sync_tray) ws_ctx.sync_tray();
        });
    }
}
