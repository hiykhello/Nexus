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
            auto endpoint = on ? desktop::select_system_proxy_endpoint(read_inbounds_from_ui(u)) : std::nullopt;
            if (on && !endpoint) {
                u.set_system_proxy_enabled(false);
                push_toast(u, tr(is_en_ui(u), "请先启用本地入站端口", "Enable a local inbound port first"), "warn");
                if (ws_ctx.sync_tray) ws_ctx.sync_tray();
                return;
            }
            ws_ctx.worker.post([&ws_ctx, &sys_proxy, on, endpoint] {
                bool ok = on ? sys_proxy.enable(endpoint->first, endpoint->second) : sys_proxy.restore();
                on_ui_thread(ws_ctx.weak_ui, [&ws_ctx, active = ok && on](auto& s) {
                    s->set_system_proxy_enabled(active);
                    if (ws_ctx.sync_tray) ws_ctx.sync_tray();
                });
            });
        });

        auto apply_host_inbound_update = [&ws_ctx](bool en) {
            auto notices = persist_workspace_and_host(ws_ctx, en);
            sync_workspace_to_ui(ws_ctx);
            ws_ctx.ui.global<nexus_ui::WorkspaceState>().set_host_strict_route_notice(
                slint::SharedString(notices.empty() ? "" : notices.front()));
            if (!notices.empty()) push_toast(ws_ctx.ui, notices.front(), "warn");
            if (!ws_ctx.doc.profiles.empty()) recompose_active_workspace(ws_ctx);
            if (ws_ctx.ui.get_system_proxy_enabled()) ws_ctx.ui.invoke_toggle_system_proxy(true);
            if (ws_ctx.sync_tray) ws_ctx.sync_tray();
        };

        ui.on_apply_inbound_proxy_config([&ws_ctx, apply_host_inbound_update](
            slint::SharedString proto, bool enabled, slint::SharedString host, slint::SharedString port_s) {
            bool const en = is_en_ui(ws_ctx.ui);
            auto port = desktop::parse_port_u16(std::string_view(port_s));
            if (enabled && !port) {
                ws_ctx.ui.set_diagnostic_ok(false);
                ws_ctx.ui.set_diagnostic_message(slint::SharedString(tr(en, "入站端口需为 1..65535", "Inbound port must be 1..65535")));
                return;
            }
            auto ep = desktop::format_host_port(std::string_view(host), std::to_string(port.value_or(7890)));
            if (enabled && ep.empty()) {
                ws_ctx.ui.set_diagnostic_ok(false);
                ws_ctx.ui.set_diagnostic_message(slint::SharedString(tr(en, "入站监听地址无效", "Invalid inbound listen host")));
                return;
            }
            if (std::string_view(proto) == "mixed") {
                ws_ctx.host.enable_mixed = enabled;
                if (enabled) ws_ctx.host.mixed_listen = ep;
            } else if (std::string_view(proto) == "second" || std::string_view(proto) == "socks5") {
                ws_ctx.host.second_local_listen = enabled ? ep : std::string{};
            } else {
                auto lan_host = std::string_view(host).empty() ? std::string_view("0.0.0.0") : std::string_view(host);
                auto lan_ep = desktop::format_host_port(lan_host, std::to_string(port.value_or(7891)));
                ws_ctx.host.lan_listen = enabled ? lan_ep : std::string{};
            }
            apply_host_inbound_update(en);
        });

        ui.on_toggle_mixed_port([&ws_ctx, apply_host_inbound_update](bool on) {
            ws_ctx.host.enable_mixed = on;
            if (on && ws_ctx.host.mixed_listen.empty()) ws_ctx.host.mixed_listen = "127.0.0.1:7890";
            apply_host_inbound_update(is_en_ui(ws_ctx.ui));
        });

        ui.on_toggle_lan_share([&ws_ctx, apply_host_inbound_update](bool on) {
            if (on) {
                auto port = desktop::parse_port_u16(std::string_view(ws_ctx.ui.get_mixed_proxy_port())).value_or(7890);
                std::uint16_t lan_port = port < 65535 ? static_cast<std::uint16_t>(port + 1) : static_cast<std::uint16_t>(7891);
                ws_ctx.host.lan_listen = std::format("0.0.0.0:{}", lan_port);
            } else {
                ws_ctx.host.lan_listen.clear();
            }
            apply_host_inbound_update(is_en_ui(ws_ctx.ui));
        });

        ui.on_switch_outbound_mode([&ws_ctx, persist_prefs](slint::SharedString mode) {
            bool const en = is_en_ui(ws_ctx.ui);
            auto prev_mode = ws_ctx.ui.get_outbound_mode();
            auto grp = std::string(ws_ctx.ui.get_selected_group());
            std::string m(mode);
            if (m != "rule" && m != "global" && m != "direct") return;
            ws_ctx.ui.set_outbound_mode(mode);
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
