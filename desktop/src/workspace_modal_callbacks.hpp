// Structured outbound node, route rule, and DNS rule modal form callbacks for desktop/src/main.cpp.
#pragma once

namespace desktop_ui_helpers {
    inline auto bind_structured_modal_callbacks(WorkspaceUiContext& ctx) -> void {
        ctx.ui.on_add_outbound_node([&ctx](nexus_ui::OutboundNodeDraft d) {
            bool const en = is_en_ui(ctx.ui);
            OutboundFormDraft form{
                .edit_id = std::string(d.edit_id), .sub_id = std::string(d.sub_id),
                .proto = std::string(d.proto), .tag = std::string(d.tag),
                .host = std::string(d.host), .port = std::string(d.port),
                .secret = std::string(d.secret), .uuid_str = std::string(d.uuid_str),
                .username = std::string(d.username), .flow = std::string(d.flow),
                .packet_encoding = std::string(d.packet_encoding),
                .hy2_ports = std::string(d.hy2_ports), .hy2_hop_interval = std::string(d.hy2_hop_interval),
                .hy2_salamander = std::string(d.hy2_salamander),
                .hy2_up_mbps = std::string(d.hy2_up_mbps), .hy2_down_mbps = std::string(d.hy2_down_mbps),
                .tuic_cc = std::string(d.tuic_cc), .tuic_udp_over_stream = d.tuic_udp_over_stream,
                .ss_method = std::string(d.ss_method), .snell_ver = d.snell_ver,
                .snell_obfs = std::string(d.snell_obfs), .snell_obfs_host = std::string(d.snell_obfs_host),
                .naive_proto = std::string(d.naive_proto), .ssh_host_sha = std::string(d.ssh_host_sha),
                .wg_peer_pbk = std::string(d.wg_peer_pbk), .wg_psk = std::string(d.wg_psk),
                .wg_local_cidr = std::string(d.wg_local_cidr), .wg_reserved = std::string(d.wg_reserved),
                .wg_mtu = std::string(d.wg_mtu),
                .masque_mode = std::string(d.masque_mode), .masque_path = std::string(d.masque_path),
                .masque_local_cidr = std::string(d.masque_local_cidr),
                .sni = std::string(d.sni), .fingerprint = std::string(d.fingerprint),
                .key_exchange = std::string(d.key_exchange), .cert_sha256 = std::string(d.cert_sha256),
                .use_reality = d.use_reality, .reality_pbk = std::string(d.reality_pbk), .reality_sid = std::string(d.reality_sid),
                .client_hello_fragment = d.client_hello_fragment, .tls_fragment = d.tls_fragment,
                .ech_dns = d.ech_dns, .ech_config = std::string(d.ech_config), .ech_query_sni = std::string(d.ech_query_sni),
                .transport = std::string(d.transport), .transport_path = std::string(d.transport_path),
                .transport_host = std::string(d.transport_host), .xhttp_mode = std::string(d.xhttp_mode),
                .ws_max_early_data = std::string(d.ws_max_early_data), .ws_early_data_header = std::string(d.ws_early_data_header),
                .grpc_permit_without_stream = d.grpc_permit_without_stream,
                .mux_enabled = d.mux_enabled, .mux_proto = std::string(d.mux_proto),
                .mux_max_conns = std::string(d.mux_max_conns), .mux_min_streams = std::string(d.mux_min_streams),
                .mux_padding = d.mux_padding,
            };
            std::unordered_set<std::string> ids;
            for (auto const& p : ctx.doc.profiles) ids.insert(p.id);
            auto built = build_workspace_node_from_form(form, ids, ctx.doc.profiles.size());
            if (!built) {
                ctx.ui.set_diagnostic_ok(false);
                ctx.ui.set_diagnostic_message(slint::SharedString(built.error()));
                push_toast(ctx.ui, built.error(), "error");
                return;
            }
            std::string target_id = built->id;
            std::string label = built->remarks;
            bool updated = false;
            if (!form.edit_id.empty()) {
                for (auto& p : ctx.doc.profiles) {
                    if (p.id == form.edit_id) {
                        built->is_from_sub = p.is_from_sub;
                        p = std::move(*built);
                        updated = true;
                        break;
                    }
                }
            }
            if (!updated) ctx.doc.profiles.push_back(std::move(*built));
            ++ctx.doc.revision;
            ctx.telemetry.active_profile_id = target_id;
            (void)persist_workspace_db(ctx);
            (void)persist_telemetry_db(ctx);
            sync_workspace_to_ui(ctx);
            if (ctx.sync_tray) ctx.sync_tray();
            ctx.ui.set_outbound_modal_open(false);
            push_toast(ctx.ui, (updated ? tr(en, "已更新节点: ", "Updated node: ") : tr(en, "已添加节点: ", "Added node: ")) + label, "success");
            recompose_active_workspace(ctx, target_id);
        });

        ctx.ui.on_add_route_rule([&ctx](nexus_ui::RouteRuleDraft d) {
            bool const en = is_en_ui(ctx.ui);
            RouteRuleFormDraft form{
                .use_rule_set = d.use_rule_set, .rule_set_name = std::string(d.rule_set_name),
                .conditions = {}, .action_kind = std::string(d.action_kind),
                .target_outbound = std::string(d.target_outbound), .tls_fragment = d.tls_fragment,
            };
            int const count = std::clamp(d.cond_count, 1, 4);
            if (count >= 1) form.conditions.push_back({std::string(d.c1_kind), std::string(d.c1_value)});
            if (count >= 2) form.conditions.push_back({std::string(d.c2_kind), std::string(d.c2_value)});
            if (count >= 3) form.conditions.push_back({std::string(d.c3_kind), std::string(d.c3_value)});
            if (count >= 4) form.conditions.push_back({std::string(d.c4_kind), std::string(d.c4_value)});

            if (ctx.doc.routing_profiles.empty()) ctx.doc.routing_profiles = desktop::make_default_workspace().routing_profiles;
            desktop::RoutingProfile* active_rp = nullptr;
            for (auto& rp : ctx.doc.routing_profiles) if (rp.is_active) { active_rp = &rp; break; }
            if (!active_rp) { ctx.doc.routing_profiles.front().is_active = true; active_rp = &ctx.doc.routing_profiles.front(); }

            auto built = build_routing_rule_from_draft(form, ctx.doc.profiles, active_rp->rules.size());
            if (!built) {
                ctx.ui.set_diagnostic_ok(false); ctx.ui.set_diagnostic_message(slint::SharedString(built.error()));
                push_toast(ctx.ui, built.error(), "error");
                return;
            }
            active_rp->rules.push_back(std::move(*built));
            ++ctx.doc.revision;
            (void)persist_workspace_db(ctx);
            sync_workspace_to_ui(ctx);
            ctx.ui.set_diagnostic_ok(true);
            ctx.ui.set_diagnostic_message(slint::SharedString(tr(en, "已添加路由规则", "Route rule added")));
            recompose_active_workspace(ctx);
        });

        ctx.ui.on_add_dns_rule([&ctx](nexus_ui::DnsRuleDraft d) {
            bool const en = is_en_ui(ctx.ui);
            DnsRuleFormDraft form{
                .match_kind = std::string(d.match_kind), .match_value = std::string(d.match_value),
                .action_kind = std::string(d.action_kind), .target_server = std::string(d.target_server),
            };
            if (ctx.doc.routing_profiles.empty()) ctx.doc.routing_profiles = desktop::make_default_workspace().routing_profiles;
            desktop::RoutingProfile* active_rp = nullptr;
            for (auto& rp : ctx.doc.routing_profiles) if (rp.is_active) { active_rp = &rp; break; }
            if (!active_rp) { ctx.doc.routing_profiles.front().is_active = true; active_rp = &ctx.doc.routing_profiles.front(); }

            auto built = build_dns_rule_from_draft(form, active_rp->rules.size());
            if (!built) {
                ctx.ui.set_diagnostic_ok(false); ctx.ui.set_diagnostic_message(slint::SharedString(built.error()));
                push_toast(ctx.ui, built.error(), "error");
                return;
            }
            active_rp->rules.push_back(std::move(*built));
            ++ctx.doc.revision;
            (void)persist_workspace_db(ctx);
            sync_workspace_to_ui(ctx);
            ctx.ui.set_diagnostic_ok(true);
            ctx.ui.set_diagnostic_message(slint::SharedString(tr(en, "已添加 DNS 规则", "DNS rule added")));
            recompose_active_workspace(ctx);
        });
    }
}
