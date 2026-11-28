// Profile editor draft population (all 5 profile kinds) and async HTTP/HTTPS subscription refresh.
#pragma once

namespace desktop_ui_helpers {
    inline auto reset_editor_for_new_profile(WorkspaceUiContext& ctx, std::string_view kind_sv) -> void {
        auto const& ws = ctx.ui.global<nexus_ui::WorkspaceState>();
        std::string kind(trim_ascii_ws(kind_sv));
        if (kind.empty()) kind = "node";
        ws.set_editor_kind(slint::SharedString(kind));
        std::string cur_sub(ws.get_selected_sub_tab());
        if (cur_sub.empty() || cur_sub == "all") cur_sub = "manual";

        ws.set_editor_node_draft({
            slint::SharedString(""), slint::SharedString(cur_sub), slint::SharedString("vless"),
            slint::SharedString("node-" + std::to_string(ctx.doc.profiles.size() + 1)),
            slint::SharedString("edge.example.net"), slint::SharedString("443"),
            slint::SharedString(""), slint::SharedString(""), slint::SharedString(""),
            slint::SharedString("xtls-rprx-vision"), slint::SharedString("xudp"),
            slint::SharedString(""), slint::SharedString(""), slint::SharedString(""),
            slint::SharedString(""), slint::SharedString(""),
            slint::SharedString("bbr"), false, slint::SharedString("2022-blake3-aes-128-gcm"),
            5, slint::SharedString("none"), slint::SharedString(""), slint::SharedString("h2"), slint::SharedString(""),
            slint::SharedString(""), slint::SharedString(""), slint::SharedString("10.0.0.2/32"),
            slint::SharedString(""), slint::SharedString("1420"),
            slint::SharedString("connect-udp"), slint::SharedString(""), slint::SharedString(""),
            slint::SharedString(""), slint::SharedString("chrome"), slint::SharedString("default"), slint::SharedString(""),
            true, slint::SharedString(""), slint::SharedString(""), false, false,
            false, slint::SharedString(""), slint::SharedString(""),
            slint::SharedString("tcp"), slint::SharedString("/"), slint::SharedString(""), slint::SharedString("auto"),
            slint::SharedString(""), slint::SharedString(""), false,
            false, slint::SharedString("h2mux"), slint::SharedString("4"), slint::SharedString("2"), false,
        });
        ws.set_editor_group_draft({
            slint::SharedString(""), slint::SharedString(""), slint::SharedString("url-test"), slint::SharedString(""),
            slint::SharedString(""), slint::SharedString(""), slint::SharedString(""),
            slint::SharedString("https://www.gstatic.com/generate_204"), slint::SharedString("300000"),
            slint::SharedString("100"), false,
        });
        ws.set_editor_chain_draft({slint::SharedString(""), slint::SharedString(""), slint::SharedString("")});
        ws.set_editor_kdl_draft({slint::SharedString(""), slint::SharedString(""), slint::SharedString(kind), slint::SharedString("")});
        ws.set_editor_revision(ws.get_editor_revision() + 1);
    }

    inline auto populate_editor_for_profile(WorkspaceUiContext& ctx, std::string_view id_sv) -> void {
        auto const& ws = ctx.ui.global<nexus_ui::WorkspaceState>();
        desktop::WorkspaceProfileItem const* found = nullptr;
        for (auto const& p : ctx.doc.profiles) if (p.id == id_sv) { found = &p; break; }
        if (!found) { reset_editor_for_new_profile(ctx, "node"); return; }

        ws.set_editor_kind(slint::SharedString(found->kind));
        if (found->kind == "node") {
            auto const& n = found->node;
            std::string proto = n.protocol == "http" ? "http-connect" : (n.protocol.empty() ? "vless" : n.protocol);
            std::string tr_type = n.transport.type.empty() ? "tcp" : n.transport.type;
            std::string tr_path = tr_type == "grpc" ? n.transport.service_name : n.transport.path;
            std::string tr_host = tr_type == "grpc" ? n.transport.authority : n.transport.host;
            ws.set_editor_node_draft({
                slint::SharedString(found->id), slint::SharedString(found->subscription_id.empty() ? "manual" : found->subscription_id),
                slint::SharedString(proto), slint::SharedString(found->remarks),
                slint::SharedString(n.server), slint::SharedString(std::to_string(n.port)),
                slint::SharedString(n.password), slint::SharedString(proto == "tuic" ? n.username : ""),
                slint::SharedString(proto == "tuic" ? "" : n.username),
                slint::SharedString(n.flow.empty() ? "none" : n.flow),
                slint::SharedString(n.packet_encoding.empty() ? "xudp" : n.packet_encoding),
                slint::SharedString(n.extra.hy2_ports),
                slint::SharedString(n.extra.hy2_hop_interval_ms > 0 ? std::to_string(n.extra.hy2_hop_interval_ms) : ""),
                slint::SharedString(n.extra.hy2_salamander_password),
                slint::SharedString(n.extra.hy2_up_mbps > 0 ? std::to_string(n.extra.hy2_up_mbps) : ""),
                slint::SharedString(n.extra.hy2_down_mbps > 0 ? std::to_string(n.extra.hy2_down_mbps) : ""),
                slint::SharedString(n.extra.tuic_congestion_control.empty() ? "bbr" : n.extra.tuic_congestion_control),
                n.extra.tuic_udp_over_stream,
                slint::SharedString(n.method.empty() ? "2022-blake3-aes-128-gcm" : n.method),
                n.extra.snell_version == 4 ? 4 : 5,
                slint::SharedString(n.extra.snell_obfs.empty() ? "none" : n.extra.snell_obfs),
                slint::SharedString(n.extra.snell_obfs_host),
                slint::SharedString(n.extra.naive_protocol.empty() ? "h2" : n.extra.naive_protocol),
                slint::SharedString(join_csv(n.extra.ssh_host_key_sha256)),
                slint::SharedString(n.extra.wg_peer_public_key), slint::SharedString(n.extra.wg_preshared_key),
                slint::SharedString(join_csv(n.extra.wg_local_addresses)), slint::SharedString(n.extra.wg_reserved),
                slint::SharedString(std::to_string(n.extra.wg_mtu > 0 ? n.extra.wg_mtu : 1420)),
                slint::SharedString(n.extra.masque_mode.empty() ? "connect-udp" : n.extra.masque_mode),
                slint::SharedString(n.extra.masque_path), slint::SharedString(join_csv(n.extra.masque_local_addresses)),
                slint::SharedString(n.tls.sni), slint::SharedString(n.tls.fingerprint.empty() ? "default" : n.tls.fingerprint),
                slint::SharedString(n.tls.key_exchange.empty() ? "default" : n.tls.key_exchange),
                slint::SharedString(join_csv(n.tls.cert_sha256)),
                !n.tls.reality_public_key.empty(), slint::SharedString(n.tls.reality_public_key), slint::SharedString(n.tls.reality_short_id),
                n.tls.fragment, n.tls.record_fragment,
                !n.tls.ech_mode.empty(), slint::SharedString(n.tls.ech_config), slint::SharedString(n.tls.ech_query_server_name),
                slint::SharedString(tr_type), slint::SharedString(tr_path), slint::SharedString(tr_host),
                slint::SharedString(n.transport.xhttp_mode.empty() ? "auto" : n.transport.xhttp_mode),
                slint::SharedString(n.transport.max_early_data > 0 ? std::to_string(n.transport.max_early_data) : ""),
                slint::SharedString(n.transport.early_data_header_name), n.transport.grpc_permit_without_stream,
                n.multiplex.enabled, slint::SharedString(n.multiplex.protocol.empty() ? "h2mux" : n.multiplex.protocol),
                slint::SharedString(n.multiplex.max_connections > 0 ? std::to_string(n.multiplex.max_connections) : "4"),
                slint::SharedString(n.multiplex.min_streams > 0 ? std::to_string(n.multiplex.min_streams) : "2"),
                n.multiplex.padding,
            });
        } else if (found->kind == "policy_group") {
            auto const& g = found->policy_group;
            ws.set_editor_group_draft({
                slint::SharedString(found->id), slint::SharedString(found->remarks), slint::SharedString(g.strategy),
                slint::SharedString(join_csv(g.member_ids)), slint::SharedString(g.dynamic_sub_id),
                slint::SharedString(g.include_regex), slint::SharedString(g.exclude_regex),
                slint::SharedString(g.probe_url), slint::SharedString(std::to_string(g.probe_interval_ms)),
                slint::SharedString(std::to_string(g.tolerance_ms)), g.interrupt_exist_connections,
            });
        } else if (found->kind == "proxy_chain") {
            ws.set_editor_chain_draft({
                slint::SharedString(found->id), slint::SharedString(found->remarks),
                slint::SharedString(join_csv(found->proxy_chain.hop_ids)),
            });
        } else {
            ws.set_editor_kdl_draft({
                slint::SharedString(found->id), slint::SharedString(found->remarks), slint::SharedString(found->kind),
                slint::SharedString(found->kind == "custom_outbound" ? found->custom_outbound_kdl : found->full_custom_kdl),
            });
        }
        ws.set_editor_revision(ws.get_editor_revision() + 1);
    }

    inline auto refresh_subscription_async(WorkspaceUiContext& ctx, std::string target_sub_id) -> void {
        bool const en = is_en_ui(ctx.ui);
        auto const& ws = ctx.ui.global<nexus_ui::WorkspaceState>();
        if (ws.get_sub_updating()) return;

        std::vector<desktop::SubscriptionItem> targets;
        for (auto const& s : ctx.doc.subscriptions) {
            if (!s.enabled || s.url.empty()) continue;
            if (target_sub_id.empty() || s.id == target_sub_id) targets.push_back(s);
        }
        if (targets.empty()) {
            push_toast(ctx.ui, tr(en, "暂无可拉取的远端订阅 URL", "No subscription URLs configured"), "warn");
            return;
        }
        ws.set_sub_updating(true);
        ctx.ui.set_diagnostic_ok(true);
        ctx.ui.set_diagnostic_message(slint::SharedString(tr(en, "正在更新远端订阅节点...", "Updating subscription feeds...")));

        bool posted = ctx.worker.post([&ctx, targets = std::move(targets), en]() mutable {
            struct SubFetchItem {
                std::string sub_id;
                std::string sub_name;
                std::string error;
                std::vector<desktop::WorkspaceProfileItem> nodes;
            };
            std::vector<SubFetchItem> results;
            for (auto const& sub : targets) {
                SubFetchItem item{sub.id, sub.remarks.empty() ? sub.id : sub.remarks, {}, {}};
                std::vector<std::pair<std::string, std::string>> hdrs = sub.request_headers;
                if (!sub.user_agent.empty()) hdrs.emplace_back("User-Agent", sub.user_agent);
                auto resp = desktop::webdav_request("GET", sub.url, {}, {}, hdrs, {});
                if (!resp.transport_ok || resp.status_code < 200 || resp.status_code >= 300) {
                    item.error = resp.error.empty() ? std::format("HTTP {}", resp.status_code) : resp.error;
                    results.push_back(std::move(item));
                    continue;
                }
                std::optional<std::regex> inc_re, exc_re;
                try {
                    if (!sub.include_regex.empty()) inc_re.emplace(sub.include_regex, std::regex::ECMAScript | std::regex::icase);
                    if (!sub.exclude_regex.empty()) exc_re.emplace(sub.exclude_regex, std::regex::ECMAScript | std::regex::icase);
                } catch (...) {}

                auto lines = decode_subscription_lines(resp.body);
                for (auto const& ln : lines) {
                    auto parsed = desktop::parse_share_link(ln);
                    if (!parsed) continue;
                    std::string rem = parsed->tag.empty() ? parsed->host : parsed->tag;
                    if (inc_re && !std::regex_search(rem, *inc_re)) continue;
                    if (exc_re && std::regex_search(rem, *exc_re)) continue;
                    desktop::WorkspaceProfileItem p{};
                    p.subscription_id = sub.id;
                    p.is_from_sub = true;
                    p.kind = "node";
                    p.remarks = rem;
                    populate_node_from_parsed_share_link(p, *parsed);
                    item.nodes.push_back(std::move(p));
                }
                if (item.nodes.empty()) item.error = tr(en, "未解析到匹配的有效节点", "No matching valid nodes found");
                results.push_back(std::move(item));
            }

            on_ui_thread(ctx.weak_ui, [&ctx, results = std::move(results), en](auto& s) mutable {
                s->template global<nexus_ui::WorkspaceState>().set_sub_updating(false);
                std::size_t ok_subs = 0, total_nodes = 0;
                std::string last_err;
                auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                for (auto& r : results) {
                    if (!r.error.empty()) { last_err = r.sub_name + ": " + r.error; continue; }
                    std::size_t n_cnt = r.nodes.size();
                    auto rep = desktop::replace_subscription_profiles(
                        ctx.doc, r.sub_id, std::move(r.nodes), ctx.telemetry.active_profile_id);
                    if (rep.ok) {
                        ++ok_subs;
                        total_nodes += n_cnt;
                        for (auto& sub : ctx.doc.subscriptions) {
                            if (sub.id == r.sub_id) sub.updated_at_ms = now_ms;
                        }
                    } else {
                        last_err = rep.message;
                    }
                }
                if (ok_subs > 0) {
                    ++ctx.doc.revision;
                    (void)persist_workspace_db(ctx);
                    (void)persist_telemetry_db(ctx);
                    sync_workspace_to_ui(ctx);
                    if (ctx.sync_tray) ctx.sync_tray();
                    auto msg = std::format("{} ({} subs, {} nodes)",
                        tr(en, "订阅更新完成", "Subscriptions updated"), ok_subs, total_nodes);
                    s->set_diagnostic_ok(true);
                    s->set_diagnostic_message(slint::SharedString(msg));
                    push_toast(*s, msg, "success");
                    recompose_active_workspace(ctx);
                } else {
                    auto err = last_err.empty() ? tr(en, "订阅更新失败", "Subscription update failed") : last_err;
                    s->set_diagnostic_ok(false);
                    s->set_diagnostic_message(slint::SharedString(err));
                    push_toast(*s, err, "error");
                }
            });
        });
        if (!posted) ws.set_sub_updating(false);
    }
}
