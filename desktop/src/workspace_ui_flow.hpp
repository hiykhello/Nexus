// 4-Layer Workspace UI callbacks, structured modal builders, and portable backup for desktop/src/main.cpp.
#pragma once

#include "workspace_ui_sync.hpp"
#include "workspace_sync_flow.hpp"

namespace desktop_ui_helpers {
    inline auto import_share_uri_to_workspace(WorkspaceUiContext& ctx, std::string_view raw_uri) -> void {
        if (trim_ascii_ws(raw_uri).starts_with("nexus://")) {
            import_share_bundle_async(ctx, std::string(trim_ascii_ws(raw_uri)));
            return;
        }
        bool const en = is_en_ui(ctx.ui);
        std::unordered_set<std::string> ids;
        for (auto const& p : ctx.doc.profiles) ids.insert(p.id);
        auto built = build_workspace_profile_from_draft("node", "", raw_uri, "", ids, ctx.doc.profiles.size());
        if (!built) {
            auto msg = tr(en, "分享链接解析失败: ", "Share URI error: ") + built.error();
            ctx.ui.set_diagnostic_ok(false);
            ctx.ui.set_diagnostic_message(slint::SharedString(msg));
            push_toast(ctx.ui, msg, "error");
            return;
        }
        std::string new_id = built->id;
        std::string new_remarks = built->remarks;
        ctx.doc.profiles.push_back(std::move(*built));
        ++ctx.doc.revision;
        ctx.telemetry.active_profile_id = new_id;
        (void)persist_workspace_db(ctx);
        (void)persist_telemetry_db(ctx);
        ctx.ui.set_share_link_input(slint::SharedString(""));
        ctx.ui.set_active_profile(slint::SharedString(new_remarks));
        sync_workspace_to_ui(ctx);
        recompose_active_workspace(ctx, new_id);
    }

    inline auto refresh_workspace_from_disk(WorkspaceUiContext& ctx) -> void {
        if (ctx.db) {
            if (auto loaded = ctx.db->load_workspace(); loaded) ctx.doc = std::move(*loaded);
            ctx.host = desktop::load_host_config_from_db(*ctx.db, ctx.cfg_dir, ctx.secrets_dir, {});
            if (auto tel = ctx.db->load_telemetry(); tel) ctx.telemetry = std::move(*tel);
        }
        if (ensure_default_workspace_profile(ctx.doc, ctx.telemetry)) {
            (void)persist_workspace_db(ctx);
            (void)persist_telemetry_db(ctx);
        }
        auto notices = desktop::normalize_desktop_host_config(ctx.host, is_en_ui(ctx.ui));
        sync_workspace_to_ui(ctx);
        sync_webdav_fields_to_ui(ctx);
        ctx.ui.global<nexus_ui::WorkspaceState>().set_host_strict_route_notice(
            slint::SharedString(notices.empty() ? "" : notices.front()));
        if (ctx.sync_tray) ctx.sync_tray();
    }

    inline auto bind_structured_modal_callbacks(WorkspaceUiContext& ctx) -> void {
        ctx.ui.on_add_outbound_node([&ctx](nexus_ui::OutboundNodeDraft d) {
            bool const en = is_en_ui(ctx.ui);
            OutboundFormDraft form{
                .proto = std::string(d.proto), .tag = std::string(d.tag),
                .host = std::string(d.host), .port = std::string(d.port),
                .secret = std::string(d.secret), .uuid_str = std::string(d.uuid_str),
                .username = std::string(d.username), .flow = std::string(d.flow),
                .hy2_ports = std::string(d.hy2_ports), .hy2_salamander = std::string(d.hy2_salamander),
                .hy2_up_mbps = std::string(d.hy2_up_mbps), .hy2_down_mbps = std::string(d.hy2_down_mbps),
                .tuic_cc = std::string(d.tuic_cc), .tuic_udp_over_stream = d.tuic_udp_over_stream,
                .ss_method = std::string(d.ss_method), .snell_ver = d.snell_ver,
                .snell_obfs = std::string(d.snell_obfs), .snell_obfs_host = std::string(d.snell_obfs_host),
                .naive_proto = std::string(d.naive_proto), .ssh_host_sha = std::string(d.ssh_host_sha),
                .sni = std::string(d.sni), .fingerprint = std::string(d.fingerprint),
                .cert_sha256 = std::string(d.cert_sha256), .use_reality = d.use_reality,
                .reality_pbk = std::string(d.reality_pbk), .reality_sid = std::string(d.reality_sid),
                .tls_fragment = d.tls_fragment, .ech_dns = d.ech_dns, .ech_query_sni = std::string(d.ech_query_sni),
                .transport = std::string(d.transport), .transport_path = std::string(d.transport_path),
                .transport_host = std::string(d.transport_host), .xhttp_mode = std::string(d.xhttp_mode),
                .ws_max_early_data = std::string(d.ws_max_early_data), .ws_early_data_header = std::string(d.ws_early_data_header),
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
            std::string new_id = built->id;
            std::string label = built->remarks;
            ctx.doc.profiles.push_back(std::move(*built));
            ++ctx.doc.revision;
            ctx.telemetry.active_profile_id = new_id;
            (void)persist_workspace_db(ctx);
            (void)persist_telemetry_db(ctx);
            sync_workspace_to_ui(ctx);
            if (ctx.sync_tray) ctx.sync_tray();
            ctx.ui.set_outbound_modal_open(false);
            push_toast(ctx.ui, tr(en, "已添加节点: ", "Added node: ") + label, "success");
            recompose_active_workspace(ctx, new_id);
        });

        ctx.ui.on_add_route_rule([&ctx](nexus_ui::RouteRuleDraft d) {
            bool const en = is_en_ui(ctx.ui);
            RouteRuleFormDraft form{
                .use_rule_set = d.use_rule_set,
                .rule_set_name = std::string(d.rule_set_name),
                .conditions = {},
                .action_kind = std::string(d.action_kind),
                .target_outbound = std::string(d.target_outbound),
                .tls_fragment = d.tls_fragment,
            };
            int const count = std::clamp(d.cond_count, 1, 4);
            if (count >= 1) form.conditions.push_back({std::string(d.c1_kind), std::string(d.c1_value)});
            if (count >= 2) form.conditions.push_back({std::string(d.c2_kind), std::string(d.c2_value)});
            if (count >= 3) form.conditions.push_back({std::string(d.c3_kind), std::string(d.c3_value)});
            if (count >= 4) form.conditions.push_back({std::string(d.c4_kind), std::string(d.c4_value)});

            if (ctx.doc.routing_profiles.empty()) {
                ctx.doc.routing_profiles = desktop::make_default_workspace().routing_profiles;
            }
            desktop::RoutingProfile* active_rp = nullptr;
            for (auto& rp : ctx.doc.routing_profiles) if (rp.is_active) { active_rp = &rp; break; }
            if (!active_rp) { ctx.doc.routing_profiles.front().is_active = true; active_rp = &ctx.doc.routing_profiles.front(); }

            auto built = build_routing_rule_from_draft(form, ctx.doc.profiles, active_rp->rules.size());
            if (!built) {
                ctx.ui.set_diagnostic_ok(false);
                ctx.ui.set_diagnostic_message(slint::SharedString(built.error()));
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
                .match_kind = std::string(d.match_kind),
                .match_value = std::string(d.match_value),
                .action_kind = std::string(d.action_kind),
                .target_server = std::string(d.target_server),
            };
            if (ctx.doc.routing_profiles.empty()) {
                ctx.doc.routing_profiles = desktop::make_default_workspace().routing_profiles;
            }
            desktop::RoutingProfile* active_rp = nullptr;
            for (auto& rp : ctx.doc.routing_profiles) if (rp.is_active) { active_rp = &rp; break; }
            if (!active_rp) { ctx.doc.routing_profiles.front().is_active = true; active_rp = &ctx.doc.routing_profiles.front(); }

            auto built = build_dns_rule_from_draft(form, active_rp->rules.size());
            if (!built) {
                ctx.ui.set_diagnostic_ok(false);
                ctx.ui.set_diagnostic_message(slint::SharedString(built.error()));
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

    inline auto bind_workspace_callbacks(WorkspaceUiContext& ctx) -> void {
        auto const runtime_dir = ctx.cfg_dir / "runtime";
        std::error_code ec;
        std::filesystem::create_directories(runtime_dir, ec);
        ctx.workspace_path = runtime_dir / "compose-workspace.json";
        ctx.host_path = runtime_dir / "compose-host.json";
        ctx.secrets_dir = ctx.cfg_dir / "secrets";

        if (ctx.db) {
            auto loaded = ctx.db->load_workspace();
            ctx.doc = loaded ? std::move(*loaded) : desktop::make_default_workspace();
            ctx.host = desktop::load_host_config_from_db(*ctx.db, ctx.cfg_dir, ctx.secrets_dir, {});
            if (auto tel = ctx.db->load_telemetry(); tel) ctx.telemetry = std::move(*tel);
        } else {
            ctx.doc = desktop::make_default_workspace();
            ctx.host = desktop::make_default_desktop_host_config(ctx.cfg_dir, {});
        }
        ctx.host.control_socket.clear();

        if (ensure_default_workspace_profile(ctx.doc, ctx.telemetry)) {
            (void)persist_workspace_db(ctx);
            (void)persist_telemetry_db(ctx);
        }
        auto init_ctl = parse_host_control_config(ctx.host);
        ctx.http_ctrl.set_endpoint(init_ctl.http_host, init_ctl.http_port);
        ctx.http_ctrl.set_bearer_token(init_ctl.bearer_token);

        auto notices = desktop::normalize_desktop_host_config(ctx.host, is_en_ui(ctx.ui));
        sync_workspace_to_ui(ctx);
        bind_workspace_sync_callbacks(ctx);
        bind_structured_modal_callbacks(ctx);
        auto const& ws = ctx.ui.global<nexus_ui::WorkspaceState>();
        if (!notices.empty()) ws.set_host_strict_route_notice(slint::SharedString(notices.front()));

        ws.on_activate_profile([&ctx](slint::SharedString id_s) {
            bool const en = is_en_ui(ctx.ui);
            std::string const id(id_s);
            desktop::WorkspaceProfileItem const* found = nullptr;
            for (auto const& p : ctx.doc.profiles) if (p.id == id) { found = &p; break; }
            if (!found) return;

            ctx.telemetry.active_profile_id = id;
            (void)persist_telemetry_db(ctx);
            ctx.ui.set_active_profile(slint::SharedString(found->remarks.empty() ? found->id : found->remarks));
            sync_workspace_to_ui(ctx);
            if (ctx.sync_tray) ctx.sync_tray();

            auto live_tag = desktop::resolve_live_switch_tag(ctx.doc, id);
            auto decision = desktop::decide_tun_live_switch(
                ctx.supervisor.running(), ctx.host.enable_tun || ctx.ui.get_tun_enabled(),
                ctx.running_selector_tag, ctx.running_selector_members, live_tag);
            if (decision.can_live_switch) {
                ctx.worker.post([&ctx, decision, en] {
                    bool ok = ctx.http_ctrl.select_group(decision.selector_tag, decision.target_tag).ok;
                    auto msg = ok ? tr(en, "已热切换 TUN 节点（免重启提权）", "Switched TUN node live (zero restart)")
                                  : tr(en, "热切换节点失败", "Live node switch failed");
                    on_ui_thread(ctx.weak_ui, [&ctx, ok, msg = std::move(msg)](auto& s) {
                        push_toast(*s, msg, ok ? "success" : "error");
                        if (ctx.sync_tray) ctx.sync_tray();
                    });
                });
                return;
            }
            recompose_active_workspace(ctx, id);
        });

        ws.on_create_profile([&ctx](slint::SharedString kind_s, slint::SharedString remarks_s, slint::SharedString payload_s) {
            bool const en = is_en_ui(ctx.ui);
            std::unordered_set<std::string> ids;
            for (auto const& p : ctx.doc.profiles) ids.insert(p.id);
            auto built = build_workspace_profile_from_draft(
                std::string_view(kind_s), std::string_view(remarks_s), std::string_view(payload_s),
                {}, ids, ctx.doc.profiles.size());
            if (!built) {
                push_toast(ctx.ui, built.error(), "error");
                return;
            }
            auto const& g = ctx.ui.global<nexus_ui::WorkspaceState>();
            if (built->kind == "policy_group") {
                built->policy_group.interrupt_exist_connections = g.get_draft_group_interrupt();
                g.set_draft_group_interrupt(false);
            }
            std::string label = built->remarks;
            ctx.doc.profiles.push_back(std::move(*built));
            ++ctx.doc.revision;
            if (ctx.telemetry.active_profile_id.empty()) ctx.telemetry.active_profile_id = ctx.doc.profiles.back().id;
            (void)persist_workspace_db(ctx);
            (void)persist_telemetry_db(ctx);
            sync_workspace_to_ui(ctx);
            if (ctx.sync_tray) ctx.sync_tray();
            push_toast(ctx.ui, tr(en, "已添加到工作区: ", "Added to workspace: ") + label, "success");
        });

        ws.on_delete_profile([&ctx](slint::SharedString id_s) {
            std::string const id(id_s);
            std::erase_if(ctx.doc.profiles, [&](auto const& p) { return p.id == id; });
            std::unordered_set<std::string> live;
            for (auto const& p : ctx.doc.profiles) live.insert(p.id);
            (void)desktop::prune_telemetry_entries(ctx.telemetry, live);
            ++ctx.doc.revision;
            (void)persist_workspace_db(ctx);
            (void)persist_telemetry_db(ctx);
            sync_workspace_to_ui(ctx);
            if (ctx.sync_tray) ctx.sync_tray();
        });

        ws.on_add_subscription([&ctx](slint::SharedString rem_s, slint::SharedString url_s, slint::SharedString prev_s, slint::SharedString next_s) {
            bool const en = is_en_ui(ctx.ui);
            std::string rem(trim_ascii_ws(std::string_view(rem_s))), url(trim_ascii_ws(std::string_view(url_s)));
            if (!url.empty() && !desktop::is_safe_subscription_link(url)) {
                push_toast(ctx.ui, tr(en, "仅允许 http/https/tg 订阅链接", "Only http/https/tg subscription URLs allowed"), "error");
                return;
            }
            if (rem.empty()) rem = "Sub-" + std::to_string(ctx.doc.subscriptions.size() + 1);
            desktop::SubscriptionItem sub{};
            auto base_id = desktop::sanitize_workspace_id(rem);
            if (base_id == "manual") base_id = "sub-manual";
            std::unordered_set<std::string> sub_ids;
            for (auto const& s : ctx.doc.subscriptions) sub_ids.insert(s.id);
            sub.id = base_id;
            for (int n = 2; sub_ids.contains(sub.id); ++n) sub.id = base_id + "-" + std::to_string(n);
            sub.remarks = rem; sub.url = url;
            sub.prev_profile_id = std::string(trim_ascii_ws(std::string_view(prev_s)));
            sub.next_profile_id = std::string(trim_ascii_ws(std::string_view(next_s)));
            ctx.doc.subscriptions.push_back(std::move(sub));
            ++ctx.doc.revision;
            (void)persist_workspace_db(ctx);
            sync_workspace_to_ui(ctx);
            push_toast(ctx.ui, tr(en, "已保存订阅: ", "Saved subscription: ") + rem, "success");
        });

        ws.on_update_subscription_chain([&ctx](slint::SharedString sid, slint::SharedString prev_s, slint::SharedString next_s) {
            for (auto& s : ctx.doc.subscriptions) {
                if (s.id == std::string_view(sid)) {
                    s.prev_profile_id = std::string(trim_ascii_ws(std::string_view(prev_s)));
                    s.next_profile_id = std::string(trim_ascii_ws(std::string_view(next_s)));
                    ++ctx.doc.revision;
                    (void)persist_workspace_db(ctx);
                    sync_workspace_to_ui(ctx);
                    recompose_active_workspace(ctx);
                    break;
                }
            }
        });

        ws.on_delete_subscription([&ctx](slint::SharedString sid) {
            std::string const id(sid);
            if (id == "manual") return;
            std::erase_if(ctx.doc.subscriptions, [&](auto const& s) { return s.id == id; });
            ++ctx.doc.revision;
            (void)persist_workspace_db(ctx);
            sync_workspace_to_ui(ctx);
        });

        ws.on_select_routing_profile([&ctx](slint::SharedString rid) {
            for (auto& rp : ctx.doc.routing_profiles) rp.is_active = (rp.id == std::string_view(rid));
            ++ctx.doc.revision;
            (void)persist_workspace_db(ctx);
            sync_workspace_to_ui(ctx);
            recompose_active_workspace(ctx);
        });

        ws.on_apply_routing_options([&ctx](bool auto_detect, bool find_proc) {
            for (auto& rp : ctx.doc.routing_profiles) {
                if (!rp.is_active) continue;
                rp.auto_detect_interface = auto_detect;
                rp.find_process = find_proc;
                ++ctx.doc.revision;
                (void)persist_workspace_db(ctx);
                sync_workspace_to_ui(ctx);
                recompose_active_workspace(ctx);
                break;
            }
        });

        ws.on_add_routing_rule([&ctx](slint::SharedString scope, slint::SharedString tgt_type, slint::SharedString tgt_pid,
                                      slint::SharedString match_s, slint::SharedString proc_s) {
            bool const en = is_en_ui(ctx.ui);
            auto tokens = split_csv_trim(std::string_view(match_s));
            auto procs = split_csv_trim(std::string_view(proc_s));
            if (tokens.empty() && procs.empty()) {
                push_toast(ctx.ui, tr(en, "请至少填写一个域名、IP/CIDR 或进程名", "Provide at least one domain, IP/CIDR, or process name"), "error");
                return;
            }
            bool const tls_frag = ctx.ui.global<nexus_ui::WorkspaceState>().get_rule_tls_fragment();
            for (auto& rp : ctx.doc.routing_profiles) {
                if (!rp.is_active) continue;
                desktop::RoutingRule r{};
                r.id = "r-" + std::to_string(rp.rules.size() + 1);
                r.scope = std::string(scope);
                r.target_type = std::string(tgt_type);
                r.target_profile_id = std::string(trim_ascii_ws(std::string_view(tgt_pid)));
                for (auto const& tok : tokens) {
                    if (is_ip_or_cidr_rule_token(tok)) r.ips.push_back(tok);
                    else r.domains.push_back(tok);
                }
                r.desktop_process = std::move(procs);
                r.tls_fragment = tls_frag;
                rp.rules.push_back(std::move(r));
                ++ctx.doc.revision;
                (void)persist_workspace_db(ctx);
                sync_workspace_to_ui(ctx);
                recompose_active_workspace(ctx);
                break;
            }
        });

        ws.on_apply_dns_config([&ctx](slint::SharedString mode, slint::SharedString dir_s, slint::SharedString rem_s,
                                      bool fakeip, slint::SharedString raw_kdl) {
            ctx.doc.dns.mode = std::string(mode);
            if (auto v = split_csv_trim(std::string_view(dir_s)); !v.empty()) ctx.doc.dns.simple.direct_dns = std::move(v);
            if (auto v = split_csv_trim(std::string_view(rem_s)); !v.empty()) ctx.doc.dns.simple.remote_dns = std::move(v);
            ctx.doc.dns.simple.fake_ip_enabled = fakeip;
            ctx.doc.dns.raw_kdl = std::string(raw_kdl);
            ++ctx.doc.revision;
            (void)persist_workspace_db(ctx);
            sync_workspace_to_ui(ctx);
            recompose_active_workspace(ctx);
        });

        ws.on_apply_host_config([&ctx] {
            bool const en = is_en_ui(ctx.ui);
            auto const& g = ctx.ui.global<nexus_ui::WorkspaceState>();
            ctx.host.enable_mixed = g.get_host_enable_mixed();
            ctx.host.mixed_listen = std::string(g.get_host_mixed_listen());
            ctx.host.enable_tun = g.get_host_enable_tun();
            ctx.host.tun_strict_route = g.get_host_tun_strict_route();
            std::string mtu_s(g.get_host_tun_mtu());
            std::int64_t mtu = 1400;
            if (auto [p, ec] = std::from_chars(mtu_s.data(), mtu_s.data() + mtu_s.size(), mtu); ec == std::errc{}) ctx.host.tun_mtu = mtu;
            std::string workers_s(trim_ascii_ws(std::string_view(g.get_host_workers())));
            std::int64_t workers_val = ctx.host.workers;
            if (auto [p, ec] = std::from_chars(workers_s.data(), workers_s.data() + workers_s.size(), workers_val); ec == std::errc{})
                ctx.host.workers = workers_val;
            ctx.host.workers_spec = std::string(trim_ascii_ws(std::string_view(g.get_host_workers_spec())));
            std::string wmax_s(trim_ascii_ws(std::string_view(g.get_host_workers_max())));
            std::int64_t wmax_val = 0;
            if (auto [p, ec] = std::from_chars(wmax_s.data(), wmax_s.data() + wmax_s.size(), wmax_val); ec == std::errc{})
                ctx.host.workers_max = wmax_val;
            auto notices = persist_workspace_and_host(ctx, en);
            sync_workspace_to_ui(ctx);
            g.set_host_strict_route_notice(slint::SharedString(notices.empty() ? "" : notices.front()));
            if (!notices.empty()) push_toast(ctx.ui, notices.front(), "warn");
            if (!ctx.doc.profiles.empty()) recompose_active_workspace(ctx);
            else if (notices.empty()) push_toast(ctx.ui, tr(en, "已保存本机设置", "Saved local settings"), "success");
        });

        ws.on_export_portable_workspace([&ctx] {
            bool const en = is_en_ui(ctx.ui);
            auto out_path = ctx.cfg_dir / "workspace-export.json";
            bool ok = desktop::save_workspace_atomic(out_path, ctx.doc);
            auto msg = ok ? tr(en, "已导出便携工作区备份", "Exported portable workspace backup")
                          : tr(en, "导出工作区失败", "Failed to export portable workspace");
            auto const& g = ctx.ui.global<nexus_ui::WorkspaceState>();
            g.set_portable_status_ok(ok);
            g.set_portable_status(slint::SharedString(msg));
            push_toast(ctx.ui, msg, ok ? "success" : "error");
        });

        ws.on_import_portable_workspace([&ctx] {
            bool const en = is_en_ui(ctx.ui);
            auto in_path = ctx.cfg_dir / "workspace-export.json";
            std::error_code ec;
            bool const exists = std::filesystem::is_regular_file(in_path, ec);
            auto loaded_ws = exists ? desktop::load_workspace(in_path)
                                    : std::expected<desktop::WorkspaceDocument, std::string>(std::unexpected("missing"));
            auto const& g = ctx.ui.global<nexus_ui::WorkspaceState>();
            if (!loaded_ws) {
                auto msg = tr(en, "未找到可导入的工作区备份", "No valid portable workspace backup found");
                g.set_portable_status_ok(false);
                g.set_portable_status(slint::SharedString(msg));
                push_toast(ctx.ui, msg, "error");
                return;
            }
            ctx.doc = std::move(*loaded_ws);
            std::unordered_set<std::string> live;
            for (auto const& p : ctx.doc.profiles) live.insert(p.id);
            (void)desktop::prune_telemetry_entries(ctx.telemetry, live);
            if (ctx.telemetry.active_profile_id.empty() && !ctx.doc.profiles.empty()) {
                ctx.telemetry.active_profile_id = ctx.doc.profiles.front().id;
            }
            (void)persist_workspace_db(ctx);
            (void)persist_telemetry_db(ctx);
            sync_workspace_to_ui(ctx);
            if (ctx.sync_tray) ctx.sync_tray();
            auto msg = tr(en, "已导入便携工作区（本机设置与遥测保持隔离）", "Imported portable workspace (local settings & telemetry untouched)");
            g.set_portable_status_ok(true);
            g.set_portable_status(slint::SharedString(msg));
            push_toast(ctx.ui, msg, "success");
            recompose_active_workspace(ctx);
        });
    }
}
