// 4-Layer Workspace UI callbacks, structured modal builders, and portable backup for desktop/src/main.cpp.
#pragma once

#include "workspace_ui_sync.hpp"
#include "workspace_sync_flow.hpp"
#include "workspace_modal_callbacks.hpp"
#include "workspace_profile_callbacks.hpp"

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
        bind_profile_callbacks(ctx);
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
                    auto msg = ok ? tr(en, "已热切换活动服务器（免重启提权）", "Switched active server live (zero restart)")
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
            if (trim_ascii_ws(std::string_view(payload_s)).starts_with("nexus://")) {
                import_share_bundle_async(ctx, std::string(trim_ascii_ws(std::string_view(payload_s))));
                return;
            }
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
            std::string sub_tab(g.get_selected_sub_tab());
            if (!sub_tab.empty() && sub_tab != "all") built->subscription_id = sub_tab;
            if (built->kind == "policy_group") {
                built->policy_group.interrupt_exist_connections = g.get_draft_group_interrupt();
                g.set_draft_group_interrupt(false);
            }
            std::string label = built->remarks;
            std::string new_id = built->id;
            ctx.doc.profiles.push_back(std::move(*built));
            ++ctx.doc.revision;
            ctx.telemetry.active_profile_id = new_id;
            (void)persist_workspace_db(ctx);
            (void)persist_telemetry_db(ctx);
            sync_workspace_to_ui(ctx);
            if (ctx.sync_tray) ctx.sync_tray();
            push_toast(ctx.ui, tr(en, "已添加到配置文件列表: ", "Added profile: ") + label, "success");
            recompose_active_workspace(ctx, new_id);
        });

        ws.on_delete_profile([&ctx](slint::SharedString id_s) {
            bool const en = is_en_ui(ctx.ui);
            std::string const id(id_s);
            bool const was_active = (id == ctx.telemetry.active_profile_id);
            std::erase_if(ctx.doc.profiles, [&](auto const& p) { return p.id == id; });
            std::unordered_set<std::string> live;
            for (auto const& p : ctx.doc.profiles) live.insert(p.id);
            (void)desktop::prune_telemetry_entries(ctx.telemetry, live);
            (void)ensure_default_workspace_profile(ctx.doc, ctx.telemetry);
            if ((was_active || ctx.telemetry.active_profile_id.empty()) && !ctx.doc.profiles.empty()) {
                ctx.telemetry.active_profile_id = ctx.doc.profiles.front().id;
            }
            ++ctx.doc.revision;
            (void)persist_workspace_db(ctx);
            (void)persist_telemetry_db(ctx);
            sync_workspace_to_ui(ctx);
            if (ctx.sync_tray) ctx.sync_tray();
            if (was_active) {
                push_toast(ctx.ui, tr(en, "已删除原活动配置并自动切换至下一配置项", "Deleted active profile; switched to next profile"), "info");
                recompose_active_workspace(ctx);
            }
        });

        ws.on_add_subscription([&ctx](slint::SharedString rem_s, slint::SharedString url_s, slint::SharedString prev_s, slint::SharedString next_s) {
            bool const en = is_en_ui(ctx.ui);
            auto const& g = ctx.ui.global<nexus_ui::WorkspaceState>();
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
            sub.auto_update_minutes = parse_positive_i64_prefix(std::string_view(g.get_sub_auto_min()));
            sub.include_regex = std::string(trim_ascii_ws(std::string_view(g.get_sub_include_regex())));
            sub.exclude_regex = std::string(trim_ascii_ws(std::string_view(g.get_sub_exclude_regex())));
            sub.prev_profile_id = std::string(trim_ascii_ws(std::string_view(prev_s)));
            sub.next_profile_id = std::string(trim_ascii_ws(std::string_view(next_s)));
            std::string new_sub_id = sub.id;
            ctx.doc.subscriptions.push_back(std::move(sub));
            ++ctx.doc.revision;
            (void)persist_workspace_db(ctx);
            sync_workspace_to_ui(ctx);
            push_toast(ctx.ui, tr(en, "已保存订阅分组: ", "Saved subscription group: ") + rem, "success");
            if (!url.empty()) refresh_subscription_async(ctx, new_sub_id);
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
                push_toast(ctx.ui, tr(en, "请至少填写一个域名、CIDR、@规则集或进程名", "Provide domain, CIDR, @ruleset, or process name"), "error");
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
                    if (tok.starts_with('@') && tok.size() > 1) r.rule_sets.push_back(tok.substr(1));
                    else if (is_ip_or_cidr_rule_token(tok)) r.ips.push_back(tok);
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
            auto const& g = ctx.ui.global<nexus_ui::WorkspaceState>();
            ctx.doc.dns.mode = std::string(mode);
            ctx.doc.dns.simple.bootstrap_dns = std::string(trim_ascii_ws(std::string_view(g.get_dns_bootstrap())));
            if (auto v = split_csv_trim(std::string_view(dir_s)); !v.empty()) ctx.doc.dns.simple.direct_dns = std::move(v);
            if (auto v = split_csv_trim(std::string_view(rem_s)); !v.empty()) ctx.doc.dns.simple.remote_dns = std::move(v);
            ctx.doc.dns.simple.strategy = std::string(g.get_dns_strategy());
            ctx.doc.dns.simple.parallel_query = g.get_dns_parallel();
            ctx.doc.dns.simple.fake_ip_enabled = fakeip;
            if (auto v4 = trim_ascii_ws(std::string_view(g.get_dns_fakeip_v4())); !v4.empty()) ctx.doc.dns.simple.fake_ip_v4_pool = std::string(v4);
            if (auto v6 = trim_ascii_ws(std::string_view(g.get_dns_fakeip_v6())); !v6.empty()) ctx.doc.dns.simple.fake_ip_v6_pool = std::string(v6);
            ctx.doc.dns.simple.fake_ip_global = g.get_dns_fakeip_global();
            ctx.doc.dns.simple.block_aaaa = g.get_dns_block_aaaa();
            ctx.doc.dns.simple.block_svcb_https = g.get_dns_block_svcb();
            ctx.doc.dns.simple.use_system_hosts = g.get_dns_use_system_hosts();
            ctx.doc.dns.simple.hosts = parse_hosts_csv(std::string_view(g.get_dns_hosts_text()));
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
            ctx.host.mixed_listen = std::string(trim_ascii_ws(std::string_view(g.get_host_mixed_listen())));
            if (ctx.host.mixed_listen.empty()) ctx.host.mixed_listen = "127.0.0.1:7890";
            ctx.host.enable_socks = g.get_host_enable_socks();
            ctx.host.socks_listen = std::string(trim_ascii_ws(std::string_view(g.get_host_socks_listen())));
            if (ctx.host.socks_listen.empty()) ctx.host.socks_listen = "127.0.0.1:10808";
            ctx.host.second_local_listen.clear();
            ctx.host.enable_http = g.get_host_enable_http();
            ctx.host.http_listen = std::string(trim_ascii_ws(std::string_view(g.get_host_http_listen())));
            if (ctx.host.http_listen.empty()) ctx.host.http_listen = "127.0.0.1:10809";
            ctx.host.allow_lan = g.get_host_allow_lan();
            ctx.host.lan_listen = std::string(trim_ascii_ws(std::string_view(g.get_host_lan_listen())));
            ctx.host.lan_username = std::string(trim_ascii_ws(std::string_view(g.get_host_lan_user())));
            ctx.host.lan_password = std::string(g.get_host_lan_pass());
            ctx.host.enable_tun = g.get_host_enable_tun();
            if (auto tn = trim_ascii_ws(std::string_view(g.get_host_tun_name())); !tn.empty()) ctx.host.tun_interface_name = std::string(tn);
            ctx.host.tun_inet4 = std::string(trim_ascii_ws(std::string_view(g.get_host_tun_inet4())));
            ctx.host.tun_inet6 = std::string(trim_ascii_ws(std::string_view(g.get_host_tun_inet6())));
            ctx.host.tun_auto_route = g.get_host_tun_auto_route();
            ctx.host.tun_strict_route = g.get_host_tun_strict_route();
            ctx.host.tun_route_exclude_private = g.get_host_tun_exclude_private();
            ctx.host.tun_route_exclude = split_csv_trim(std::string_view(g.get_host_tun_exclude_cidr()));
            ctx.host.bind_interface = std::string(trim_ascii_ws(std::string_view(g.get_host_bind_iface())));
            ctx.host.inet4_bind_address = std::string(trim_ascii_ws(std::string_view(g.get_host_bind_inet4())));
            ctx.host.inet6_bind_address = std::string(trim_ascii_ws(std::string_view(g.get_host_bind_inet6())));
            ctx.host.include_sibling_nodes_in_selector = g.get_host_include_siblings();
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
            if (!has_any_enabled_inbound(ctx.host)) {
                ctx.host.enable_mixed = true;
                if (ctx.host.mixed_listen.empty()) ctx.host.mixed_listen = "127.0.0.1:7890";
                push_toast(ctx.ui, tr(en, "未启用任何入站协议，已自动保留 Mixed 本地监听", "No inbound selected; kept Mixed inbound enabled"), "warn");
            }
            auto notices = persist_workspace_and_host(ctx, en);
            sync_workspace_to_ui(ctx);
            g.set_host_strict_route_notice(slint::SharedString(notices.empty() ? "" : notices.front()));
            if (!notices.empty()) push_toast(ctx.ui, notices.front(), "warn");
            if (!ctx.doc.profiles.empty()) recompose_active_workspace(ctx);
            else if (notices.empty()) push_toast(ctx.ui, tr(en, "已保存本机入站与核心参数", "Saved local settings"), "success");
            sync_system_proxy_with_inbounds(ctx, en);
            if (ctx.sync_tray) ctx.sync_tray();
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
