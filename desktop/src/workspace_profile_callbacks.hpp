// Profile & server console UI callbacks: clipboard import, structured policy-group/proxy-chain/custom editors, rule-sets, and FullTemplate.
#pragma once

#include "workspace_profile_ops.hpp"

namespace desktop_ui_helpers {
    inline auto bind_profile_callbacks(WorkspaceUiContext& ctx) -> void {
        auto const& ws = ctx.ui.global<nexus_ui::WorkspaceState>();

        ws.on_set_sub_filter([&ctx](slint::SharedString sub) {
            ctx.ui.global<nexus_ui::WorkspaceState>().set_selected_sub_tab(sub);
            sync_workspace_to_ui(ctx);
        });
        ws.on_set_profile_search([&ctx](slint::SharedString q) {
            ctx.ui.global<nexus_ui::WorkspaceState>().set_profile_search(q);
            sync_workspace_to_ui(ctx);
        });
        ws.on_cycle_profile_sort([&ctx] {
            auto const& g = ctx.ui.global<nexus_ui::WorkspaceState>();
            std::string cur(g.get_profile_sort());
            g.set_profile_sort(slint::SharedString(cur == "default" ? "latency" : cur == "latency" ? "name" : "default"));
            sync_workspace_to_ui(ctx);
        });
        ws.on_request_new_profile([&ctx](slint::SharedString kind) { reset_editor_for_new_profile(ctx, std::string_view(kind)); });
        ws.on_request_edit_profile([&ctx](slint::SharedString id) { populate_editor_for_profile(ctx, std::string_view(id)); });

        ws.on_import_clipboard_uris([&ctx] {
            bool const en = is_en_ui(ctx.ui);
            auto clip = read_text_from_clipboard();
            auto sv = trim_ascii_ws(clip);
            if (sv.empty()) {
                push_toast(ctx.ui, tr(en, "剪贴板为空，或可直接在输入框粘贴链接回车", "Clipboard empty; or paste URI in input box"), "warn");
                return;
            }
            if (sv.starts_with("nexus://")) {
                import_share_bundle_async(ctx, std::string(sv));
                return;
            }
            if (sv.starts_with("https://") || sv.starts_with("http://")) {
                auto const& g = ctx.ui.global<nexus_ui::WorkspaceState>();
                g.invoke_add_subscription(slint::SharedString(""), slint::SharedString(sv), slint::SharedString(""), slint::SharedString(""));
                return;
            }
            auto lines = decode_subscription_lines(sv);
            std::unordered_set<std::string> ids;
            for (auto const& p : ctx.doc.profiles) ids.insert(p.id);
            std::string sub_id(ctx.ui.global<nexus_ui::WorkspaceState>().get_selected_sub_tab());
            if (sub_id.empty() || sub_id == "all") sub_id = "manual";
            std::size_t added = 0;
            std::string last_id;
            for (auto const& ln : lines) {
                auto built = build_workspace_profile_from_draft("node", "", ln, "", ids, ctx.doc.profiles.size());
                if (!built) continue;
                built->subscription_id = sub_id;
                ids.insert(built->id);
                last_id = built->id;
                ctx.doc.profiles.push_back(std::move(*built));
                ++added;
            }
            if (added == 0) {
                push_toast(ctx.ui, tr(en, "剪贴板未包含可识别的节点分享链接", "No valid share URIs found in clipboard"), "error");
                return;
            }
            ++ctx.doc.revision;
            ctx.telemetry.active_profile_id = last_id;
            (void)persist_workspace_db(ctx);
            (void)persist_telemetry_db(ctx);
            sync_workspace_to_ui(ctx);
            if (ctx.sync_tray) ctx.sync_tray();
            push_toast(ctx.ui, std::format("{} ({})", tr(en, "已从剪贴板批量导入节点", "Imported nodes from clipboard"), added), "success");
            recompose_active_workspace(ctx, last_id);
        });

        ws.on_save_group_profile([&ctx](nexus_ui::PolicyGroupDraft d) {
            bool const en = is_en_ui(ctx.ui);
            auto members = split_csv_trim(std::string_view(d.member_ids_csv));
            auto dyn_sub = std::string(trim_ascii_ws(std::string_view(d.dynamic_sub_id)));
            if (members.empty() && dyn_sub.empty()) {
                push_toast(ctx.ui, tr(en, "策略组需至少选择一个静态成员或绑定动态订阅", "Select at least one member or dynamic subscription"), "error");
                return;
            }
            std::string edit_id(trim_ascii_ws(std::string_view(d.edit_id)));
            std::string rem(trim_ascii_ws(std::string_view(d.remarks)));
            if (rem.empty()) rem = "Group-" + std::to_string(ctx.doc.profiles.size() + 1);
            desktop::PolicyGroupConfig pg{
                .strategy = std::string(trim_ascii_ws(std::string_view(d.strategy))),
                .member_ids = std::move(members),
                .dynamic_sub_id = std::move(dyn_sub),
                .include_regex = std::string(trim_ascii_ws(std::string_view(d.include_regex))),
                .exclude_regex = std::string(trim_ascii_ws(std::string_view(d.exclude_regex))),
                .probe_url = std::string(trim_ascii_ws(std::string_view(d.probe_url))),
                .probe_interval_ms = std::max<std::int64_t>(5000, parse_positive_i64_prefix(std::string_view(d.probe_interval_ms))),
                .tolerance_ms = std::max<std::int64_t>(0, parse_positive_i64_prefix(std::string_view(d.tolerance_ms))),
                .interrupt_exist_connections = d.interrupt_exist,
            };
            if (pg.probe_url.empty()) pg.probe_url = "https://www.gstatic.com/generate_204";
            std::string target_id = edit_id;
            if (!edit_id.empty()) {
                for (auto& p : ctx.doc.profiles) {
                    if (p.id == edit_id) { p.remarks = rem; p.kind = "policy_group"; p.policy_group = std::move(pg); break; }
                }
            } else {
                std::unordered_set<std::string> ids;
                for (auto const& p : ctx.doc.profiles) ids.insert(p.id);
                auto base = desktop::sanitize_workspace_id(rem);
                target_id = base;
                for (int n = 2; ids.contains(target_id); ++n) target_id = base + "-" + std::to_string(n);
                ctx.doc.profiles.push_back({.id = target_id, .remarks = rem, .subscription_id = "manual", .kind = "policy_group", .policy_group = std::move(pg)});
            }
            ++ctx.doc.revision;
            ctx.telemetry.active_profile_id = target_id;
            (void)persist_workspace_db(ctx);
            (void)persist_telemetry_db(ctx);
            sync_workspace_to_ui(ctx);
            ctx.ui.set_outbound_modal_open(false);
            push_toast(ctx.ui, tr(en, "策略组已保存: ", "Saved policy group: ") + rem, "success");
            recompose_active_workspace(ctx, target_id);
        });

        ws.on_save_chain_profile([&ctx](nexus_ui::ProxyChainDraft d) {
            bool const en = is_en_ui(ctx.ui);
            auto hops = split_csv_trim(std::string_view(d.hop_ids_csv));
            if (hops.size() < 2) {
                push_toast(ctx.ui, tr(en, "链式代理至少需要 2 个按序跳点", "Proxy chain requires at least 2 ordered hops"), "error");
                return;
            }
            std::string edit_id(trim_ascii_ws(std::string_view(d.edit_id)));
            std::string rem(trim_ascii_ws(std::string_view(d.remarks)));
            if (rem.empty()) rem = "Chain-" + std::to_string(ctx.doc.profiles.size() + 1);
            std::string target_id = edit_id;
            if (!edit_id.empty()) {
                for (auto& p : ctx.doc.profiles) {
                    if (p.id == edit_id) { p.remarks = rem; p.kind = "proxy_chain"; p.proxy_chain.hop_ids = std::move(hops); break; }
                }
            } else {
                std::unordered_set<std::string> ids;
                for (auto const& p : ctx.doc.profiles) ids.insert(p.id);
                auto base = desktop::sanitize_workspace_id(rem);
                target_id = base;
                for (int n = 2; ids.contains(target_id); ++n) target_id = base + "-" + std::to_string(n);
                ctx.doc.profiles.push_back({.id = target_id, .remarks = rem, .subscription_id = "manual", .kind = "proxy_chain", .proxy_chain = {std::move(hops)}});
            }
            ++ctx.doc.revision;
            ctx.telemetry.active_profile_id = target_id;
            (void)persist_workspace_db(ctx);
            (void)persist_telemetry_db(ctx);
            sync_workspace_to_ui(ctx);
            ctx.ui.set_outbound_modal_open(false);
            push_toast(ctx.ui, tr(en, "代理链已保存: ", "Saved proxy chain: ") + rem, "success");
            recompose_active_workspace(ctx, target_id);
        });

        ws.on_save_kdl_profile([&ctx](nexus_ui::CustomKdlDraft d) {
            bool const en = is_en_ui(ctx.ui);
            std::string raw_cfg(trim_ascii_ws(std::string_view(d.kdl_text)));
            if (raw_cfg.empty()) {
                push_toast(ctx.ui, tr(en, "请填写自定义配置内容", "Custom configuration content is required"), "error");
                return;
            }
            std::string kind = d.kind == "full_custom_kdl" ? "full_custom_kdl" : "custom_outbound";
            std::string edit_id(trim_ascii_ws(std::string_view(d.edit_id)));
            std::string rem(trim_ascii_ws(std::string_view(d.remarks)));
            if (rem.empty()) rem = "Custom-" + std::to_string(ctx.doc.profiles.size() + 1);
            std::string target_id = edit_id;
            if (!edit_id.empty()) {
                for (auto& p : ctx.doc.profiles) {
                    if (p.id == edit_id) {
                        p.remarks = rem; p.kind = kind;
                        if (kind == "custom_outbound") p.custom_outbound_kdl = raw_cfg; else p.full_custom_kdl = raw_cfg;
                        break;
                    }
                }
            } else {
                std::unordered_set<std::string> ids;
                for (auto const& p : ctx.doc.profiles) ids.insert(p.id);
                auto base = desktop::sanitize_workspace_id(rem);
                target_id = base;
                for (int n = 2; ids.contains(target_id); ++n) target_id = base + "-" + std::to_string(n);
                desktop::WorkspaceProfileItem item{.id = target_id, .remarks = rem, .subscription_id = "manual", .kind = kind};
                if (kind == "custom_outbound") item.custom_outbound_kdl = raw_cfg; else item.full_custom_kdl = raw_cfg;
                ctx.doc.profiles.push_back(std::move(item));
            }
            ++ctx.doc.revision;
            ctx.telemetry.active_profile_id = target_id;
            (void)persist_workspace_db(ctx);
            (void)persist_telemetry_db(ctx);
            sync_workspace_to_ui(ctx);
            ctx.ui.set_outbound_modal_open(false);
            push_toast(ctx.ui, tr(en, "自定义配置已保存: ", "Saved custom profile: ") + rem, "success");
            recompose_active_workspace(ctx, target_id);
        });

        ws.on_refresh_subscription([&ctx](slint::SharedString sub_id) {
            refresh_subscription_async(ctx, std::string(trim_ascii_ws(std::string_view(sub_id))));
        });

        ws.on_create_routing_preset([&ctx](slint::SharedString name_s) {
            std::string name(trim_ascii_ws(std::string_view(name_s)));
            if (name.empty()) return;
            for (auto& rp : ctx.doc.routing_profiles) rp.is_active = false;
            auto id = "rp-" + desktop::sanitize_workspace_id(name) + "-" + std::to_string(ctx.doc.routing_profiles.size() + 1);
            ctx.doc.routing_profiles.push_back({.id = id, .name = name, .is_active = true});
            ++ctx.doc.revision;
            (void)persist_workspace_db(ctx);
            sync_workspace_to_ui(ctx);
            recompose_active_workspace(ctx);
        });

        ws.on_apply_routing_strategy([&ctx](slint::SharedString dom_s, slint::SharedString def_s) {
            for (auto& rp : ctx.doc.routing_profiles) {
                if (!rp.is_active) continue;
                rp.domain_strategy = std::string(dom_s);
                rp.default_outbound = std::string(def_s);
                ++ctx.doc.revision;
                (void)persist_workspace_db(ctx);
                sync_workspace_to_ui(ctx);
                recompose_active_workspace(ctx);
                break;
            }
        });

        ws.on_toggle_routing_rule([&ctx](slint::SharedString rid_s, bool en_flag) {
            for (auto& rp : ctx.doc.routing_profiles) {
                if (!rp.is_active) continue;
                for (auto& r : rp.rules) {
                    if (r.id == std::string_view(rid_s) && !r.locked) { r.enabled = en_flag; break; }
                }
                ++ctx.doc.revision;
                (void)persist_workspace_db(ctx);
                sync_workspace_to_ui(ctx);
                recompose_active_workspace(ctx);
                break;
            }
        });

        ws.on_delete_routing_rule([&ctx](slint::SharedString rid_s) {
            for (auto& rp : ctx.doc.routing_profiles) {
                if (!rp.is_active) continue;
                std::erase_if(rp.rules, [&](auto const& r) { return r.id == std::string_view(rid_s) && !r.locked; });
                ++ctx.doc.revision;
                (void)persist_workspace_db(ctx);
                sync_workspace_to_ui(ctx);
                recompose_active_workspace(ctx);
                break;
            }
        });

        ws.on_add_rule_set([&ctx](slint::SharedString tag_s, slint::SharedString src_s, slint::SharedString fmt_s,
                                  slint::SharedString loc_s, slint::SharedString min_s) {
            std::string tag(trim_ascii_ws(std::string_view(tag_s)));
            std::string src(trim_ascii_ws(std::string_view(src_s)));
            std::string loc(trim_ascii_ws(std::string_view(loc_s)));
            if (tag.empty() || loc.empty()) return;
            std::erase_if(ctx.doc.rule_set_assets, [&](auto const& a) { return a.tag == tag; });
            desktop::RuleSetAsset rs{
                .tag = tag, .source_type = src == "local" ? "local" : "remote",
                .format = std::string(trim_ascii_ws(std::string_view(fmt_s))),
                .path = src == "local" ? loc : std::string{},
                .url = src == "local" ? std::string{} : loc,
                .update_interval_ms = parse_positive_i64_prefix(std::string_view(min_s)) * 60000LL,
            };
            ctx.doc.rule_set_assets.push_back(std::move(rs));
            ++ctx.doc.revision;
            (void)persist_workspace_db(ctx);
            sync_workspace_to_ui(ctx);
            recompose_active_workspace(ctx);
        });

        ws.on_delete_rule_set([&ctx](slint::SharedString tag_s) {
            std::erase_if(ctx.doc.rule_set_assets, [&](auto const& a) { return a.tag == std::string_view(tag_s); });
            ++ctx.doc.revision;
            (void)persist_workspace_db(ctx);
            sync_workspace_to_ui(ctx);
            recompose_active_workspace(ctx);
        });

        ws.on_apply_full_template([&ctx] {
            bool const en = is_en_ui(ctx.ui);
            auto const& g = ctx.ui.global<nexus_ui::WorkspaceState>();
            ctx.doc.full_template.enabled = g.get_tpl_enabled();
            ctx.doc.full_template.append_proxies_only = g.get_tpl_append_only();
            ctx.doc.full_template.proxy_detour = std::string(trim_ascii_ws(std::string_view(g.get_tpl_proxy_detour())));
            ctx.doc.full_template.template_kdl = std::string(g.get_tpl_kdl());
            ++ctx.doc.revision;
            (void)persist_workspace_db(ctx);
            sync_workspace_to_ui(ctx);
            push_toast(ctx.ui, tr(en, "已保存全局配置模板", "Saved FullTemplate"), "success");
            recompose_active_workspace(ctx);
        });
    }
}
