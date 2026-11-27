// Stages 1, 5, 6, 7: Unified 7-stage workspace compiler & strict JSON serializer.
module provider.workspace_compose;
import std;
import config;
import glaze;
import platform.ip_address;
import provider.types;
import rules.regex;
import :detail;

namespace provider {
    using namespace ws_detail;

    namespace {
        // Stage 1 recursive resolver with Fail-Closed ProxyChain validation & cycle detection.
        struct DagResolver {
            ComposeContext& ctx;
            std::map<std::string, std::string> resolved_tag;
            std::map<std::string, std::vector<std::string>> group_members_by_tag;

            auto expand_chain_hops(std::vector<std::string> const& hop_ids, std::set<std::string>& visiting,
                                   std::vector<WorkspaceProfile const*>& flat_hops) -> std::expected<void, std::string> {
                if (hop_ids.empty()) return std::unexpected("proxy_chain has no hops");
                for (auto const& hid : hop_ids) {
                    auto it = ctx.profile_by_id.find(hid);
                    if (it == ctx.profile_by_id.end())
                        return std::unexpected("proxy_chain hop not found: " + hid);
                    if (visiting.contains(hid))
                        return std::unexpected("proxy_chain cycle detected at: " + hid);
                    auto const* hp = it->second;
                    if (hp->kind == "full_custom_kdl")
                        return std::unexpected("proxy_chain cannot include full_custom_kdl hop: " + hid);
                    if (node_is_xhttp_vless(*hp))
                        return std::unexpected("proxy_chain cannot include vless+xhttp hop: " + hid);
                    if (hp->kind == "policy_group" && lower_ascii(hp->policy_group.strategy) != "selector")
                        return std::unexpected("proxy_chain hop '" + hid + "' cannot target non-selector policy_group (" + hp->policy_group.strategy + ")");
                    if (hp->kind == "proxy_chain") {
                        visiting.insert(hid);
                        if (auto ok = expand_chain_hops(hp->proxy_chain.hop_ids, visiting, flat_hops); !ok) return ok;
                        visiting.erase(hid);
                    } else {
                        flat_hops.push_back(hp);
                    }
                }
                return {};
            }

            auto emit_chain(std::string_view chain_label, std::vector<std::string> const& hop_ids,
                            std::set<std::string>& visiting, bool note_datagram) -> std::expected<std::string, std::string> {
                std::vector<WorkspaceProfile const*> hops;
                if (auto ok = expand_chain_hops(hop_ids, visiting, hops); !ok) return std::unexpected(ok.error());
                if (hops.empty()) return std::unexpected("proxy_chain resolved to zero hops");
                for (std::size_t i = 0; i < hops.size(); ++i)
                    for (std::size_t j = i + 1; j < hops.size(); ++j)
                        if (hops[i]->id == hops[j]->id)
                            return std::unexpected("proxy_chain contains duplicate/cyclic hop: " + hops[i]->id);
                // Hop[0] is the physical entry outbound (or a pure selector); hops[1..N-1] detour through previous hop.
                std::string prev_tag;
                for (std::size_t i = 0; i < hops.size(); ++i) {
                    auto const& hp = *hops[i];
                    if (i == 0) {
                        auto t = resolve_profile(hp.id, visiting, note_datagram);
                        if (!t) return std::unexpected("proxy_chain entry hop failed: " + t.error());
                        prev_tag = *t;
                    } else {
                        if (hp.kind == "policy_group")
                            return std::unexpected("proxy_chain policy_group hop '" + hp.id + "' is only valid as entry hop[0]");
                        auto hop_tag = ctx.alloc_tag(std::string(chain_label) + "-h" + std::to_string(i) + "-" +
                                                     (!hp.remarks.empty() ? hp.remarks : hp.id), "hop");
                        std::expected<std::string, std::string> kdl = (hp.kind == "custom_outbound")
                            ? emit_custom_outbound(ctx, hp.custom_outbound_kdl, hop_tag, prev_tag)
                            : emit_node_outbound(ctx, hp.node, hop_tag, prev_tag, note_datagram);
                        if (!kdl) return std::unexpected("proxy_chain hop '" + hp.id + "': " + kdl.error());
                        ctx.emitted_outbound_kdl.push_back(std::move(*kdl));
                        ctx.emitted_tags.insert(hop_tag);
                        ++ctx.physical_outbound_count;
                        prev_tag = hop_tag;
                    }
                }
                return prev_tag;
            }

            auto resolve_profile(std::string const& id, std::set<std::string>& visiting, bool note_datagram)
                -> std::expected<std::string, std::string> {
                if (auto it = resolved_tag.find(id); it != resolved_tag.end()) return it->second;
                auto pit = ctx.profile_by_id.find(id);
                if (pit == ctx.profile_by_id.end()) return std::unexpected("profile not found: " + id);
                if (!visiting.insert(id).second) return std::unexpected("profile dependency cycle detected at: " + id);
                auto const& p = *pit->second;
                auto done = [&](std::expected<std::string, std::string> r) {
                    visiting.erase(id);
                    if (r) resolved_tag.emplace(id, *r);
                    return r;
                };
                if (p.kind == "full_custom_kdl") return done(std::unexpected("full_custom_kdl cannot be referenced as a nested outbound: " + id));
                if (p.kind == "node") {
                    auto tag = ctx.tag_for_profile(p);
                    auto kdl = emit_node_outbound(ctx, p.node, tag, {}, note_datagram);
                    if (!kdl) return done(std::unexpected(kdl.error()));
                    ctx.emitted_outbound_kdl.push_back(std::move(*kdl));
                    ctx.emitted_tags.insert(tag);
                    ++ctx.physical_outbound_count;
                    return done(tag);
                }
                if (p.kind == "custom_outbound") {
                    auto tag = ctx.tag_for_profile(p);
                    auto kdl = emit_custom_outbound(ctx, p.custom_outbound_kdl, tag, {});
                    if (!kdl) return done(std::unexpected(kdl.error()));
                    ctx.emitted_outbound_kdl.push_back(std::move(*kdl));
                    ctx.emitted_tags.insert(tag);
                    ++ctx.physical_outbound_count;
                    return done(tag);
                }
                if (p.kind == "proxy_chain") {
                    auto label = !p.remarks.empty() ? p.remarks : p.id;
                    return done(emit_chain(label, p.proxy_chain.hop_ids, visiting, note_datagram));
                }
                if (p.kind == "policy_group") {
                    std::vector<std::string> candidate_ids;
                    std::set<std::string> seen_ids;
                    for (auto const& mid : p.policy_group.member_ids)
                        if (seen_ids.insert(mid).second) candidate_ids.push_back(mid);
                    if (!p.policy_group.dynamic_sub_id.empty()) {
                        std::vector<rules::BoundedRegex> inc, exc;
                        if (!p.policy_group.include_regex.empty()) {
                            auto r = compile_filter_regex(p.policy_group.include_regex);
                            if (!r) return done(std::unexpected("invalid policy_group include_regex on " + id));
                            inc = std::move(*r);
                        }
                        if (!p.policy_group.exclude_regex.empty()) {
                            auto r = compile_filter_regex(p.policy_group.exclude_regex);
                            if (!r) return done(std::unexpected("invalid policy_group exclude_regex on " + id));
                            exc = std::move(*r);
                        }
                        for (auto const& cand : ctx.ws.profiles) {
                            if (cand.subscription_id != p.policy_group.dynamic_sub_id || cand.id == p.id || cand.kind == "full_custom_kdl")
                                continue;
                            auto hay = !cand.remarks.empty() ? cand.remarks : cand.id;
                            if (!inc.empty() && !std::ranges::any_of(inc, [&](auto const& re) { return re.search(hay); })) continue;
                            if (!exc.empty() && std::ranges::any_of(exc, [&](auto const& re) { return re.search(hay); })) continue;
                            if (seen_ids.insert(cand.id).second) candidate_ids.push_back(cand.id);
                        }
                    }
                    std::vector<std::string> member_tags;
                    for (auto const& mid : candidate_ids) {
                        if (visiting.contains(mid)) return done(std::unexpected("policy_group cycle detected at: " + mid));
                        auto mt = resolve_profile_isolated(mid, visiting, note_datagram);
                        if (!mt) { ctx.warnings.push_back("policy_group '" + id + "' skipped member '" + mid + "': " + mt.error()); continue; }
                        if (!std::ranges::contains(member_tags, *mt)) member_tags.push_back(*mt);
                    }
                    if (member_tags.empty()) return done(std::unexpected("policy_group '" + id + "' resolved to zero valid members"));
                    auto tag = ctx.tag_for_profile(p);
                    ctx.emitted_outbound_kdl.push_back(emit_policy_group_outbound(ctx, p, tag, member_tags));
                    ctx.emitted_tags.insert(tag);
                    group_members_by_tag.emplace(tag, std::move(member_tags));
                    return done(tag);
                }
                return done(std::unexpected("unsupported profile kind '" + p.kind + "' on " + id));
            }

            auto resolve_profile_isolated(std::string const& id, std::set<std::string>& visiting, bool note_datagram)
                -> std::expected<std::string, std::string> {
                auto cp = ctx.checkpoint();
                auto saved_used = ctx.used_tags;
                auto saved_base = ctx.base_tag_for_id;
                auto saved_emitted = ctx.emitted_tags;
                auto saved_resolved = resolved_tag;
                auto saved_groups = group_members_by_tag;
                auto r = resolve_profile(id, visiting, note_datagram);
                if (!r) {
                    ctx.rollback_to(cp);
                    ctx.used_tags = std::move(saved_used);
                    ctx.base_tag_for_id = std::move(saved_base);
                    ctx.emitted_tags = std::move(saved_emitted);
                    resolved_tag = std::move(saved_resolved);
                    group_members_by_tag = std::move(saved_groups);
                }
                return r;
            }
        };
    }

    auto compose_workspace(std::string_view workspace_json, std::string_view host_json,
                           WorkspaceComposeOptions const& opts) -> WorkspaceComposeResult {
        WorkspaceComposeResult res{};
        constexpr std::size_t max_input_json_bytes = 8u * 1024u * 1024u;
        if (workspace_json.size() > max_input_json_bytes) { res.errors.push_back("workspace.json exceeds 8 MiB limit"); return res; }
        if (host_json.size() > max_input_json_bytes) { res.errors.push_back("host.json exceeds 8 MiB limit"); return res; }
        Workspace ws{};
        HostConfig host{};
        if (auto err = glaze::read<glaze::opts{.error_on_unknown_keys = false}>(ws, workspace_json)) {
            res.errors.push_back("invalid workspace.json: " + format_json_error(static_cast<std::uint32_t>(err.ec), err.count, err.custom_error_message, workspace_json));
            return res;
        }
        if (auto err = glaze::read<glaze::opts{.error_on_unknown_keys = false}>(host, host_json)) {
            res.errors.push_back("invalid host.json: " + format_json_error(static_cast<std::uint32_t>(err.ec), err.count, err.custom_error_message, host_json));
            return res;
        }
        if (ws.schema_version != 1) { res.errors.push_back("unsupported workspace schema_version"); return res; }
        if (host.schema_version != 1) { res.errors.push_back("unsupported host schema_version"); return res; }
        if (!host.workers_spec.empty() && !config::validate_workers_spec(host.workers_spec)) {
            res.errors.push_back("invalid host workers_spec: " + host.workers_spec);
            return res;
        }
        if (ws.profiles.empty()) { res.errors.push_back("workspace contains no profiles"); return res; }

        ComposeContext ctx{ws, host, opts};
        ctx.resolved_ca_file = !host.ca_file.empty() ? host.ca_file : system_ca_path();
        for (auto const& p : ws.profiles) if (!p.id.empty()) ctx.profile_by_id.emplace(p.id, &p);
        for (auto const& s : ws.subscriptions) if (!s.id.empty()) ctx.sub_by_id.emplace(s.id, &s);
        for (auto const& a : ws.rule_set_assets) if (!a.tag.empty()) ctx.asset_by_tag.emplace(a.tag, &a);

        std::string active_id = opts.active_profile_id.empty() ? ws.profiles.front().id : opts.active_profile_id;
        auto active_it = ctx.profile_by_id.find(active_id);
        if (active_it == ctx.profile_by_id.end()) {
            res.errors.push_back("active profile not found: " + active_id);
            return res;
        }
        auto const& active = *active_it->second;

        auto fail = [&](std::string msg) {
            ctx.rollback_secrets();
            res.warnings = std::move(ctx.warnings);
            res.errors.push_back(std::move(msg));
            return res;
        };

        std::string final_kdl;
        if (active.kind == "full_custom_kdl") {
            auto overridden = compose_full_custom_kdl(ctx, active);
            if (!overridden) return fail(overridden.error());
            final_kdl = std::move(*overridden);
            res.active_tag = ctx.tag_for_profile(active);
        } else {
            DagResolver dag{ctx};
            std::set<std::string> visiting;
            // Check subscription prev/next chaining for active profile ONLY
            std::vector<std::string> sub_chain;
            if (!active.subscription_id.empty()) {
                if (auto sit = ctx.sub_by_id.find(active.subscription_id); sit != ctx.sub_by_id.end()) {
                    auto const& sub = *sit->second;
                    if (!sub.prev_profile_id.empty() || !sub.next_profile_id.empty()) {
                        if (!sub.prev_profile_id.empty()) sub_chain.push_back(sub.prev_profile_id);
                        sub_chain.push_back(active.id);
                        if (!sub.next_profile_id.empty()) sub_chain.push_back(sub.next_profile_id);
                    }
                }
            }

            std::expected<std::string, std::string> entry = sub_chain.empty()
                ? dag.resolve_profile(active.id, visiting, true)
                : dag.emit_chain("subchain", sub_chain, visiting, true);
            if (!entry) return fail(entry.error());
            res.active_tag = *entry;

            // Sibling selector population (up to min(max_selector_members, max_tunnel_outbounds))
            std::vector<std::string> proxy_members{*entry};
            if (host.include_sibling_nodes_in_selector && sub_chain.empty() && active.kind == "node") {
                std::size_t cap = std::min<std::size_t>(host.max_selector_members ? host.max_selector_members : 128, config::max_tunnel_outbounds);
                auto add_siblings = [&](bool same_sub) {
                    for (auto const& cand : ws.profiles) {
                        if (proxy_members.size() >= cap || ctx.physical_outbound_count >= config::max_tunnel_outbounds) break;
                        if (cand.id == active.id || cand.kind != "node") continue;
                        if ((cand.subscription_id == active.subscription_id) != same_sub) continue;
                        std::set<std::string> sv;
                        auto st = dag.resolve_profile_isolated(cand.id, sv, true);
                        if (!st) { ctx.warnings.push_back("skipped sibling node '" + cand.id + "': " + st.error()); continue; }
                        if (!std::ranges::contains(proxy_members, *st)) proxy_members.push_back(*st);
                    }
                };
                add_siblings(true);
                add_siblings(false);
            }

            if (active.kind == "policy_group" && lower_ascii(active.policy_group.strategy) == "selector" && sub_chain.empty()) {
                res.selector_tag = *entry;
                if (auto it = dag.group_members_by_tag.find(*entry); it != dag.group_members_by_tag.end())
                    res.selector_members = it->second;
            } else {
                res.selector_tag = "proxy";
                res.selector_members = proxy_members;
            }

            // Pick active routing profile and fault-isolated resolve any target_type == "profile_id"
            WorkspaceRoutingProfile default_rp{};
            WorkspaceRoutingProfile const* active_rp = &default_rp;
            for (auto const& rp : ws.routing_profiles) if (rp.is_active) { active_rp = &rp; break; }
            if (active_rp == &default_rp && !ws.routing_profiles.empty()) active_rp = &ws.routing_profiles.front();

            bool is_desktop = host.platform.starts_with("desktop-");
            bool is_android = (host.platform == "android");
            auto rule_has_platform_preds = [&](WorkspaceRoutingRule const& r) {
                auto sc = lower_ascii(r.scope);
                if (sc != "both" && sc != "routing_only") return false;
                if (!r.domains.empty() || !r.ips.empty() || !r.rule_sets.empty() ||
                    !r.ports.empty() || !r.networks.empty() || !r.protocols.empty()) return true;
                if (is_desktop && !r.desktop_process.empty()) return true;
                if (is_android && !r.android_packages.empty()) return true;
                return false;
            };
            std::map<std::string, std::string> rule_profile_tags;
            for (auto const& r : active_rp->rules) {
                if (!r.enabled || !rule_has_platform_preds(r) || lower_ascii(r.target_type) != "profile_id" || r.target_profile_id.empty()) continue;
                if (rule_profile_tags.contains(r.target_profile_id)) continue;
                std::set<std::string> rv;
                auto rt = dag.resolve_profile_isolated(r.target_profile_id, rv, false);
                if (!rt) ctx.warnings.push_back("routing rule target profile '" + r.target_profile_id + "' fallback to proxy: " + rt.error());
                else rule_profile_tags.emplace(r.target_profile_id, *rt);
            }

            // Emit routing & DNS (also determines ctx.fake_ip_active for TUN!)
            std::ostringstream routing_os, dns_os, http_clients_os;
            if (auto ok = emit_routing_and_dns(ctx, *active_rp, rule_profile_tags, routing_os, dns_os, http_clients_os); !ok)
                return fail(ok.error());

            std::ostringstream full;
            emit_host_header(ctx, full);
            if (auto ok = emit_host_inbounds(ctx, full); !ok) return fail(ok.error());
            full << "outbounds {\n";
            if (active_rp->auto_detect_interface) full << "  auto-detect-interface #true\n";
            emit_direct_and_block(ctx, full);
            for (auto const& ob : ctx.emitted_outbound_kdl) full << ob;
            full << "  outbound \"proxy\" type=\"selector\" {\n";
            for (auto const& m : proxy_members) full << "    member " << kdl_quote(m) << '\n';
            full << "    selected " << kdl_quote(*entry) << "\n  }\n";
            full << "}\n";
            full << dns_os.str() << http_clients_os.str() << routing_os.str();
            final_kdl = full.str();

            if (ws.full_template.enabled && !trim(ws.full_template.template_kdl).empty()) {
                auto overlaid = apply_full_template(ws.full_template, final_kdl);
                if (!overlaid) return fail(overlaid.error());
                final_kdl = std::move(*overlaid);
            }
        }

        // Stage 7: Mandatory full in-memory validation via Core parser
        auto validated = config::parse_kdl(final_kdl);
        if (!validated) return fail("KDL validation failed: " + validated.error());

        res.ok = true;
        res.warnings = std::move(ctx.warnings);
        res.secret_files = std::move(ctx.secret_files);
        res.kdl = std::move(final_kdl);
        return res;
    }

    auto serialize_compose_result_json(WorkspaceComposeResult const& r) -> std::string {
        auto write_arr = [](std::string& out, std::vector<std::string> const& items) {
            out.push_back('[');
            for (std::size_t i = 0; i < items.size(); ++i) {
                if (i) out.push_back(',');
                out += json_quote(items[i]);
            }
            out.push_back(']');
        };
        std::string out = "{\"ok\":";
        out += r.ok ? "true" : "false";
        out += ",\"active_tag\":"; out += json_quote(r.active_tag);
        out += ",\"selector_tag\":"; out += json_quote(r.selector_tag);
        out += ",\"selector_members\":"; write_arr(out, r.selector_members);
        out += ",\"warnings\":"; write_arr(out, r.warnings);
        out += ",\"errors\":"; write_arr(out, r.errors);
        out += ",\"secret_files\":"; write_arr(out, r.secret_files);
        out += ",\"kdl\":"; out += json_quote(r.kdl);
        out += "}\n";
        return out;
    }
}
