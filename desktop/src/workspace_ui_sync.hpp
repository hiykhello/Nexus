// Workspace UI state synchronization, server table filtering, Core composer commit, and Core start hook.
#pragma once

#include "workspace_ui_helpers.hpp"

namespace desktop_ui_helpers {
    struct WorkspaceUiContext {
        nexus_ui::AppWindow& ui;
        slint::ComponentWeakHandle<nexus_ui::AppWindow> weak_ui;
        desktop::AsyncWorker& worker;
        desktop::CoreSupervisor& supervisor;
        desktop::HttpControlClient& http_ctrl;
        RateTracker& rate_tracker;
        std::optional<std::chrono::steady_clock::time_point>& core_started_at;
        std::atomic<bool>& lifecycle_busy;
        std::filesystem::path const& cfg_dir;
        std::filesystem::path const& config_path;
        std::function<void()>& sync_tray;
        desktop::ClientDatabase* db = nullptr;

        std::filesystem::path workspace_path;
        std::filesystem::path host_path;
        std::filesystem::path secrets_dir;

        desktop::WorkspaceDocument doc;
        desktop::DesktopHostConfig host;
        desktop::TelemetryStoreData telemetry;
        std::string running_selector_tag = "proxy";
        std::vector<std::string> running_selector_members;
        std::vector<std::string> last_secret_files;
        desktop::SystemProxyController* sys_proxy = nullptr;
    };

    inline auto has_any_enabled_inbound(desktop::DesktopHostConfig const& h) noexcept -> bool {
        bool const linux_strict = (h.platform == "desktop-linux") && h.enable_tun && h.tun_strict_route;
        if (h.enable_tun) return true;
        if (linux_strict) return false;
        return (h.enable_mixed && !h.mixed_listen.empty())
            || (h.enable_http && !h.http_listen.empty())
            || (h.enable_socks && !h.socks_listen.empty())
            || !h.second_local_listen.empty()
            || !h.lan_listen.empty();
    }

    inline auto select_active_inbound_tag(desktop::DesktopHostConfig const& h, std::string_view preferred = {}) -> std::string {
        if (!preferred.empty() && preferred != "local-mixed") {
            if (preferred == "mixed-in" && h.enable_mixed) return "mixed-in";
            if (preferred == "http-in" && h.enable_http) return "http-in";
            if (preferred == "socks-in" && (h.enable_socks || !h.second_local_listen.empty())) return "socks-in";
            if (preferred == "tun-in" && h.enable_tun) return "tun-in";
            if (preferred != "mixed-in" && preferred != "http-in" && preferred != "socks-in" && preferred != "tun-in")
                return std::string(preferred);
        }
        if (h.enable_mixed) return "mixed-in";
        if (h.enable_http) return "http-in";
        if (h.enable_socks || !h.second_local_listen.empty()) return "socks-in";
        if (!h.lan_listen.empty()) return "lan-in";
        if (h.enable_tun) return "tun-in";
        return "mixed-in";
    }

    inline auto persist_workspace_db(WorkspaceUiContext& ctx) -> bool {
        if (ctx.db) return ctx.db->save_workspace(ctx.doc).has_value();
        return desktop::save_workspace_atomic(ctx.workspace_path, ctx.doc);
    }

    inline auto persist_host_db(WorkspaceUiContext& ctx) -> bool {
        if (ctx.db) return desktop::save_host_config_to_db(*ctx.db, ctx.secrets_dir, ctx.host);
        if (!desktop::save_sync_secrets(ctx.secrets_dir, {ctx.host.webdav_password, ctx.host.sync_passphrase, ctx.host.lan_password})) {
            return false;
        }
        desktop::DesktopHostConfig stripped = ctx.host;
        stripped.webdav_password.clear();
        stripped.sync_passphrase.clear();
        stripped.lan_password.clear();
        return desktop::save_desktop_host_config(ctx.host_path, stripped);
    }

    inline auto persist_telemetry_db(WorkspaceUiContext& ctx) -> bool {
        if (ctx.db) return ctx.db->save_telemetry(ctx.telemetry).has_value();
        return true;
    }

    struct ScopedTempJson {
        std::filesystem::path path;
        bool ok = false;
        ScopedTempJson() = default;
        ScopedTempJson(ScopedTempJson const&) = delete;
        auto operator=(ScopedTempJson const&) -> ScopedTempJson& = delete;
        ScopedTempJson(ScopedTempJson&& o) noexcept : path(std::move(o.path)), ok(o.ok) { o.path.clear(); o.ok = false; }
        auto operator=(ScopedTempJson&& o) noexcept -> ScopedTempJson& {
            if (this != &o) { wipe_and_remove(); path = std::move(o.path); ok = o.ok; o.path.clear(); o.ok = false; }
            return *this;
        }
        ~ScopedTempJson() { wipe_and_remove(); }
        auto wipe_and_remove() noexcept -> void {
            if (path.empty()) return;
            std::error_code ec;
            auto st = std::filesystem::symlink_status(path, ec);
            if (!ec && std::filesystem::is_regular_file(st) && !std::filesystem::is_symlink(st)) {
                auto sz = std::filesystem::file_size(path, ec);
                if (!ec && sz > 0 && sz <= 16ULL * 1024ULL * 1024ULL) {
                    std::ofstream out(path, std::ios::binary | std::ios::in | std::ios::out);
                    if (out) {
                        std::string zeros(static_cast<std::size_t>(std::min<std::uintmax_t>(sz, 4096)), '\0');
                        std::uintmax_t rem = sz;
                        while (rem > 0) {
                            auto chunk = static_cast<std::streamsize>(std::min<std::uintmax_t>(rem, zeros.size()));
                            out.write(zeros.data(), chunk);
                            rem -= static_cast<std::uintmax_t>(chunk);
                        }
                        out.flush();
                    }
                }
            }
            std::filesystem::remove(path, ec);
            path.clear();
        }
    };

    inline auto next_temp_compose_path(std::filesystem::path const& cfg_dir, std::string_view prefix) -> std::filesystem::path {
        static std::atomic<std::uint64_t> seq{0};
        auto const dir = cfg_dir / "runtime";
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
#ifndef _WIN32
        (void)::chmod(dir.c_str(), 0700);
        auto const pid = static_cast<std::uint64_t>(::getpid());
#else
        auto const pid = static_cast<std::uint64_t>(::GetCurrentProcessId());
#endif
        std::random_device rd;
        std::uint64_t const rnd = (static_cast<std::uint64_t>(rd()) << 32) ^ static_cast<std::uint64_t>(rd());
        return dir / std::format("{}-{}-{:016x}-{}.json", prefix, pid, rnd, seq.fetch_add(1, std::memory_order_relaxed));
    }

    inline auto make_temp_compose_workspace(std::filesystem::path const& cfg_dir, desktop::WorkspaceDocument const& doc) -> ScopedTempJson {
        ScopedTempJson f{};
        f.path = next_temp_compose_path(cfg_dir, "compose-ws");
        f.ok = desktop::save_workspace_atomic(f.path, doc);
        return f;
    }

    inline auto make_temp_compose_host(std::filesystem::path const& cfg_dir, desktop::DesktopHostConfig const& host) -> ScopedTempJson {
        desktop::DesktopHostConfig core_host = host;
        core_host.webdav_password.clear();
        core_host.sync_passphrase.clear();
        if (!core_host.enable_mixed && !core_host.enable_tun && (core_host.enable_http || core_host.enable_socks)) {
            core_host.enable_mixed = true;
            if (core_host.mixed_listen.empty()) core_host.mixed_listen = "127.0.0.1:7890";
        }
        ScopedTempJson f{};
        f.path = next_temp_compose_path(cfg_dir, "compose-host");
        f.ok = desktop::save_desktop_host_config(f.path, core_host);
        return f;
    }

    inline auto format_quota_human(std::int64_t used, std::int64_t total) -> std::string {
        if (total <= 0) return used > 0 ? format_bytes_human(static_cast<std::uint64_t>(used)) : std::string{};
        return format_bytes_human(static_cast<std::uint64_t>(std::max<std::int64_t>(0, used))) + " / " +
               format_bytes_human(static_cast<std::uint64_t>(total));
    }

    inline auto upper_proto_badge(desktop::WorkspaceProfileItem const& p) -> std::string {
        if (p.kind == "policy_group") return "GROUP";
        if (p.kind == "proxy_chain") return "CHAIN";
        if (p.kind == "custom_outbound") return "OUT";
        if (p.kind == "full_custom_kdl") return "RAW";
        auto pr = p.node.protocol;
        if (pr == "hysteria2") return "HY2";
        if (pr == "shadowsocks") return "SS";
        if (pr == "wireguard") return "WG";
        for (char& c : pr) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        return pr.empty() ? "NODE" : pr;
    }

    inline auto build_transport_summary(desktop::WorkspaceProfileItem const& p) -> std::string {
        if (p.kind == "policy_group") {
            std::string s = p.policy_group.strategy;
            if (!p.policy_group.dynamic_sub_id.empty()) s += " · regex";
            if (p.policy_group.interrupt_exist_connections) s += " · cut";
            return s;
        }
        if (p.kind == "proxy_chain") return join_csv(p.proxy_chain.hop_ids);
        if (p.kind != "node") return "custom";
        auto const& n = p.node;
        if (n.protocol == "wireguard") return std::format("wg · mtu {}", n.extra.wg_mtu > 0 ? n.extra.wg_mtu : 1420);
        if (n.protocol == "masque") return "h3 · " + (n.extra.masque_mode.empty() ? "connect-udp" : n.extra.masque_mode);
        if (n.protocol == "hysteria2") {
            std::string s = "quic+tls";
            if (!n.extra.hy2_ports.empty()) s += " · hop:" + n.extra.hy2_ports;
            if (!n.extra.hy2_salamander_password.empty()) s += " · obfs";
            return s;
        }
        if (n.protocol == "tuic") {
            return "quic+tls · " + (n.extra.tuic_congestion_control.empty() ? "bbr" : n.extra.tuic_congestion_control);
        }
        if (n.protocol == "ssh") return "ssh";
        if (n.protocol == "naive") return (n.extra.naive_protocol.empty() ? "h2" : n.extra.naive_protocol) + std::string("+tls");
        if (n.protocol == "shadowsocks") {
            std::string s = n.method.empty() ? "aead" : n.method;
            if (n.multiplex.enabled) s += "+mux";
            return s;
        }
        if (n.protocol == "snell") {
            std::string s = std::format("v{}", n.extra.snell_version > 0 ? n.extra.snell_version : 4);
            if (!n.extra.snell_obfs.empty() && n.extra.snell_obfs != "none") s += "+" + n.extra.snell_obfs;
            return s;
        }
        std::string s = n.transport.type.empty() ? "tcp" : n.transport.type;
        if (!n.tls.reality_public_key.empty()) s += "+reality";
        else if (n.tls.enabled) s += "+tls";
        if (!n.flow.empty()) s += "+vision";
        if (n.multiplex.enabled) s += "+mux";
        if (n.tls.fragment || n.tls.record_fragment) s += "+frag";
        return s;
    }

    inline auto sync_workspace_to_ui(WorkspaceUiContext& ctx) -> void {
        auto const& ws = ctx.ui.global<nexus_ui::WorkspaceState>();
        std::unordered_map<std::string, std::string> sub_names;
        std::unordered_map<std::string, int> sub_counts;
        for (auto const& s : ctx.doc.subscriptions) sub_names[s.id] = s.remarks.empty() ? s.id : s.remarks;

        std::unordered_map<std::string, int> delays;
        for (auto const& e : ctx.telemetry.entries) delays[e.profile_id] = static_cast<int>(e.delay_ms);

        std::string const sub_filter(ws.get_selected_sub_tab());
        std::string const search_q = lower_ascii(std::string_view(ws.get_profile_search()));
        std::string const sort_mode(ws.get_profile_sort());

        std::vector<nexus_ui::WorkspaceProfileRow> p_rows;
        std::vector<nexus_ui::WorkspaceProfileRow> f_rows;
        p_rows.reserve(ctx.doc.profiles.size());
        for (auto const& p : ctx.doc.profiles) {
            std::string eff_sub = p.subscription_id.empty() ? "manual" : p.subscription_id;
            ++sub_counts[eff_sub];
            bool const active = (p.id == ctx.telemetry.active_profile_id);
            std::string badge = upper_proto_badge(p);
            std::string endpoint = p.kind == "node"
                ? std::format("{}:{}", p.node.server, p.node.port)
                : (p.kind == "policy_group" ? std::format("{} members", p.policy_group.member_ids.size())
                : (p.kind == "proxy_chain" ? std::format("{} hops", p.proxy_chain.hop_ids.size()) : "custom"));
            std::string trans = build_transport_summary(p);
            std::string subtitle = endpoint + " · " + trans;
            auto sub_it = sub_names.find(eff_sub);
            std::string sub_label = sub_it != sub_names.end() ? sub_it->second : (eff_sub == "manual" ? "" : eff_sub);
            auto d_it = delays.find(p.id);
            nexus_ui::WorkspaceProfileRow row{
                slint::SharedString(p.id),
                slint::SharedString(p.remarks.empty() ? p.id : p.remarks),
                slint::SharedString(p.kind),
                slint::SharedString(badge),
                slint::SharedString(endpoint),
                slint::SharedString(trans),
                slint::SharedString(subtitle),
                slint::SharedString(eff_sub),
                slint::SharedString(sub_label),
                d_it != delays.end() ? d_it->second : -1,
                active,
            };
            bool sub_ok = (sub_filter.empty() || sub_filter == "all")
                || (sub_filter == "manual" && (eff_sub == "manual" || !sub_names.contains(eff_sub)))
                || (eff_sub == sub_filter);
            bool q_ok = search_q.empty() || lower_ascii(p.remarks + " " + p.id + " " + badge + " " + endpoint + " " + trans).contains(search_q);
            if (sub_ok && q_ok) f_rows.push_back(row);
            p_rows.push_back(std::move(row));
        }

        if (sort_mode == "latency") {
            std::ranges::stable_sort(f_rows, [](auto const& a, auto const& b) {
                int da = a.delay_ms > 0 ? a.delay_ms : 999999;
                int db = b.delay_ms > 0 ? b.delay_ms : 999999;
                return da < db;
            });
        } else if (sort_mode == "name") {
            std::ranges::stable_sort(f_rows, [](auto const& a, auto const& b) {
                return std::string_view(a.remarks) < std::string_view(b.remarks);
            });
        }

        ws.set_active_profile_id(slint::SharedString(ctx.telemetry.active_profile_id));
        ws.set_profiles(std::make_shared<slint::VectorModel<nexus_ui::WorkspaceProfileRow>>(std::move(p_rows)));
        ws.set_filtered_profiles(std::make_shared<slint::VectorModel<nexus_ui::WorkspaceProfileRow>>(std::move(f_rows)));

        std::vector<nexus_ui::WorkspaceSubRow> s_rows;
        s_rows.reserve(ctx.doc.subscriptions.size());
        for (auto const& s : ctx.doc.subscriptions) {
            std::int64_t used = s.usage.upload_bytes + s.usage.download_bytes;
            float ratio = (s.usage.total_bytes > 0)
                ? static_cast<float>(std::clamp(static_cast<double>(used) / static_cast<double>(s.usage.total_bytes), 0.0, 1.0))
                : 0.0f;
            std::string exp;
            if (s.usage.expire_unix_sec > 0) {
                auto tp = std::chrono::sys_seconds{std::chrono::seconds{s.usage.expire_unix_sec}};
                auto ymd = std::chrono::year_month_day{std::chrono::floor<std::chrono::days>(tp)};
                if (ymd.ok()) {
                    exp = std::format("{:04d}-{:02d}-{:02d}", static_cast<int>(ymd.year()),
                                      static_cast<unsigned>(ymd.month()), static_cast<unsigned>(ymd.day()));
                }
            }
            s_rows.push_back({
                slint::SharedString(s.id), slint::SharedString(s.remarks.empty() ? s.id : s.remarks),
                slint::SharedString(s.url), sub_counts[s.id],
                slint::SharedString(format_quota_human(used, s.usage.total_bytes)), ratio, slint::SharedString(exp),
                slint::SharedString(s.prev_profile_id), slint::SharedString(s.next_profile_id),
                static_cast<int>(s.auto_update_minutes), slint::SharedString(s.include_regex),
                slint::SharedString(s.exclude_regex), slint::SharedString(s.user_agent), s.enabled,
            });
        }
        ws.set_subscriptions(std::make_shared<slint::VectorModel<nexus_ui::WorkspaceSubRow>>(std::move(s_rows)));

        std::vector<nexus_ui::WorkspaceRoutingRow> r_rows;
        std::vector<nexus_ui::WorkspaceRuleRow> rule_rows;
        bool active_auto_detect = false, active_find_process = false;
        std::string active_routing_name, active_dom_strat = "as-is", active_def_out = "proxy";
        int active_rule_count = 0;
        for (auto const& rp : ctx.doc.routing_profiles) {
            r_rows.push_back({
                slint::SharedString(rp.id), slint::SharedString(rp.name),
                slint::SharedString(rp.default_outbound), slint::SharedString(rp.domain_strategy),
                static_cast<int>(rp.rules.size()), rp.is_active,
            });
            if (rp.is_active) {
                active_auto_detect = rp.auto_detect_interface;
                active_find_process = rp.find_process;
                active_dom_strat = rp.domain_strategy.empty() ? "as-is" : rp.domain_strategy;
                active_def_out = rp.default_outbound.empty() ? "proxy" : rp.default_outbound;
                active_routing_name = rp.name.empty() ? rp.id : rp.name;
                active_rule_count = static_cast<int>(rp.rules.size());
                for (auto const& r : rp.rules) {
                    std::string tgt = (r.target_type == "profile_id" && !r.target_profile_id.empty())
                        ? ("@" + r.target_profile_id) : r.target_type;
                    std::string match = !r.domains.empty() ? join_csv(r.domains)
                        : !r.ips.empty() ? join_csv(r.ips)
                        : !r.rule_sets.empty() ? ("@" + join_csv(r.rule_sets))
                        : !r.ports.empty() ? ("port:" + join_csv(r.ports))
                        : !r.protocols.empty() ? join_csv(r.protocols) : join_csv(r.networks);
                    rule_rows.push_back({
                        slint::SharedString(r.id), slint::SharedString(r.scope), slint::SharedString(tgt),
                        slint::SharedString(match), slint::SharedString(join_csv(r.desktop_process)),
                        r.tls_fragment, r.locked, r.enabled,
                    });
                }
            }
        }
        ctx.ui.set_active_rule_count(active_rule_count);
        ctx.ui.set_active_routing_name(slint::SharedString(active_routing_name));
        ws.set_routing_domain_strategy(slint::SharedString(active_dom_strat));
        ws.set_routing_default_outbound(slint::SharedString(active_def_out));
        ws.set_routing_auto_detect_interface(active_auto_detect);
        ws.set_routing_find_process(active_find_process);
        ws.set_routing_profiles(std::make_shared<slint::VectorModel<nexus_ui::WorkspaceRoutingRow>>(std::move(r_rows)));
        ws.set_routing_rules(std::make_shared<slint::VectorModel<nexus_ui::WorkspaceRuleRow>>(std::move(rule_rows)));

        std::vector<nexus_ui::WorkspaceRuleSetRow> rs_rows;
        rs_rows.reserve(ctx.doc.rule_set_assets.size());
        for (auto const& rs : ctx.doc.rule_set_assets) {
            rs_rows.push_back({
                slint::SharedString(rs.tag), slint::SharedString(rs.source_type), slint::SharedString(rs.format),
                slint::SharedString(rs.source_type == "remote" ? rs.url : rs.path),
                static_cast<int>(rs.update_interval_ms / 60000),
            });
        }
        ws.set_rule_sets(std::make_shared<slint::VectorModel<nexus_ui::WorkspaceRuleSetRow>>(std::move(rs_rows)));

        ws.set_dns_mode(slint::SharedString(ctx.doc.dns.mode));
        ws.set_dns_bootstrap(slint::SharedString(ctx.doc.dns.simple.bootstrap_dns));
        ws.set_dns_direct(slint::SharedString(join_csv(ctx.doc.dns.simple.direct_dns)));
        ws.set_dns_remote(slint::SharedString(join_csv(ctx.doc.dns.simple.remote_dns)));
        ws.set_dns_strategy(slint::SharedString(ctx.doc.dns.simple.strategy));
        ws.set_dns_parallel(ctx.doc.dns.simple.parallel_query);
        ws.set_dns_fakeip(ctx.doc.dns.simple.fake_ip_enabled);
        ws.set_dns_fakeip_v4(slint::SharedString(ctx.doc.dns.simple.fake_ip_v4_pool));
        ws.set_dns_fakeip_v6(slint::SharedString(ctx.doc.dns.simple.fake_ip_v6_pool));
        ws.set_dns_fakeip_global(ctx.doc.dns.simple.fake_ip_global);
        ws.set_dns_block_aaaa(ctx.doc.dns.simple.block_aaaa);
        ws.set_dns_block_svcb(ctx.doc.dns.simple.block_svcb_https);
        ws.set_dns_use_system_hosts(ctx.doc.dns.simple.use_system_hosts);
        ws.set_dns_hosts_text(slint::SharedString(format_hosts_csv(ctx.doc.dns.simple.hosts)));
        ws.set_dns_raw_kdl(slint::SharedString(ctx.doc.dns.raw_kdl));

        ws.set_tpl_enabled(ctx.doc.full_template.enabled);
        ws.set_tpl_append_only(ctx.doc.full_template.append_proxies_only);
        ws.set_tpl_proxy_detour(slint::SharedString(ctx.doc.full_template.proxy_detour));
        ws.set_tpl_kdl(slint::SharedString(ctx.doc.full_template.template_kdl));

        ws.set_host_is_linux(ctx.host.platform == "desktop-linux");
        ws.set_host_enable_mixed(ctx.host.enable_mixed);
        ws.set_host_mixed_listen(slint::SharedString(ctx.host.mixed_listen));
        ws.set_host_enable_socks(ctx.host.enable_socks);
        ws.set_host_socks_listen(slint::SharedString(ctx.host.socks_listen.empty() ? ctx.host.second_local_listen : ctx.host.socks_listen));
        ws.set_host_enable_http(ctx.host.enable_http);
        ws.set_host_http_listen(slint::SharedString(ctx.host.http_listen));
        ws.set_host_allow_lan(ctx.host.allow_lan);
        ws.set_host_lan_listen(slint::SharedString(ctx.host.lan_listen));
        ws.set_host_lan_user(slint::SharedString(ctx.host.lan_username));
        ws.set_host_lan_pass(slint::SharedString(ctx.host.lan_password));
        ws.set_host_enable_tun(ctx.host.enable_tun);
        ws.set_host_tun_name(slint::SharedString(ctx.host.tun_interface_name));
        ws.set_host_tun_mtu(slint::SharedString(std::to_string(ctx.host.tun_mtu)));
        ws.set_host_tun_inet4(slint::SharedString(ctx.host.tun_inet4));
        ws.set_host_tun_inet6(slint::SharedString(ctx.host.tun_inet6));
        ws.set_host_tun_auto_route(ctx.host.tun_auto_route);
        ws.set_host_tun_strict_route(ctx.host.tun_strict_route);
        ws.set_host_tun_exclude_private(ctx.host.tun_route_exclude_private);
        ws.set_host_tun_exclude_cidr(slint::SharedString(join_csv(ctx.host.tun_route_exclude)));
        ws.set_host_bind_iface(slint::SharedString(ctx.host.bind_interface));
        ws.set_host_bind_inet4(slint::SharedString(ctx.host.inet4_bind_address));
        ws.set_host_bind_inet6(slint::SharedString(ctx.host.inet6_bind_address));
        ws.set_host_include_siblings(ctx.host.include_sibling_nodes_in_selector);
        ws.set_host_workers(slint::SharedString(std::to_string(ctx.host.workers)));
        ws.set_host_workers_spec(slint::SharedString(ctx.host.workers_spec));
        ws.set_host_workers_max(slint::SharedString(std::to_string(ctx.host.workers_max)));

        sync_profiles_to_ui(ctx.ui, ctx.doc, ctx.telemetry.active_profile_id);
        std::string active_label;
        for (auto const& p : ctx.doc.profiles) {
            if (p.id == ctx.telemetry.active_profile_id) { active_label = p.remarks.empty() ? p.id : p.remarks; break; }
        }
        ctx.ui.set_active_profile(slint::SharedString(active_label));
        ctx.ui.set_tun_enabled(ctx.host.enable_tun);
        ctx.ui.set_mixed_proxy_enabled(ctx.host.enable_mixed);
        if (auto hp = parse_host_port_literal(ctx.host.mixed_listen); hp) {
            ctx.ui.set_mixed_proxy_host(slint::SharedString(ctx.host.allow_lan && hp->first == "127.0.0.1" ? "0.0.0.0" : hp->first));
            ctx.ui.set_mixed_proxy_port(slint::SharedString(std::to_string(hp->second)));
        }
        bool const eff_socks = ctx.host.enable_socks || !ctx.host.second_local_listen.empty();
        ctx.ui.set_socks_proxy_enabled(eff_socks);
        auto const& socks_src = !ctx.host.socks_listen.empty() ? ctx.host.socks_listen : ctx.host.second_local_listen;
        if (auto shp = parse_host_port_literal(socks_src); shp) {
            ctx.ui.set_socks_proxy_host(slint::SharedString(ctx.host.allow_lan && shp->first == "127.0.0.1" ? "0.0.0.0" : shp->first));
            ctx.ui.set_socks_proxy_port(slint::SharedString(std::to_string(shp->second)));
        }
        ctx.ui.set_http_proxy_enabled(ctx.host.enable_http);
        if (auto hhp = parse_host_port_literal(ctx.host.http_listen); hhp) {
            ctx.ui.set_http_proxy_host(slint::SharedString(ctx.host.allow_lan && hhp->first == "127.0.0.1" ? "0.0.0.0" : hhp->first));
            ctx.ui.set_http_proxy_port(slint::SharedString(std::to_string(hhp->second)));
        }
        bool const lan_on = ctx.host.allow_lan || !ctx.host.lan_listen.empty();
        ctx.ui.set_lan_share_enabled(lan_on);
        if (ctx.host.allow_lan) {
            ctx.ui.set_lan_share_subtitle(slint::SharedString("0.0.0.0"));
        } else if (auto lhp = parse_host_port_literal(ctx.host.lan_listen); lhp) {
            ctx.ui.set_lan_share_subtitle(slint::SharedString(":" + std::to_string(lhp->second)));
        } else {
            ctx.ui.set_lan_share_subtitle(slint::SharedString(ctx.host.lan_listen));
        }
    }
}

#include "workspace_recompose_flow.hpp"
