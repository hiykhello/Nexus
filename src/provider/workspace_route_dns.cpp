// Stage 4: Routing & SimpleDNS auto-derivation for workspace compiler.
module provider.workspace_compose;
import std;
import glaze;
import platform.ip_address;
import :detail;

namespace provider::ws_detail {
    namespace {
        struct ParsedDnsServer {
            std::string type;
            std::string host;
            std::uint16_t port = 0;
            std::string path;
            bool is_ip = false;
            bool encrypted = false;
        };

        auto parse_dns_url(std::string_view raw) -> std::optional<ParsedDnsServer> {
            auto s = trim(raw);
            if (s.empty()) return std::nullopt;
            auto l = lower_ascii(s);
            if (l == "local" || l == "system") return ParsedDnsServer{.type = "local"};
            if (l == "dhcp" || l == "mdns") return ParsedDnsServer{.type = l};
            ParsedDnsServer out{};
            auto sep = s.find("://");
            std::string_view rest = s;
            if (sep != std::string_view::npos) {
                auto scheme = lower_ascii(s.substr(0, sep));
                rest = s.substr(sep + 3);
                if (scheme == "udp") out.type = "udp";
                else if (scheme == "tcp") out.type = "tcp";
                else if (scheme == "tls" || scheme == "dot") { out.type = "tls"; out.encrypted = true; }
                else if (scheme == "https" || scheme == "doh") { out.type = "https"; out.encrypted = true; }
                else if (scheme == "quic" || scheme == "doq") { out.type = "quic"; out.encrypted = true; }
                else if (scheme == "https3" || scheme == "h3" || scheme == "doh3") { out.type = "https3"; out.encrypted = true; }
                else return std::nullopt;
            } else {
                out.type = "udp";
            }
            if (auto slash = rest.find('/'); slash != std::string_view::npos) {
                out.path = std::string(rest.substr(slash));
                rest = rest.substr(0, slash);
            }
            if (auto hp = platform::split_host_port(rest, false)) {
                out.host = std::string(hp->host);
                out.port = hp->port;
            } else {
                std::string_view h = rest;
                if (h.starts_with('[') && h.ends_with(']') && h.size() > 2) h = h.substr(1, h.size() - 2);
                out.host = std::string(h);
            }
            if (out.host.empty()) return std::nullopt;
            out.is_ip = platform::parse_ip_address(out.host).has_value();
            if ((!out.is_ip && !is_valid_hostname(out.host)) || (out.encrypted && out.host.contains(':'))) return std::nullopt;
            return out;
        }

        auto is_host_pattern(std::string_view h) -> bool {
            if (h.starts_with("*.")) return is_valid_hostname(h.substr(2));
            if (h.starts_with('.')) return is_valid_hostname(h.substr(1));
            return is_valid_hostname(h);
        }

        auto emit_dns_server_node(ComposeContext& ctx, std::ostringstream& os, std::string_view name,
                                  ParsedDnsServer srv, std::string_view detour, std::string_view bootstrap_name) -> void {
            if (srv.type == "local" || srv.type == "dhcp" || srv.type == "mdns") {
                os << "    server " << kdl_quote(name) << " type=" << kdl_quote(srv.type) << '\n';
                return;
            }
            if (detour == "proxy" && !ctx.proxy_datagram_capable) {
                if (srv.type == "udp") srv.type = "tcp";
                else if (srv.type == "quic" || srv.type == "https3") {
                    ctx.warnings.push_back("DNS server '" + std::string(name) + "' upgraded from " + srv.type + " to https for non-datagram proxy");
                    srv.type = "https";
                    if (srv.path.empty()) srv.path = "/dns-query";
                }
            }
            os << "    server " << kdl_quote(name) << " type=" << kdl_quote(srv.type) << " host=" << kdl_quote(srv.host);
            if (srv.port != 0) os << " port=" << srv.port;
            if (srv.encrypted) {
                os << " server-name=" << kdl_quote(srv.host);
                if (!ctx.resolved_ca_file.empty()) os << " ca-file=" << kdl_quote(ctx.resolved_ca_file);
                if ((srv.type == "https" || srv.type == "https3") && !srv.path.empty())
                    os << " path=" << kdl_quote(srv.path);
            }
            if (!srv.is_ip && !bootstrap_name.empty()) os << " domain-resolver=" << kdl_quote(bootstrap_name);
            if (!detour.empty()) os << " detour=" << kdl_quote(detour);
            os << '\n';
        }

        auto coerce_fakeip_v4(std::string_view raw, std::vector<std::string>& warnings) -> std::string {
            auto s = trim(raw);
            auto slash = s.find('/');
            auto ip = slash == std::string_view::npos ? std::nullopt : platform::parse_ip_address(s.substr(0, slash));
            unsigned pfx = 0; bool ok_pfx = false;
            if (slash != std::string_view::npos) {
                auto ps = s.substr(slash + 1);
                auto [e, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), pfx);
                ok_pfx = !ps.empty() && ec == std::errc{} && e == ps.data() + ps.size();
            }
            if (!ip || ip->size != 4 || !ok_pfx || pfx > 32) {
                if (!s.empty()) warnings.push_back("invalid fake_ip_v4_pool '" + std::string(s) + "', using 198.18.0.0/16");
                return "198.18.0.0/16";
            }
            unsigned orig = pfx;
            pfx = std::clamp(pfx, 16u, 30u);
            if (pfx != orig) warnings.push_back("fake_ip_v4_pool prefix /" + std::to_string(orig) + " coerced to /" + std::to_string(pfx));
            std::uint32_t addr = (std::uint32_t(ip->bytes[0]) << 24) | (std::uint32_t(ip->bytes[1]) << 16) |
                                 (std::uint32_t(ip->bytes[2]) << 8) | std::uint32_t(ip->bytes[3]);
            addr &= ~((std::uint32_t{1} << (32u - pfx)) - 1u);
            return std::format("{}.{}.{}.{}/{}", (addr >> 24) & 0xffu, (addr >> 16) & 0xffu, (addr >> 8) & 0xffu, addr & 0xffu, pfx);
        }

        auto validate_fakeip_v6(std::string_view raw, std::vector<std::string>& warnings) -> std::string {
            auto s = trim(raw);
            if (s.empty()) return {};
            auto slash = s.find('/');
            if (slash == std::string_view::npos) { warnings.push_back("ignored invalid fake_ip_v6_pool"); return {}; }
            auto ip = platform::parse_ip_address(s.substr(0, slash));
            unsigned pfx = 0; auto ps = s.substr(slash + 1);
            auto [e, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), pfx);
            if (!ip || ip->size != 16 || ec != std::errc{} || e != ps.data() + ps.size() || pfx < 7 || pfx > 96 || ((ip->bytes[0] & 0xfeu) != 0xfcu)) {
                warnings.push_back("ignored invalid fake_ip_v6_pool '" + std::string(s) + "'"); return {};
            }
            for (unsigned bit = pfx; bit < 128; ++bit)
                if (ip->bytes[bit / 8] & (0x80u >> (bit % 8))) { warnings.push_back("ignored fake_ip_v6_pool with host bits '" + std::string(s) + "'"); return {}; }
            return std::string(s);
        }

        auto normalize_dns_strategy(std::string_view raw) -> std::string_view {
            std::string s = lower_ascii(trim(raw));
            std::ranges::replace(s, '-', '_');
            if (s == "prefer_ipv6") return "prefer_ipv6";
            if (s == "ipv4_only") return "ipv4_only";
            return (s == "ipv6_only") ? "ipv6_only" : "prefer_ipv4";
        }

        struct DomainAtom { std::string kind, value; };

        auto parse_domain_expr(std::string_view raw) -> std::optional<DomainAtom> {
            auto s = trim(raw);
            if (s.empty()) return std::nullopt;
            if (s.starts_with("full:")) { auto v = lower_ascii(trim(s.substr(5))); return is_valid_hostname(v) ? std::optional(DomainAtom{"domain", std::move(v)}) : std::nullopt; }
            if (s.starts_with("domain:")) { auto v = lower_ascii(trim(s.substr(7))); return is_valid_hostname(v) ? std::optional(DomainAtom{"domain-suffix", std::move(v)}) : std::nullopt; }
            if (s.starts_with("keyword:")) { auto v = lower_ascii(trim(s.substr(8))); return !v.empty() ? std::optional(DomainAtom{"domain-keyword", std::move(v)}) : std::nullopt; }
            if (s.starts_with("regexp:") || s.starts_with("regex:")) { auto v = trim(s.substr(s.find(':') + 1)); return !v.empty() ? std::optional(DomainAtom{"domain-regex", std::string(v)}) : std::nullopt; }
            if (s.starts_with("*.")) { auto v = lower_ascii(s); return is_valid_hostname(std::string_view(v).substr(2)) ? std::optional(DomainAtom{"domain-wildcard", std::move(v)}) : std::nullopt; }
            if (s.contains(':')) return std::nullopt;
            auto v = lower_ascii(s);
            return is_valid_hostname(v) ? std::optional(DomainAtom{"domain-suffix", std::move(v)}) : std::nullopt;
        }

        auto valid_hex64(std::string_view s) noexcept -> bool {
            return s.size() == 64 && std::ranges::all_of(s, [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            });
        }

        auto valid_ruleset_asset(ComposeContext const& ctx, WorkspaceRuleSetAsset const& a, bool is_dns, std::string& why) -> bool {
            if (a.tag.empty() || a.tag.size() > 63) { why = "invalid tag"; return false; }
            auto fmt = lower_ascii(a.format);
            if (fmt.empty()) fmt = "nxmm";
            if (fmt != "kdl" && fmt != "beve" && fmt != "srs" && fmt != "nxmm" && fmt != "json" &&
                fmt != "domain-list" && fmt != "ipcidr-list" && fmt != "classical" && fmt != "adguard") { why = "unsupported format"; return false; }
            if (is_dns && fmt == "ipcidr-list") { why = "ipcidr-list unsupported in DNS rules"; return false; }
            if (lower_ascii(a.source_type) == "remote") {
                if (!a.url.starts_with("https://") || a.url.size() > 2048) { why = "remote rule-set requires https:// URL"; return false; }
                if (!a.sha256.empty() && !valid_hex64(a.sha256)) { why = "invalid sha256 hex"; return false; }
                if (ctx.resolved_ca_file.empty() || ctx.direct_dns_primary.empty()) { why = "remote rule-set requires CA file and DNS resolver"; return false; }
                return true;
            }
            if (a.path.empty()) { why = "local rule-set missing path"; return false; }
            return true;
        }

        auto emit_ruleset_decl(std::ostringstream& os, WorkspaceRuleSetAsset const& a, bool is_dns, bool& has_remote) -> void {
            auto fmt = lower_ascii(a.format);
            if (fmt.empty()) fmt = "nxmm";
            if (lower_ascii(a.source_type) == "remote") {
                has_remote = true;
                os << "  rule-set " << kdl_quote(a.tag) << " type=\"remote\" url=" << kdl_quote(a.url) << " format=" << kdl_quote(fmt);
                if (is_dns) os << " http-client=\"ruleset-http\"";
                if (!a.sha256.empty()) os << " sha256=" << kdl_quote(a.sha256);
                if (a.update_interval_ms >= 1000 && a.update_interval_ms <= 86400000) os << " update-interval-ms=" << a.update_interval_ms;
                os << '\n';
            } else {
                os << "  rule-set " << kdl_quote(a.tag) << " type=\"local\" path=" << kdl_quote(a.path) << " format=" << kdl_quote(fmt) << '\n';
            }
        }

        auto extract_raw_dns_server(glaze::KdlDocument const& doc) -> std::string {
            auto const& nodes = (doc.size() == 1 && doc.front().name == "dns") ? doc.front().children : doc;
            auto arg0 = [](glaze::KdlNode const& n) -> std::string {
                if (!n.arguments.empty()) if (auto* s = std::get_if<std::string>(&n.arguments[0].data)) return *s;
                return {};
            };
            std::string first_srv;
            for (auto const& n : nodes) {
                if (n.name == "final") if (auto s = arg0(n); !s.empty()) return s;
                if (n.name == "server" && first_srv.empty()) first_srv = arg0(n);
                if (n.name == "servers" && first_srv.empty())
                    for (auto const& ch : n.children) if (ch.name == "server") { first_srv = arg0(ch); if (!first_srv.empty()) break; }
            }
            return first_srv;
        }

        auto emit_or_group(std::ostringstream& os, std::vector<std::string> const& lines) -> void {
            if (lines.empty()) return;
            if (lines.size() == 1) { os << "      " << lines.front() << '\n'; return; }
            os << "      or {\n";
            for (auto const& l : lines) os << "        " << l << '\n';
            os << "      }\n";
        }
    }

    auto emit_routing_and_dns(ComposeContext& ctx, WorkspaceRoutingProfile const& rp,
                              std::map<std::string, std::string> const& rule_profile_tags,
                              std::ostringstream& routing_out, std::ostringstream& dns_out,
                              std::ostringstream& http_clients_out) -> std::expected<void, std::string> {
        bool is_desktop = ctx.host.platform.starts_with("desktop-");
        bool is_android = (ctx.host.platform == "android");
        bool android_protect = is_android && !ctx.host.android.protect_socket_path.empty();

        // 1. Determine default outbound & emit DNS first so we know dns_emitted, fake_ip_active, direct_dns_primary
        auto def_ob = lower_ascii(rp.default_outbound);
        bool def_block = (def_ob == "block");
        std::string resolved_default = (def_ob == "direct") ? "direct" : "proxy";
        if (def_block) {
            resolved_default = "direct";
            ctx.warnings.push_back("routing default_outbound=block compiled via catch-all reject rule");
        }

        std::set<std::string> ref_route_sets, ref_dns_sets;
        bool dns_has_remote = false, route_has_remote = false;

        // 2. Build DNS block
        if (lower_ascii(ctx.ws.dns.mode) == "raw_kdl" && !trim(ctx.ws.dns.raw_kdl).empty()) {
            auto doc = glaze::read_kdl<glaze::KdlDocument>(ctx.ws.dns.raw_kdl);
            if (!doc) return std::unexpected("invalid dns.raw_kdl syntax");
            if (doc->size() == 1 && doc->front().name == "dns")
                dns_out << ctx.ws.dns.raw_kdl << (ctx.ws.dns.raw_kdl.ends_with('\n') ? "" : "\n");
            else dns_out << "dns {\n" << ctx.ws.dns.raw_kdl << "\n}\n";
            ctx.dns_emitted = true;
            ctx.direct_dns_primary = extract_raw_dns_server(*doc);
        } else {
            auto const& sd = ctx.ws.dns.simple;
            if (sd.parallel_query) ctx.warnings.push_back("dns.simple.parallel_query is not yet compiled in SimpleDNS; using sequential rules");
            if (!sd.direct_expected_rule_sets.empty()) ctx.warnings.push_back("dns.simple.direct_expected_rule_sets is not yet compiled in SimpleDNS");
            if (sd.fake_ip_global) ctx.warnings.push_back("dns.simple.fake_ip_global is not distinct from fake_ip_enabled in SimpleDNS");
            std::ostringstream dns_servers_os, dns_rules_os;
            auto boot_srv = parse_dns_url(sd.bootstrap_dns.empty() ? std::string_view("223.5.5.5") : std::string_view(sd.bootstrap_dns));
            if (!boot_srv || !boot_srv->is_ip) boot_srv = ParsedDnsServer{.type = "udp", .host = "223.5.5.5", .port = 53, .is_ip = true};
            emit_dns_server_node(ctx, dns_servers_os, "bootstrap", *boot_srv,
                                 (android_protect && boot_srv->encrypted) ? "direct" : "", "");

            std::vector<std::string> host_rules;
            if (!sd.hosts.empty() || sd.use_system_hosts) {
                std::ostringstream hos;
                std::error_code ec;
                bool sys_hosts = sd.use_system_hosts && std::filesystem::is_regular_file("/etc/hosts", ec) && !ec;
                std::size_t entries = 0;
                auto push_hrule = [&](std::string const& hk) {
                    if (hk.starts_with("*.")) host_rules.push_back("domain-wildcard=" + kdl_quote(hk));
                    else if (hk.starts_with('.')) host_rules.push_back("domain-suffix=" + kdl_quote(hk.substr(1)));
                    else host_rules.push_back("domain=" + kdl_quote(hk));
                };
                for (auto const& [k, rv] : sd.hosts) {
                    auto hk = lower_ascii(trim(k));
                    if (hk.empty() || !is_host_pattern(hk)) continue;
                    std::vector<std::string_view> vals;
                    if (auto* s = std::get_if<std::string>(&rv)) {
                        for (std::string_view rest = trim(*s); !rest.empty();) {
                            auto c = rest.find(',');
                            if (auto tok = trim(rest.substr(0, c)); !tok.empty()) vals.push_back(tok);
                            if (c == std::string_view::npos) break;
                            rest.remove_prefix(c + 1);
                        }
                    } else if (auto* arr = std::get_if<std::vector<std::string>>(&rv)) {
                        for (auto const& x : *arr) if (auto tok = trim(x); !tok.empty()) vals.push_back(tok);
                    }
                    if (vals.empty()) continue;
                    if (std::ranges::all_of(vals, [](auto v) { return platform::parse_ip_address(v).has_value(); })) {
                        std::string ips;
                        for (std::size_t i = 0; i < vals.size(); ++i) { if (i) ips.push_back(','); ips += vals[i]; }
                        hos << "      entry host=" << kdl_quote(hk) << " ip=" << kdl_quote(ips) << '\n';
                        push_hrule(hk); ++entries;
                    } else if (vals.size() == 1 && is_valid_hostname(vals.front())) {
                        hos << "      entry host=" << kdl_quote(hk) << " cname=" << kdl_quote(vals.front()) << '\n';
                        push_hrule(hk); ++entries;
                    }
                }
                if (sys_hosts || entries > 0) {
                    dns_servers_os << "    server \"static-hosts\" type=\"hosts\"" << (sys_hosts ? " file=\"/etc/hosts\"" : "");
                    if (entries > 0) dns_servers_os << " {\n" << hos.str() << "    }\n"; else dns_servers_os << '\n';
                }
            }

            std::vector<std::string> direct_list = sd.direct_dns.empty() ? std::vector<std::string>{"223.5.5.5"} : sd.direct_dns;
            int didx = 0;
            for (auto const& raw : direct_list) {
                auto parsed = parse_dns_url(raw);
                if (!parsed) { ctx.warnings.push_back("skipped invalid direct_dns: " + raw); continue; }
                std::string sname = "direct-dns-" + std::to_string(didx++);
                if (ctx.direct_dns_primary.empty()) ctx.direct_dns_primary = sname;
                std::string_view dt = (android_protect && parsed->encrypted) ? "direct" : "";
                emit_dns_server_node(ctx, dns_servers_os, sname, *parsed, dt, "bootstrap");
            }
            if (ctx.direct_dns_primary.empty()) {
                ctx.direct_dns_primary = "direct-dns-0";
                emit_dns_server_node(ctx, dns_servers_os, "direct-dns-0",
                                     ParsedDnsServer{.type = "udp", .host = "223.5.5.5", .port = 53, .is_ip = true}, "", "bootstrap");
            }

            std::vector<std::string> remote_list = sd.remote_dns.empty() ? std::vector<std::string>{"https://1.1.1.1/dns-query"} : sd.remote_dns;
            int ridx = 0;
            for (auto const& raw : remote_list) {
                auto parsed = parse_dns_url(raw);
                if (!parsed) { ctx.warnings.push_back("skipped invalid remote_dns: " + raw); continue; }
                std::string sname = "remote-dns-" + std::to_string(ridx++);
                if (ctx.remote_dns_primary.empty()) ctx.remote_dns_primary = sname;
                emit_dns_server_node(ctx, dns_servers_os, sname, *parsed, "proxy", "bootstrap");
            }
            if (ctx.remote_dns_primary.empty()) {
                ctx.remote_dns_primary = "remote-dns-0";
                emit_dns_server_node(ctx, dns_servers_os, "remote-dns-0",
                                     ParsedDnsServer{.type = "https", .host = "1.1.1.1", .port = 443, .path = "/dns-query", .is_ip = true, .encrypted = true},
                                     "proxy", "bootstrap");
            }

            // FakeIP requires both dns { listen } and absolute host.state_dir
            std::optional<std::pair<std::string, std::uint16_t>> dns_listen_ep;
            if (is_android && !ctx.host.android.dns_listen.empty()) {
                if (auto hp = platform::split_host_port(ctx.host.android.dns_listen, true))
                    if (platform::parse_ip_address(hp->host)) dns_listen_ep = {std::string(hp->host), hp->port};
            }
            std::string fakeip_line;
            if (sd.fake_ip_enabled) {
                if (ctx.host.state_dir.empty() || !ctx.host.state_dir.starts_with('/')) {
                    ctx.warnings.push_back("fake-ip disabled: absolute host.state_dir is required");
                } else {
                    if (!dns_listen_ep) dns_listen_ep = {"127.0.0.1", 1053};
                    auto v4 = coerce_fakeip_v4(sd.fake_ip_v4_pool, ctx.warnings);
                    auto v6 = validate_fakeip_v6(sd.fake_ip_v6_pool, ctx.warnings);
                    fakeip_line = "  fake-ip ipv4-pool=" + kdl_quote(v4);
                    if (!v6.empty()) fakeip_line += " ipv6-pool=" + kdl_quote(v6);
                    fakeip_line += " server=" + kdl_quote(ctx.remote_dns_primary) + "\n";
                    ctx.fake_ip_active = true;
                }
            }

            std::size_t dns_rule_count = 0;
            constexpr std::size_t max_dns_rules = 240;
            for (auto const& hr : host_rules) { if (dns_rule_count >= max_dns_rules) break; dns_rules_os << "    - " << hr << " to=\"static-hosts\"\n"; ++dns_rule_count; }
            for (auto const& dom : ctx.protect_domains) { if (dns_rule_count >= max_dns_rules) break; dns_rules_os << "    - domain=" << kdl_quote(dom) << " to=" << kdl_quote(ctx.direct_dns_primary) << '\n'; ++dns_rule_count; }
            if (sd.block_aaaa && dns_rule_count < max_dns_rules) { dns_rules_os << "    - query-type=\"AAAA\" action=\"reject\" reject-rcode=\"NOERROR\"\n"; ++dns_rule_count; }
            if (sd.block_svcb_https && dns_rule_count + 2 <= max_dns_rules) {
                dns_rules_os << "    - query-type=\"SVCB\" action=\"reject\" reject-rcode=\"NOERROR\"\n"
                             << "    - query-type=\"HTTPS\" action=\"reject\" reject-rcode=\"NOERROR\"\n";
                dns_rule_count += 2;
            }
            for (auto const& r : rp.rules) {
                if (!r.enabled) continue;
                auto sc = lower_ascii(r.scope);
                if (sc != "both" && sc != "dns_only") continue;
                auto tt = lower_ascii(r.target_type);
                std::string_view srv = (tt == "direct") ? std::string_view(ctx.direct_dns_primary) : std::string_view(ctx.remote_dns_primary);
                auto tail = (tt == "block") ? std::string(" action=\"reject\" reject-rcode=\"NXDOMAIN\"\n") : (" to=" + kdl_quote(srv) + "\n");
                for (auto const& d : r.domains) {
                    if (dns_rule_count >= max_dns_rules) break;
                    if (auto atom = parse_domain_expr(d)) { dns_rules_os << "    - " << atom->kind << '=' << kdl_quote(atom->value) << tail; ++dns_rule_count; }
                }
                for (auto const& rs : r.rule_sets) {
                    if (dns_rule_count >= max_dns_rules) break;
                    auto it = ctx.asset_by_tag.find(rs);
                    if (it == ctx.asset_by_tag.end()) continue;
                    std::string why;
                    if (!valid_ruleset_asset(ctx, *it->second, true, why)) {
                        if (lower_ascii(it->second->format) != "ipcidr-list") ctx.warnings.push_back("DNS rule skipped invalid rule-set '" + rs + "': " + why);
                        continue;
                    }
                    ref_dns_sets.insert(rs); dns_rules_os << "    - rule-set=" << kdl_quote(rs) << tail; ++dns_rule_count;
                }
            }

            dns_out << "dns {\n";
            if (dns_listen_ep) dns_out << "  listen host=" << kdl_quote(dns_listen_ep->first) << " port=" << dns_listen_ep->second << '\n';
            dns_out << "  servers {\n" << dns_servers_os.str() << "  }\n";
            if (!fakeip_line.empty()) dns_out << fakeip_line;
            for (auto const& rs_tag : ref_dns_sets)
                if (auto it = ctx.asset_by_tag.find(rs_tag); it != ctx.asset_by_tag.end()) emit_ruleset_decl(dns_out, *it->second, true, dns_has_remote);
            if (dns_rule_count > 0) dns_out << "  rules {\n" << dns_rules_os.str() << "  }\n";
            dns_out << "  final " << kdl_quote(resolved_default == "direct" ? ctx.direct_dns_primary : ctx.remote_dns_primary) << '\n';
            dns_out << "  strategy " << kdl_quote(normalize_dns_strategy(sd.strategy)) << '\n';
            if (sd.serve_stale_seconds > 0) dns_out << "  optimistic-cache-seconds " << std::clamp<std::uint32_t>(sd.serve_stale_seconds, 1, 3600) << '\n';
            dns_out << "}\n";
            ctx.dns_emitted = true;
        }

        // 3. Build routing rules
        std::ostringstream rules_os;
        rules_os << "    - \"sniff\"\n";
        if (ctx.dns_emitted) rules_os << "    - action=\"hijack-dns\" {\n      or {\n        protocol \"dns\"\n        port 53\n      }\n    }\n";
        rules_os << "    - \"route-mode\" \"direct\" to=\"direct\"\n    - \"route-mode\" \"global\" to=\"proxy\"\n";
        auto ds = lower_ascii(rp.domain_strategy);
        bool resolve_emitted = false;
        if (ctx.dns_emitted && ds == "ip-on-demand") { rules_os << "    - \"resolve\"\n"; resolve_emitted = true; }

        for (auto const& r : rp.rules) {
            if (!r.enabled) continue;
            if (auto sc = lower_ascii(r.scope); sc != "both" && sc != "routing_only") continue;
            std::vector<std::string> dom_preds, ip_preds, rs_preds, port_preds, net_preds, proto_preds, proc_preds, pkg_preds;
            for (auto const& d : r.domains) if (auto a = parse_domain_expr(d)) dom_preds.push_back(a->kind + " " + kdl_quote(a->value));
            for (auto const& raw_ip : r.ips) {
                auto t = lower_ascii(trim(raw_ip));
                if (t == "private" || t == "geoip:private") ip_preds.push_back("ip-is-private #true");
                else if (t.contains('/')) ip_preds.push_back("ip-cidr " + kdl_quote(t));
                else if (auto parsed = platform::parse_ip_address(t))
                    ip_preds.push_back("ip-cidr " + kdl_quote(t + (parsed->size == 4 ? "/32" : "/128")));
            }
            for (auto const& rs : r.rule_sets) {
                auto it = ctx.asset_by_tag.find(rs);
                std::string why;
                if (it == ctx.asset_by_tag.end()) ctx.warnings.push_back("routing rule skipped unknown rule-set: " + rs);
                else if (!valid_ruleset_asset(ctx, *it->second, false, why)) ctx.warnings.push_back("routing rule skipped invalid rule-set '" + rs + "': " + why);
                else { ref_route_sets.insert(rs); rs_preds.push_back("rule-set " + kdl_quote(rs)); }
            }
            for (auto const& p : r.ports) {
                auto t = trim(p);
                if (t.contains('-') || t.contains(':')) {
                    std::string rng(t); std::ranges::replace(rng, ':', '-');
                    port_preds.push_back("port-range " + kdl_quote(rng));
                } else {
                    unsigned pv = 0;
                    auto [e, ec] = std::from_chars(t.data(), t.data() + t.size(), pv);
                    if (!t.empty() && ec == std::errc{} && e == t.data() + t.size() && pv >= 1 && pv <= 65535)
                        port_preds.push_back("port " + std::to_string(pv));
                }
            }
            for (auto const& net : r.networks) if (auto ln = lower_ascii(trim(net)); ln == "tcp" || ln == "udp") net_preds.push_back("network " + kdl_quote(ln));
            for (auto const& pr : r.protocols) {
                auto lp = lower_ascii(trim(pr));
                if (lp == "http" || lp == "tls" || lp == "tls-ech" || lp == "dns" || lp == "ssh" ||
                    lp == "stun" || lp == "quic" || lp == "bittorrent" || lp == "dtls" || lp == "rdp" || lp == "ntp")
                    proto_preds.push_back("protocol " + kdl_quote(lp));
            }
            if (is_desktop) for (auto const& proc : r.desktop_process) if (auto tp = trim(proc); !tp.empty())
                proc_preds.push_back((tp.starts_with('/') ? "process-path " : "process-name ") + kdl_quote(tp));
            if (is_android) for (auto const& pkg : r.android_packages) if (auto tp = trim(pkg); !tp.empty())
                pkg_preds.push_back("package-name " + kdl_quote(tp));
            if (dom_preds.empty() && ip_preds.empty() && rs_preds.empty() && port_preds.empty() &&
                net_preds.empty() && proto_preds.empty() && proc_preds.empty() && pkg_preds.empty()) continue;

            if (ctx.dns_emitted && ds == "ip-if-non-match" && !resolve_emitted && (!ip_preds.empty() || !rs_preds.empty())) {
                rules_os << "    - \"resolve\" route-only=#true\n";
                resolve_emitted = true;
            }
            auto tt = lower_ascii(r.target_type);
            std::string target = (tt == "direct") ? "direct" : "proxy";
            if (tt == "profile_id") if (auto it = rule_profile_tags.find(r.target_profile_id); it != rule_profile_tags.end()) target = it->second;
            rules_os << "    -";
            if (tt == "block") rules_os << " action=\"reject\"";
            else { rules_os << " to=" << kdl_quote(target); if (r.tls_fragment) rules_os << " tls-record-fragment=#true"; }
            rules_os << " {\n";
            for (auto const* grp : {&dom_preds, &ip_preds, &rs_preds, &port_preds, &net_preds, &proto_preds, &proc_preds, &pkg_preds})
                emit_or_group(rules_os, *grp);
            rules_os << "    }\n";
        }
        if (def_block) rules_os << "    - action=\"reject\" {\n      or {\n        network \"tcp\"\n        network \"udp\"\n      }\n    }\n";

        routing_out << "routing {\n";
        if (rp.auto_detect_interface) routing_out << "  auto-detect-interface #true\n";
        if (rp.find_process) routing_out << "  find-process #true\n";
        for (auto const& rs_tag : ref_route_sets)
            if (auto it = ctx.asset_by_tag.find(rs_tag); it != ctx.asset_by_tag.end()) emit_ruleset_decl(routing_out, *it->second, false, route_has_remote);
        if (route_has_remote) routing_out << "  default-http-client \"ruleset-http\"\n";
        routing_out << "  rules sniff-timeout-ms=300 unknown=\"skip\" udp=#true {\n" << rules_os.str() << "  }\n  default " << kdl_quote(resolved_default) << "\n}\n";

        if ((route_has_remote || dns_has_remote) && ctx.dns_emitted && !ctx.resolved_ca_file.empty() && !ctx.direct_dns_primary.empty())
            http_clients_out << "http-clients {\n  ruleset-http {\n    outbound \"direct\"\n    domain-resolver "
                             << kdl_quote(ctx.direct_dns_primary) << "\n    ca-file " << kdl_quote(ctx.resolved_ca_file) << "\n  }\n}\n";
        return {};
    }
}
