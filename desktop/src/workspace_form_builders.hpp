// Structured UI modal form builders (Full Nexus Outbound Protocols, Route Rule, DNS Rule, Subscription decode).
#pragma once

namespace desktop_ui_helpers {
    struct OutboundFormDraft {
        std::string edit_id;
        std::string sub_id = "manual";
        std::string proto = "vless";
        std::string tag, host, port = "443", secret, uuid_str, username, flow, packet_encoding = "xudp";
        std::string hy2_ports, hy2_hop_interval, hy2_salamander, hy2_up_mbps, hy2_down_mbps;
        std::string tuic_cc = "bbr";
        bool tuic_udp_over_stream = false;
        std::string ss_method = "2022-blake3-aes-128-gcm";
        int snell_ver = 5;
        std::string snell_obfs = "none", snell_obfs_host, naive_proto = "h2", ssh_host_sha;
        std::string wg_peer_pbk, wg_psk, wg_local_cidr, wg_reserved, wg_mtu = "1420";
        std::string masque_mode = "connect-udp", masque_path, masque_local_cidr;
        std::string sni, fingerprint = "chrome", key_exchange = "default", cert_sha256;
        bool use_reality = false;
        std::string reality_pbk, reality_sid;
        bool client_hello_fragment = false, tls_fragment = false, ech_dns = false;
        std::string ech_config, ech_query_sni, transport = "tcp", transport_path, transport_host, xhttp_mode = "auto";
        std::string ws_max_early_data, ws_early_data_header;
        bool grpc_permit_without_stream = false;
        bool mux_enabled = false;
        std::string mux_proto = "h2mux", mux_max_conns, mux_min_streams;
        bool mux_padding = false;
    };

    inline auto decode_base64_flexible(std::string_view in) -> std::optional<std::string> {
        static constexpr std::string_view kTable =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        std::uint32_t acc = 0;
        int bits = 0;
        for (char ch : in) {
            if (ch == '=' || ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') continue;
            char mapped = ch == '-' ? '+' : (ch == '_' ? '/' : ch);
            auto pos = kTable.find(mapped);
            if (pos == std::string_view::npos) return std::nullopt;
            acc = (acc << 6) | static_cast<std::uint32_t>(pos);
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push_back(static_cast<char>((acc >> bits) & 0xffu));
            }
        }
        return out;
    }

    inline auto decode_subscription_lines(std::string_view raw) -> std::vector<std::string> {
        auto sv = trim_ascii_ws(raw);
        if (sv.empty()) return {};
        std::string decoded_buf;
        if (!sv.contains("://")) {
            if (auto dec = decode_base64_flexible(sv); dec && dec->contains("://")) {
                decoded_buf = std::move(*dec);
                sv = decoded_buf;
            }
        }
        std::vector<std::string> lines;
        while (!sv.empty()) {
            auto nl = sv.find('\n');
            auto ln = trim_ascii_ws(nl == std::string_view::npos ? sv : sv.substr(0, nl));
            sv = nl == std::string_view::npos ? std::string_view{} : sv.substr(nl + 1);
            if (!ln.empty() && !ln.starts_with('#') && !ln.starts_with("//")) lines.emplace_back(ln);
        }
        return lines;
    }

    inline auto format_hosts_csv(std::vector<std::pair<std::string, std::string>> const& hosts) -> std::string {
        std::string out;
        for (std::size_t i = 0; i < hosts.size(); ++i) {
            if (i > 0) out += ", ";
            out += hosts[i].first + "=" + hosts[i].second;
        }
        return out;
    }

    inline auto parse_hosts_csv(std::string_view sv) -> std::vector<std::pair<std::string, std::string>> {
        std::vector<std::pair<std::string, std::string>> out;
        for (auto const& tok : split_csv_trim(sv)) {
            auto eq = tok.find('=');
            if (eq == std::string::npos) continue;
            auto k = trim_ascii_ws(std::string_view(tok).substr(0, eq));
            auto v = trim_ascii_ws(std::string_view(tok).substr(eq + 1));
            if (!k.empty() && !v.empty()) out.emplace_back(std::string(k), std::string(v));
        }
        return out;
    }

    inline auto build_workspace_node_from_form(
        OutboundFormDraft const& d,
        std::unordered_set<std::string> const& existing_ids,
        std::size_t current_count) -> std::expected<desktop::WorkspaceProfileItem, std::string> {
        auto proto = std::string(trim_ascii_ws(d.proto));
        auto host = std::string(trim_ascii_ws(d.host));
        auto port_sv = trim_ascii_ws(d.port);
        if (proto.empty()) proto = "vless";
        if (proto == "http-connect") proto = "http";
        if (host.empty()) return std::unexpected("Server host is required");
        std::int64_t port = 0;
        auto [ptr, ec] = std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), port);
        if (ec != std::errc{} || ptr != port_sv.data() + port_sv.size() || port < 1 || port > 65535) {
            return std::unexpected("Port must be 1..65535");
        }

        auto secret = std::string(trim_ascii_ws(d.secret));
        auto uuid_s = std::string(trim_ascii_ws(d.uuid_str));
        auto user = std::string(trim_ascii_ws(d.username));
        if (proto == "vless" && secret.empty()) return std::unexpected("VLESS UUID is required");
        if ((proto == "trojan" || proto == "anytls" || proto == "hysteria2") && secret.empty()) {
            return std::unexpected("Password is required");
        }
        if (proto == "shadowsocks" && secret.empty()) return std::unexpected("Shadowsocks key is required");
        if (proto == "snell" && secret.empty()) return std::unexpected("Snell PSK is required");
        if (proto == "tuic" && (uuid_s.empty() || secret.empty())) return std::unexpected("TUIC requires both UUID and password");
        if (proto == "naive" && (user.empty() || secret.empty())) return std::unexpected("Naive requires username and password");
        if (proto == "ssh" && (user.empty() || secret.empty() || trim_ascii_ws(d.ssh_host_sha).empty())) {
            return std::unexpected("SSH requires username, credential, and HostKey SHA-256");
        }
        if (proto == "wireguard" && (secret.empty() || trim_ascii_ws(d.wg_peer_pbk).empty())) {
            return std::unexpected("WireGuard requires both local private key and peer public key");
        }

        desktop::WorkspaceProfileItem item{};
        auto sub = trim_ascii_ws(d.sub_id);
        item.subscription_id = sub.empty() ? "manual" : std::string(sub);
        item.kind = "node";
        std::string remarks(trim_ascii_ws(d.tag));
        if (remarks.empty()) remarks = proto + "-" + std::to_string(current_count + 1);
        item.remarks = remarks;
        auto edit_id = trim_ascii_ws(d.edit_id);
        if (!edit_id.empty()) {
            item.id = std::string(edit_id);
        } else {
            auto base = desktop::sanitize_workspace_id(remarks);
            item.id = base;
            for (int n = 2; existing_ids.contains(item.id); ++n) item.id = base + "-" + std::to_string(n);
        }

        auto& n = item.node;
        n.protocol = proto;
        n.server = host;
        n.port = port;
        n.username = (proto == "tuic") ? uuid_s : user;
        n.password = secret;
        if (proto == "shadowsocks") n.method = std::string(trim_ascii_ws(d.ss_method));
        if (proto == "vless") {
            if (d.flow != "none") n.flow = std::string(trim_ascii_ws(d.flow));
            if (auto pe = trim_ascii_ws(d.packet_encoding); !pe.empty() && pe != "none") n.packet_encoding = std::string(pe);
        }

        bool const has_tls = proto != "shadowsocks" && proto != "snell" && proto != "ssh" && proto != "wireguard" && proto != "socks5";
        bool const has_transport = proto == "vless" || proto == "trojan" || proto == "anytls";
        if (has_tls) {
            n.tls.enabled = true;
            n.tls.sni = std::string(trim_ascii_ws(d.sni));
            if (d.fingerprint != "default" && !trim_ascii_ws(d.fingerprint).empty()) n.tls.fingerprint = std::string(trim_ascii_ws(d.fingerprint));
            if (d.key_exchange != "default" && !trim_ascii_ws(d.key_exchange).empty()) n.tls.key_exchange = std::string(trim_ascii_ws(d.key_exchange));
            if (auto pin = trim_ascii_ws(d.cert_sha256); !pin.empty()) n.tls.cert_sha256 = split_csv_trim(pin);
            if (has_transport && d.use_reality && !trim_ascii_ws(d.reality_pbk).empty()) {
                n.tls.reality_public_key = std::string(trim_ascii_ws(d.reality_pbk));
                n.tls.reality_short_id = std::string(trim_ascii_ws(d.reality_sid));
            }
            n.tls.fragment = d.client_hello_fragment;
            n.tls.record_fragment = d.tls_fragment;
            if (d.ech_dns) {
                n.tls.ech_config = std::string(trim_ascii_ws(d.ech_config));
                n.tls.ech_mode = n.tls.ech_config.empty() ? "dns" : "config";
                n.tls.ech_query_server_name = std::string(trim_ascii_ws(d.ech_query_sni));
            }
        }
        if (has_transport) {
            n.transport.type = normalize_node_transport_type(d.transport);
            if (n.transport.type == "grpc") {
                n.transport.service_name = std::string(trim_ascii_ws(d.transport_path));
                n.transport.authority = std::string(trim_ascii_ws(d.transport_host));
                n.transport.grpc_permit_without_stream = d.grpc_permit_without_stream;
            } else if (!n.transport.type.empty()) {
                n.transport.path = std::string(trim_ascii_ws(d.transport_path));
                n.transport.host = std::string(trim_ascii_ws(d.transport_host));
                if (n.transport.type == "xhttp") n.transport.xhttp_mode = std::string(trim_ascii_ws(d.xhttp_mode));
                if (n.transport.type == "websocket") {
                    n.transport.max_early_data = parse_positive_i64_prefix(d.ws_max_early_data);
                    n.transport.early_data_header_name = std::string(trim_ascii_ws(d.ws_early_data_header));
                }
            }
        }
        if (d.mux_enabled && (has_transport || proto == "shadowsocks" || proto == "snell" || proto == "socks5")) {
            n.multiplex.enabled = true;
            n.multiplex.protocol = std::string(trim_ascii_ws(d.mux_proto));
            n.multiplex.max_connections = parse_positive_i64_prefix(d.mux_max_conns);
            n.multiplex.min_streams = parse_positive_i64_prefix(d.mux_min_streams);
            n.multiplex.padding = d.mux_padding;
        }
        if (proto == "hysteria2") {
            n.extra.hy2_ports = std::string(trim_ascii_ws(d.hy2_ports));
            n.extra.hy2_hop_interval_ms = parse_positive_i64_prefix(d.hy2_hop_interval);
            n.extra.hy2_salamander_password = std::string(trim_ascii_ws(d.hy2_salamander));
            n.extra.hy2_up_mbps = parse_positive_i64_prefix(d.hy2_up_mbps);
            n.extra.hy2_down_mbps = parse_positive_i64_prefix(d.hy2_down_mbps);
        } else if (proto == "tuic") {
            auto cc = std::string(trim_ascii_ws(d.tuic_cc));
            if (cc == "new_reno") cc = "reno";
            n.extra.tuic_congestion_control = std::move(cc);
            n.extra.tuic_udp_over_stream = d.tuic_udp_over_stream;
        } else if (proto == "wireguard") {
            n.extra.wg_peer_public_key = std::string(trim_ascii_ws(d.wg_peer_pbk));
            n.extra.wg_preshared_key = std::string(trim_ascii_ws(d.wg_psk));
            n.extra.wg_local_addresses = split_csv_trim(d.wg_local_cidr);
            if (n.extra.wg_local_addresses.empty()) n.extra.wg_local_addresses.emplace_back("10.0.0.2/32");
            n.extra.wg_reserved = std::string(trim_ascii_ws(d.wg_reserved));
            n.extra.wg_mtu = parse_positive_i64_prefix(d.wg_mtu);
            if (n.extra.wg_mtu <= 0) n.extra.wg_mtu = 1420;
        } else if (proto == "masque") {
            n.extra.masque_mode = std::string(trim_ascii_ws(d.masque_mode));
            if (n.extra.masque_mode.empty()) n.extra.masque_mode = "connect-udp";
            n.extra.masque_path = std::string(trim_ascii_ws(d.masque_path));
            n.extra.masque_local_addresses = split_csv_trim(d.masque_local_cidr);
        } else if (proto == "snell") {
            n.extra.snell_version = (d.snell_ver == 4) ? 4 : 5;
            if (d.snell_obfs == "http") {
                n.extra.snell_obfs = "http";
                n.extra.snell_obfs_host = std::string(trim_ascii_ws(d.snell_obfs_host));
            }
        } else if (proto == "naive") {
            n.extra.naive_protocol = std::string(trim_ascii_ws(d.naive_proto));
        } else if (proto == "ssh") {
            n.extra.ssh_host_key_sha256 = split_csv_trim(d.ssh_host_sha);
        }
        return item;
    }

    struct RouteRuleConditionDraft {
        std::string kind;
        std::string value;
    };

    struct RouteRuleFormDraft {
        bool use_rule_set = false;
        std::string rule_set_name;
        std::vector<RouteRuleConditionDraft> conditions;
        std::string action_kind = "route";
        std::string target_outbound = "proxy";
        bool tls_fragment = false;
    };

    inline auto append_domain_condition(desktop::RoutingRule& r, std::string_view kind, std::string_view val) -> void {
        if (kind == "domain") r.domains.push_back("full:" + std::string(val));
        else if (kind == "domain-keyword") r.domains.push_back("keyword:" + std::string(val));
        else if (kind == "domain-regex") r.domains.push_back("regexp:" + std::string(val));
        else if (kind == "domain-wildcard") r.domains.push_back(val.starts_with("*.") ? std::string(val) : "*." + std::string(val));
        else r.domains.emplace_back(val);
    }

    inline auto build_routing_rule_from_draft(
        RouteRuleFormDraft const& d,
        std::vector<desktop::WorkspaceProfileItem> const& profiles,
        std::size_t current_rule_count) -> std::expected<desktop::RoutingRule, std::string> {
        desktop::RoutingRule r{};
        r.id = "r-" + std::to_string(current_rule_count + 1);
        r.scope = "routing_only";
        r.tls_fragment = d.tls_fragment;

        if (d.use_rule_set) {
            auto rs = trim_ascii_ws(d.rule_set_name);
            if (rs.empty()) return std::unexpected("Rule-set name is required");
            r.rule_sets.emplace_back(rs);
        } else {
            for (auto const& c : d.conditions) {
                auto k = trim_ascii_ws(c.kind);
                auto v = trim_ascii_ws(c.value);
                if (k == "ip-is-private") { r.ips.emplace_back("private"); continue; }
                if (v.empty()) continue;
                if (k == "domain-suffix" || k == "domain" || k == "domain-keyword" || k == "domain-wildcard" || k == "domain-regex") {
                    append_domain_condition(r, k, v);
                } else if (k == "ip-cidr" || k == "source-ip-cidr") {
                    r.ips.emplace_back(v);
                } else if (k == "port" || k == "port-range") {
                    r.ports.emplace_back(v);
                } else if (k == "network") {
                    r.networks.emplace_back(v);
                } else if (k == "protocol") {
                    r.protocols.emplace_back(v);
                } else if (k == "process-name" || k == "process-path") {
                    r.desktop_process.emplace_back(v);
                } else if (k == "rule-set") {
                    r.rule_sets.emplace_back(v);
                }
            }
            if (r.domains.empty() && r.ips.empty() && r.rule_sets.empty() &&
                r.ports.empty() && r.networks.empty() && r.protocols.empty() && r.desktop_process.empty()) {
                return std::unexpected("At least one valid match condition is required");
            }
        }

        auto act = trim_ascii_ws(d.action_kind);
        auto tgt = trim_ascii_ws(d.target_outbound);
        if (act == "reject" || act == "block") {
            r.target_type = "block";
        } else if (act == "bypass" || tgt == "direct") {
            r.target_type = "direct";
        } else if (tgt.empty() || tgt == "proxy") {
            r.target_type = "proxy";
        } else {
            std::string matched_id;
            for (auto const& p : profiles) {
                if (p.id == tgt || p.remarks == tgt) { matched_id = p.id; break; }
            }
            if (!matched_id.empty()) {
                r.target_type = "profile_id";
                r.target_profile_id = std::move(matched_id);
            } else {
                r.target_type = "proxy";
            }
        }
        return r;
    }

    struct DnsRuleFormDraft {
        std::string match_kind = "domain-suffix";
        std::string match_value;
        std::string action_kind = "direct";
        std::string target_server = "direct";
    };

    inline auto build_dns_rule_from_draft(
        DnsRuleFormDraft const& d,
        std::size_t current_rule_count) -> std::expected<desktop::RoutingRule, std::string> {
        auto k = trim_ascii_ws(d.match_kind);
        auto v = trim_ascii_ws(d.match_value);
        if (v.empty()) return std::unexpected("DNS match value is required");
        desktop::RoutingRule r{};
        r.id = "dns-" + std::to_string(current_rule_count + 1);
        r.scope = "dns_only";
        if (k == "rule-set") r.rule_sets.emplace_back(v);
        else append_domain_condition(r, k, v);

        auto act = trim_ascii_ws(d.action_kind);
        auto srv = trim_ascii_ws(d.target_server);
        if (act == "block" || act == "reject") r.target_type = "block";
        else if (act == "direct" || srv == "direct" || srv == "local") r.target_type = "direct";
        else r.target_type = "proxy";
        return r;
    }
}
