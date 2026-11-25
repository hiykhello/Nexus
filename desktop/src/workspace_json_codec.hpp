// Layer 1 WorkspaceDocument JSON serialization/deserialization helpers included by desktop/src/workspace_store.cpp.
#pragma once

namespace desktop::ws_codec {
    inline auto tls_to_json(TlsConfig const& t) -> JsonValue {
        return JsonObject{
            {"enabled", t.enabled},
            {"sni", t.sni},
            {"fingerprint", t.fingerprint},
            {"key_exchange", t.key_exchange},
            {"ca_pem", t.ca_pem},
            {"cert_sha256", json_from_string_vec(t.cert_sha256)},
            {"reality_public_key", t.reality_public_key},
            {"reality_short_id", t.reality_short_id},
            {"ech_mode", t.ech_mode},
            {"ech_config", t.ech_config},
        };
    }

    inline auto tls_from_json(JsonObject const& o) -> TlsConfig {
        return {
            json_get_bool(o, "enabled", false),
            json_get_string(o, "sni"),
            json_get_string(o, "fingerprint"),
            json_get_string(o, "key_exchange"),
            json_get_string(o, "ca_pem"),
            json_get_string_vec(o, "cert_sha256"),
            json_get_string(o, "reality_public_key"),
            json_get_string(o, "reality_short_id"),
            json_get_string(o, "ech_mode"),
            json_get_string(o, "ech_config"),
        };
    }

    inline auto transport_to_json(TransportConfig const& tr) -> JsonValue {
        return JsonObject{
            {"type", tr.type},
            {"host", tr.host},
            {"path", tr.path},
            {"service_name", tr.service_name},
            {"authority", tr.authority},
            {"xhttp_mode", tr.xhttp_mode},
            {"xhttp_protocol", tr.xhttp_protocol},
            {"headers", json_from_string_map(tr.headers)},
        };
    }

    inline auto normalize_transport_type_str(std::string_view raw) -> std::string {
        while (!raw.empty() && std::isspace(static_cast<unsigned char>(raw.front()))) raw.remove_prefix(1);
        while (!raw.empty() && std::isspace(static_cast<unsigned char>(raw.back()))) raw.remove_suffix(1);
        std::string out(raw.size(), '\0');
        for (std::size_t i = 0; i < raw.size(); ++i) {
            out[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(raw[i])));
        }
        if (out == "tcp" || out == "raw" || out == "none") return {};
        return out;
    }

    inline auto transport_from_json(JsonObject const& o) -> TransportConfig {
        return {
            normalize_transport_type_str(json_get_string(o, "type")),
            json_get_string(o, "host"),
            json_get_string(o, "path"),
            json_get_string(o, "service_name"),
            json_get_string(o, "authority"),
            json_get_string(o, "xhttp_mode"),
            json_get_string(o, "xhttp_protocol"),
            json_get_string_map(o, "headers"),
        };
    }

    inline auto extra_to_json(NodeExtraConfig const& e) -> JsonValue {
        return JsonObject{
            {"hy2_ports", e.hy2_ports},
            {"hy2_hop_interval_ms", e.hy2_hop_interval_ms},
            {"hy2_up_mbps", e.hy2_up_mbps},
            {"hy2_down_mbps", e.hy2_down_mbps},
            {"hy2_salamander_password", e.hy2_salamander_password},
            {"tuic_congestion_control", e.tuic_congestion_control},
            {"tuic_udp_over_stream", e.tuic_udp_over_stream},
            {"wg_peer_public_key", e.wg_peer_public_key},
            {"wg_preshared_key", e.wg_preshared_key},
            {"wg_local_addresses", json_from_string_vec(e.wg_local_addresses)},
            {"wg_reserved", e.wg_reserved},
            {"wg_mtu", e.wg_mtu},
            {"masque_mode", e.masque_mode},
            {"masque_path", e.masque_path},
            {"masque_local_addresses", json_from_string_vec(e.masque_local_addresses)},
            {"naive_protocol", e.naive_protocol},
            {"snell_version", e.snell_version},
            {"snell_obfs", e.snell_obfs},
            {"snell_obfs_host", e.snell_obfs_host},
            {"ssh_host_key_sha256", json_from_string_vec(e.ssh_host_key_sha256)},
        };
    }

    inline auto extra_from_json(JsonObject const& o) -> NodeExtraConfig {
        return {
            json_get_string(o, "hy2_ports"),
            json_get_i64(o, "hy2_hop_interval_ms"),
            json_get_i64(o, "hy2_up_mbps"),
            json_get_i64(o, "hy2_down_mbps"),
            json_get_string(o, "hy2_salamander_password"),
            json_get_string(o, "tuic_congestion_control"),
            json_get_bool(o, "tuic_udp_over_stream"),
            json_get_string(o, "wg_peer_public_key"),
            json_get_string(o, "wg_preshared_key"),
            json_get_string_vec(o, "wg_local_addresses"),
            json_get_string(o, "wg_reserved"),
            json_get_i64(o, "wg_mtu"),
            json_get_string(o, "masque_mode"),
            json_get_string(o, "masque_path"),
            json_get_string_vec(o, "masque_local_addresses"),
            json_get_string(o, "naive_protocol"),
            json_get_i64(o, "snell_version"),
            json_get_string(o, "snell_obfs"),
            json_get_string(o, "snell_obfs_host"),
            json_get_string_vec(o, "ssh_host_key_sha256"),
        };
    }

    inline auto node_to_json(NodeConfig const& n) -> JsonValue {
        return JsonObject{
            {"protocol", n.protocol},
            {"server", n.server},
            {"port", n.port},
            {"username", n.username},
            {"password", n.password},
            {"method", n.method},
            {"flow", n.flow},
            {"packet_encoding", n.packet_encoding},
            {"tls", tls_to_json(n.tls)},
            {"transport", transport_to_json(n.transport)},
            {"multiplex", JsonObject{
                {"enabled", n.multiplex.enabled},
                {"protocol", n.multiplex.protocol},
                {"max_connections", n.multiplex.max_connections},
                {"padding", n.multiplex.padding},
            }},
            {"extra", extra_to_json(n.extra)},
        };
    }

    inline auto node_from_json(JsonObject const& o) -> NodeConfig {
        NodeConfig n{};
        n.protocol = json_get_string(o, "protocol");
        n.server = json_get_string(o, "server");
        n.port = json_get_i64(o, "port", 443);
        n.username = json_get_string(o, "username");
        n.password = json_get_string(o, "password");
        n.method = json_get_string(o, "method");
        n.flow = json_get_string(o, "flow");
        n.packet_encoding = json_get_string(o, "packet_encoding");
        if (auto const* v = json_find(o, "tls"); v && v->is_object()) n.tls = tls_from_json(std::get<JsonObject>(v->data));
        if (auto const* v = json_find(o, "transport"); v && v->is_object()) n.transport = transport_from_json(std::get<JsonObject>(v->data));
        if (auto const* v = json_find(o, "multiplex"); v && v->is_object()) {
            auto const& m = std::get<JsonObject>(v->data);
            n.multiplex = {json_get_bool(m, "enabled"), json_get_string(m, "protocol"),
                           json_get_i64(m, "max_connections"), json_get_bool(m, "padding")};
        }
        if (auto const* v = json_find(o, "extra"); v && v->is_object()) n.extra = extra_from_json(std::get<JsonObject>(v->data));
        return n;
    }

    inline auto profile_to_json(WorkspaceProfileItem const& p) -> JsonValue {
        return JsonObject{
            {"id", p.id},
            {"remarks", p.remarks},
            {"subscription_id", p.subscription_id},
            {"is_from_sub", p.is_from_sub},
            {"kind", p.kind},
            {"node", node_to_json(p.node)},
            {"custom_outbound_kdl", p.custom_outbound_kdl},
            {"policy_group", JsonObject{
                {"strategy", p.policy_group.strategy},
                {"member_ids", json_from_string_vec(p.policy_group.member_ids)},
                {"dynamic_sub_id", p.policy_group.dynamic_sub_id},
                {"include_regex", p.policy_group.include_regex},
                {"exclude_regex", p.policy_group.exclude_regex},
                {"probe_url", p.policy_group.probe_url},
                {"probe_interval_ms", p.policy_group.probe_interval_ms},
                {"tolerance_ms", p.policy_group.tolerance_ms},
            }},
            {"proxy_chain", JsonObject{{"hop_ids", json_from_string_vec(p.proxy_chain.hop_ids)}}},
            {"full_custom_kdl", p.full_custom_kdl},
        };
    }

    inline auto profile_from_json(JsonObject const& o) -> WorkspaceProfileItem {
        WorkspaceProfileItem p{};
        p.id = json_get_string(o, "id");
        p.remarks = json_get_string(o, "remarks");
        p.subscription_id = json_get_string(o, "subscription_id");
        p.is_from_sub = json_get_bool(o, "is_from_sub");
        p.kind = json_get_string(o, "kind", "node");
        if (auto const* v = json_find(o, "node"); v && v->is_object()) p.node = node_from_json(std::get<JsonObject>(v->data));
        p.custom_outbound_kdl = json_get_string(o, "custom_outbound_kdl");
        if (auto const* v = json_find(o, "policy_group"); v && v->is_object()) {
            auto const& g = std::get<JsonObject>(v->data);
            p.policy_group = {
                json_get_string(g, "strategy", "selector"),
                json_get_string_vec(g, "member_ids"),
                json_get_string(g, "dynamic_sub_id"),
                json_get_string(g, "include_regex"),
                json_get_string(g, "exclude_regex"),
                json_get_string(g, "probe_url", "https://www.gstatic.com/generate_204"),
                json_get_i64(g, "probe_interval_ms", 300000),
                json_get_i64(g, "tolerance_ms", 100),
            };
        }
        if (auto const* v = json_find(o, "proxy_chain"); v && v->is_object()) {
            p.proxy_chain.hop_ids = json_get_string_vec(std::get<JsonObject>(v->data), "hop_ids");
        }
        p.full_custom_kdl = json_get_string(o, "full_custom_kdl");
        return p;
    }

    inline auto sub_to_json(SubscriptionItem const& s) -> JsonValue {
        return JsonObject{
            {"id", s.id},
            {"remarks", s.remarks},
            {"url", s.url},
            {"more_urls", json_from_string_vec(s.more_urls)},
            {"enabled", s.enabled},
            {"auto_update_minutes", s.auto_update_minutes},
            {"user_agent", s.user_agent},
            {"request_headers", json_from_string_map(s.request_headers)},
            {"include_regex", s.include_regex},
            {"exclude_regex", s.exclude_regex},
            {"prev_profile_id", s.prev_profile_id},
            {"next_profile_id", s.next_profile_id},
            {"updated_at_ms", s.updated_at_ms},
            {"usage", JsonObject{
                {"upload_bytes", s.usage.upload_bytes},
                {"download_bytes", s.usage.download_bytes},
                {"total_bytes", s.usage.total_bytes},
                {"expire_unix_sec", s.usage.expire_unix_sec},
                {"profile_title", s.usage.profile_title},
                {"web_page_url", s.usage.web_page_url},
                {"support_url", s.usage.support_url},
            }},
        };
    }

    inline auto sub_from_json(JsonObject const& o) -> SubscriptionItem {
        SubscriptionItem s{};
        s.id = json_get_string(o, "id");
        s.remarks = json_get_string(o, "remarks");
        s.url = json_get_string(o, "url");
        s.more_urls = json_get_string_vec(o, "more_urls");
        s.enabled = json_get_bool(o, "enabled", true);
        s.auto_update_minutes = json_get_i64(o, "auto_update_minutes", 0);
        s.user_agent = json_get_string(o, "user_agent");
        s.request_headers = json_get_string_map(o, "request_headers");
        s.include_regex = json_get_string(o, "include_regex");
        s.exclude_regex = json_get_string(o, "exclude_regex");
        s.prev_profile_id = json_get_string(o, "prev_profile_id");
        s.next_profile_id = json_get_string(o, "next_profile_id");
        s.updated_at_ms = json_get_i64(o, "updated_at_ms", 0);
        if (auto const* v = json_find(o, "usage"); v && v->is_object()) {
            auto const& u = std::get<JsonObject>(v->data);
            s.usage = {
                json_get_i64(u, "upload_bytes"), json_get_i64(u, "download_bytes"),
                json_get_i64(u, "total_bytes"), json_get_i64(u, "expire_unix_sec"),
                json_get_string(u, "profile_title"), json_get_string(u, "web_page_url"), json_get_string(u, "support_url"),
            };
        }
        return s;
    }

    inline auto routing_to_json(RoutingProfile const& rp) -> JsonValue {
        JsonArray rules;
        rules.reserve(rp.rules.size());
        for (auto const& r : rp.rules) {
            rules.emplace_back(JsonObject{
                {"id", r.id}, {"enabled", r.enabled}, {"locked", r.locked}, {"scope", r.scope},
                {"target_type", r.target_type}, {"target_profile_id", r.target_profile_id},
                {"domains", json_from_string_vec(r.domains)}, {"ips", json_from_string_vec(r.ips)},
                {"rule_sets", json_from_string_vec(r.rule_sets)}, {"ports", json_from_string_vec(r.ports)},
                {"networks", json_from_string_vec(r.networks)}, {"protocols", json_from_string_vec(r.protocols)},
                {"desktop_process", json_from_string_vec(r.desktop_process)},
                {"android_packages", json_from_string_vec(r.android_packages)},
                {"tls_fragment", r.tls_fragment},
            });
        }
        return JsonObject{
            {"id", rp.id}, {"name", rp.name}, {"is_active", rp.is_active},
            {"domain_strategy", rp.domain_strategy}, {"default_outbound", rp.default_outbound},
            {"rules", JsonValue(std::move(rules))},
        };
    }

    inline auto routing_from_json(JsonObject const& o) -> RoutingProfile {
        RoutingProfile rp{};
        rp.id = json_get_string(o, "id");
        rp.name = json_get_string(o, "name");
        rp.is_active = json_get_bool(o, "is_active");
        rp.domain_strategy = json_get_string(o, "domain_strategy", "as-is");
        rp.default_outbound = json_get_string(o, "default_outbound", "proxy");
        if (auto const* arr = json_find(o, "rules"); arr && arr->is_array()) {
            for (auto const& elem : std::get<JsonArray>(arr->data)) {
                if (!elem.is_object()) continue;
                auto const& r = std::get<JsonObject>(elem.data);
                rp.rules.push_back({
                    json_get_string(r, "id"), json_get_bool(r, "enabled", true), json_get_bool(r, "locked", false),
                    json_get_string(r, "scope", "both"), json_get_string(r, "target_type", "proxy"),
                    json_get_string(r, "target_profile_id"), json_get_string_vec(r, "domains"),
                    json_get_string_vec(r, "ips"), json_get_string_vec(r, "rule_sets"), json_get_string_vec(r, "ports"),
                    json_get_string_vec(r, "networks"), json_get_string_vec(r, "protocols"),
                    json_get_string_vec(r, "desktop_process"), json_get_string_vec(r, "android_packages"),
                    json_get_bool(r, "tls_fragment", false),
                });
            }
        }
        return rp;
    }

    inline auto dns_to_json(DnsConfig const& d) -> JsonValue {
        return JsonObject{
            {"mode", d.mode},
            {"simple", JsonObject{
                {"bootstrap_dns", d.simple.bootstrap_dns},
                {"direct_dns", json_from_string_vec(d.simple.direct_dns)},
                {"remote_dns", json_from_string_vec(d.simple.remote_dns)},
                {"parallel_query", d.simple.parallel_query},
                {"direct_expected_rule_sets", json_from_string_vec(d.simple.direct_expected_rule_sets)},
                {"fake_ip_enabled", d.simple.fake_ip_enabled},
                {"fake_ip_v4_pool", d.simple.fake_ip_v4_pool},
                {"fake_ip_v6_pool", d.simple.fake_ip_v6_pool},
                {"fake_ip_global", d.simple.fake_ip_global},
                {"block_aaaa", d.simple.block_aaaa},
                {"block_svcb_https", d.simple.block_svcb_https},
                {"serve_stale_seconds", d.simple.serve_stale_seconds},
                {"use_system_hosts", d.simple.use_system_hosts},
                {"hosts", json_from_string_map(d.simple.hosts)},
                {"strategy", d.simple.strategy},
            }},
            {"raw_kdl", d.raw_kdl},
        };
    }

    inline auto dns_from_json(JsonObject const& o) -> DnsConfig {
        DnsConfig d{};
        d.mode = json_get_string(o, "mode", "simple");
        d.raw_kdl = json_get_string(o, "raw_kdl");
        if (auto const* v = json_find(o, "simple"); v && v->is_object()) {
            auto const& s = std::get<JsonObject>(v->data);
            d.simple.bootstrap_dns = json_get_string(s, "bootstrap_dns", "223.5.5.5");
            if (auto vec = json_get_string_vec(s, "direct_dns"); !vec.empty()) d.simple.direct_dns = std::move(vec);
            if (auto vec = json_get_string_vec(s, "remote_dns"); !vec.empty()) d.simple.remote_dns = std::move(vec);
            d.simple.parallel_query = json_get_bool(s, "parallel_query", false);
            d.simple.direct_expected_rule_sets = json_get_string_vec(s, "direct_expected_rule_sets");
            d.simple.fake_ip_enabled = json_get_bool(s, "fake_ip_enabled", false);
            d.simple.fake_ip_v4_pool = json_get_string(s, "fake_ip_v4_pool", "198.18.0.0/16");
            d.simple.fake_ip_v6_pool = json_get_string(s, "fake_ip_v6_pool", "fc00::/18");
            d.simple.fake_ip_global = json_get_bool(s, "fake_ip_global", false);
            d.simple.block_aaaa = json_get_bool(s, "block_aaaa", false);
            d.simple.block_svcb_https = json_get_bool(s, "block_svcb_https", false);
            d.simple.serve_stale_seconds = json_get_i64(s, "serve_stale_seconds", 0);
            d.simple.use_system_hosts = json_get_bool(s, "use_system_hosts", true);
            d.simple.hosts = json_get_string_map(s, "hosts");
            d.simple.strategy = json_get_string(s, "strategy", "prefer_ipv4");
        }
        return d;
    }

    inline auto decode_base64_str(std::string_view input) -> std::optional<std::string> {
        auto val_of = [](unsigned char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
            if (c >= '0' && c <= '9') return 52 + (c - '0');
            if (c == '+' || c == '-') return 62;
            if (c == '/' || c == '_') return 63;
            return -1;
        };
        std::string out;
        std::uint32_t acc = 0;
        int bits = 0;
        for (unsigned char c : input) {
            if (std::isspace(c) || c == '=') continue;
            int v = val_of(c);
            if (v < 0) return std::nullopt;
            acc = (acc << 6) | static_cast<std::uint32_t>(v);
            bits += 6;
            if (bits >= 8) { bits -= 8; out.push_back(static_cast<char>((acc >> bits) & 0xFFu)); }
        }
        return out;
    }

    inline auto percent_decode_str(std::string_view input) -> std::string {
        auto hex = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            return -1;
        };
        std::string out;
        out.reserve(input.size());
        for (std::size_t i = 0; i < input.size(); ++i) {
            if (input[i] == '%' && i + 2 < input.size()) {
                int hi = hex(input[i + 1]), lo = hex(input[i + 2]);
                if (hi >= 0 && lo >= 0) { out.push_back(static_cast<char>((hi << 4) | lo)); i += 2; continue; }
            }
            out.push_back(input[i]);
        }
        return out;
    }
}
