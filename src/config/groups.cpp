// Outbound group & KDL block normalization parser implementation.
module config;
import std;
import glaze;
import config.kdl_common;
import config.desugar;

namespace config {
    using namespace config::kdl;

    auto normalize_groups(g::KdlDocument& document) -> std::expected<void, std::string> {
        auto typed = [](Node& group, std::string_view canonical, std::initializer_list<std::string_view> allowed)
            -> std::expected<void, std::string> {
            for (auto& child : group.children) {
                if (child.name == canonical) continue;
                if (std::ranges::find(allowed, child.name) == allowed.end() || property(child, "type"))
                    return error("unsupported type in " + group.name);
                if (group.name == "outbounds" && (child.name == "direct" || child.name == "block") &&
                    child.arguments.empty() && child.properties.empty() && !child.tag)
                    child.arguments.push_back({child.name, {}});
                child.properties.push_back({"type", {child.name, {}}});
                child.name = canonical;
            }
            return {};
        };
        for (auto& node : document) {
            if (node.name == "inbounds" || node.name == "outbounds") {
                auto result = node.name == "inbounds" ?
                    typed(node, "inbound", {"socks5", "mixed", "http", "fixed-tcp", "fixed-udp", "vless", "shadowsocks", "trojan", "anytls", "hysteria2", "snell", "masque", "redirect", "tproxy", "tun", "naive", "shadowtls", "tuic"}) :
                    typed(node, "outbound", {"direct", "block", "vless", "shadowsocks", "trojan", "anytls", "hysteria2", "snell", "socks5", "socks4", "socks4a", "http-connect", "selector", "fallback", "url-test", "load-balance", "naive", "shadowtls", "tuic", "masque", "wireguard", "ssh", "openvpn", "openconnect", "tailscale"});
                if (!result) return result;
                if (auto ok = desugar_detail::desugar_endpoints(node); !ok) return ok;
                if (node.name == "outbounds")
                    for (auto& child : node.children)
                        if (auto ok = desugar_detail::desugar_group_members(child); !ok) return ok;
            } else if (node.name == "routing") {
                if (auto ok = desugar_detail::desugar_routing(node); !ok) return ok;
            } else if (node.name == "dns") {
                bool rules_seen = false;
                bool rulesets_seen = false;
                std::vector<Node> children;
                for (auto& child : node.children) {
                    if (child.name == "servers") {
                        if (auto result = typed(child, "server", {"local", "hosts", "udp", "tcp", "tls", "https", "quic", "https3", "dhcp", "mdns"}); !result) return result;
                        children.push_back(std::move(child));
                    } else if (child.name == "rulesets" || child.name == "rule-sets") {
                        if (auto ok = desugar_detail::desugar_rulesets_block(child, rulesets_seen, children); !ok) return ok;
                    } else if (child.name == "rule-set") {
                        if (auto ok = desugar_detail::desugar_rule_set_fields(child); !ok) return ok;
                        children.push_back(std::move(child));
                    } else if (child.name == "rules") {
                        if (rules_seen || child.tag || !child.arguments.empty() || !child.properties.empty())
                            return error("invalid or duplicate rules block");
                        rules_seen = true;
                        for (auto& rule : child.children) {
                            if (rule.name != "-") return error("rules accepts only - nodes");
                            if (auto ok = desugar_detail::desugar_dns_rule(rule); !ok) return ok;
                            rule.name = "rule";
                            children.push_back(std::move(rule));
                        }
                    } else if (child.name == "rule") {
                        return error("bare DNS rule is removed; use dns { rules { - ... } }");
                    } else {
                        children.push_back(std::move(child));
                    }
                }
                node.children = std::move(children);
            }
        }
        return {};
    }

    auto parse_probe_status_item(g::KdlValue const& value) -> std::expected<OutboundStatusRange, std::string> {
        if (value.tag) return error("invalid outbound probe-expected-status");
        auto parse_code = [](std::string_view text) -> std::optional<std::uint16_t> {
            std::uint16_t code = 0;
            auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), code);
            if (ec != std::errc{} || end != text.data() + text.size() || code < 100 || code > 599) return {};
            return code;
        };
        if (auto n = std::get_if<std::uint64_t>(&value.data)) {
            if (*n < 100 || *n > 599) return error("outbound probe-expected-status must be 100..599");
            auto c = static_cast<std::uint16_t>(*n);
            return OutboundStatusRange{c, c};
        }
        if (auto n = std::get_if<std::int64_t>(&value.data)) {
            if (*n < 100 || *n > 599) return error("outbound probe-expected-status must be 100..599");
            auto c = static_cast<std::uint16_t>(*n);
            return OutboundStatusRange{c, c};
        }
        if (auto s = std::get_if<std::string>(&value.data)) {
            auto sv = std::string_view(*s);
            if (auto sep = sv.find(".."); sep != sv.npos) {
                auto lo = parse_code(sv.substr(0, sep));
                auto hi = parse_code(sv.substr(sep + 2));
                if (!lo || !hi || *lo > *hi) return error("invalid outbound probe-expected-status range");
                return OutboundStatusRange{*lo, *hi};
            }
            auto single = parse_code(sv);
            if (!single) return error("invalid outbound probe-expected-status value");
            return OutboundStatusRange{*single, *single};
        }
        return error("invalid outbound probe-expected-status type");
    }

    auto parse_outbound_selector(g::KdlNode const& node, std::string_view name, std::string_view type)
        -> std::expected<OutboundSelector, std::string> {
        OutboundSelector result;
        result.name = name;
        if (type == "fallback") result.mode = OutboundGroupMode::fallback;
        if (type == "url-test") result.mode = OutboundGroupMode::url_test;
        if (type == "load-balance") result.mode = OutboundGroupMode::load_balance;
        auto automatic = result.mode == OutboundGroupMode::fallback || result.mode == OutboundGroupMode::url_test;
        auto can_probe = automatic || result.mode == OutboundGroupMode::load_balance;
        std::optional<std::uint64_t> interval, timeout, tolerance, idle_timeout, concurrency;
        bool mode_seen = false, status_seen = false, interrupt_seen = false;
        std::unordered_set<std::string_view> seen_members, seen_providers;
        for (auto const& child : node.children) {
            if (child.name == "member" || (result.mode == OutboundGroupMode::select && child.name == "selected")) {
                auto value = scalar(child);
                if (!value || !valid_name(*value)) return error("invalid outbound group member");
                if (child.name == "member" && result.members.size() < max_tunnel_outbounds &&
                    seen_members.insert(*value).second) result.members.push_back(*value);
                else if (child.name == "selected" && result.selected.empty()) result.selected = *value;
                else return error("invalid or duplicate selector field");
            } else if (child.name == "use") {
                auto value = scalar(child);
                if (!value || !valid_name(*value)) return error("invalid outbound group provider");
                if (result.use_providers.size() < max_tunnel_outbounds &&
                    seen_providers.insert(*value).second)
                    result.use_providers.push_back(*value);
                else return error("duplicate or excessive outbound group provider");
            } else if (child.name == "interrupt-exist-connections" && !interrupt_seen) {
                auto enabled = boolean(child);
                if (!enabled) return error("invalid outbound group interrupt-exist-connections");
                result.interrupt_exist_connections = *enabled;
                interrupt_seen = true;
            } else if (can_probe && child.name == "probe-url" && result.probe.url.empty()) {
                auto url = scalar(child);
                if (!url || (!url->starts_with("http://") && !url->starts_with("https://")) || url->size() > 1024)
                    return error("outbound probe-url requires an HTTP or HTTPS URL");
                result.probe.url = *url;
            } else if (can_probe && child.name == "probe-mode" && !mode_seen) {
                auto mode = scalar(child);
                if (!mode) return error("invalid outbound probe-mode");
                if (*mode == "http") result.probe.mode = OutboundProbeMode::http;
                else if (*mode == "h2-ping") result.probe.mode = OutboundProbeMode::h2_ping;
                else return error("outbound probe-mode must be http or h2-ping");
                mode_seen = true;
            } else if (can_probe && child.name == "probe-expected-status" && !status_seen) {
                if (child.tag || !child.properties.empty() || !child.children.empty() ||
                    child.arguments.empty() || child.arguments.size() > 512)
                    return error("invalid outbound probe-expected-status");
                for (auto const& arg : child.arguments) {
                    auto parsed = parse_probe_status_item(arg);
                    if (!parsed) return std::unexpected(parsed.error());
                    result.probe.expected_status.push_back(*parsed);
                }
                status_seen = true;
            } else if (can_probe && child.name == "probe-ca-file" && result.probe.ca_file.empty()) {
                auto ca = scalar(child);
                if (!ca || ca->empty() || ca->front() != '/' || ca->size() > 1024 || ca->contains('\0'))
                    return error("invalid outbound probe-ca-file");
                result.probe.ca_file = *ca;
            } else if (can_probe && child.name == "probe-server-name" && result.probe.server_name.empty()) {
                auto sni = scalar(child);
                if (!sni || sni->empty() || sni->size() > 253 || sni->contains('\0'))
                    return error("invalid outbound probe-server-name");
                result.probe.server_name = *sni;
            } else if (can_probe && child.name == "probe-interval-ms" && !interval) {
                interval = integer(child);
                if (!interval || *interval < 500 || *interval > 3600000)
                    return error("invalid outbound probe-interval-ms");
            } else if (can_probe && child.name == "probe-timeout-ms" && !timeout) {
                timeout = integer(child);
                if (!timeout || *timeout < 100 || *timeout > 10000)
                    return error("invalid outbound probe-timeout-ms");
            } else if (can_probe && child.name == "idle-timeout-ms" && !idle_timeout) {
                idle_timeout = integer(child);
                if (!idle_timeout || *idle_timeout > 86400000)
                    return error("invalid outbound probe idle-timeout-ms");
            } else if (can_probe && child.name == "probe-concurrency" && !concurrency) {
                concurrency = integer(child);
                if (!concurrency || *concurrency < 1 || *concurrency > 1024)
                    return error("invalid outbound probe-concurrency");
            } else if (result.mode == OutboundGroupMode::url_test && child.name == "tolerance-ms" && !tolerance) {
                tolerance = integer(child);
                if (!tolerance || *tolerance > 10000) return error("invalid url-test tolerance-ms");
            } else return error("invalid or duplicate outbound group field");
        }
        if (result.members.empty() && result.use_providers.empty())
            return error("selector requires at least one member or provider");
        if (result.selected.empty() && !result.members.empty()) result.selected = result.members.front();
        if (!result.selected.empty() && !result.members.empty() && !seen_members.contains(result.selected))
            return error("selector selected outbound must be a member");
        if (automatic && result.probe.url.empty()) return error("outbound group requires probe-url");
        if (result.probe.url.empty() && (mode_seen || status_seen || !result.probe.ca_file.empty() || !result.probe.server_name.empty() || interval || timeout || idle_timeout || concurrency))
            return error("outbound probe options require probe-url");
        if (!result.probe.url.empty() && result.probe.mode == OutboundProbeMode::h2_ping && !result.probe.expected_status.empty())
            return error("outbound probe-expected-status is only valid with http probe-mode");
        if (!result.probe.url.empty() && (!result.probe.ca_file.empty() || !result.probe.server_name.empty()) &&
            !result.probe.url.starts_with("https://"))
            return error("outbound probe TLS options require an https:// probe-url");
        if (interval) result.probe.interval_ms = static_cast<std::uint32_t>(*interval);
        if (timeout) result.probe.timeout_ms = static_cast<std::uint32_t>(*timeout);
        if (tolerance) result.probe.tolerance_ms = static_cast<std::uint32_t>(*tolerance);
        if (idle_timeout) result.probe.idle_timeout_ms = static_cast<std::uint32_t>(*idle_timeout);
        if (concurrency) result.probe.probe_concurrency = static_cast<std::uint16_t>(*concurrency);
        return result;
    }
}
