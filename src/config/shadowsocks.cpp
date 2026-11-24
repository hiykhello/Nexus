// Shadowsocks-2022 outbound configuration parser & validator implementation.
module config;
import std;
import glaze;
import config.kdl_common;
import config.routing;

namespace config {
    using namespace config::kdl;
    auto parse_tcp_dial_option(g::KdlNode const&, TcpSocketOptions&) -> std::expected<bool, std::string>;
    auto parse_outbound_multiplex(g::KdlNode const&) -> std::expected<MultiplexConfig, std::string>;
    auto dns_ipv4(std::string_view) -> std::optional<std::array<std::uint8_t, 4>>;
    auto dns_hostname(std::string_view) -> bool;

    auto shadowsocks_outbound(Node const& node) -> std::expected<ShadowsocksOutbound, std::string> {
        ShadowsocksOutbound result;
        bool server = false, method = false, key = false, uot = false, timeout_seen = false;
        for (auto const& child : node.children) {
            if (child.name == "server") {
                auto host = text_property(child, "host");
                auto value = property(child, "port");
                auto port = value ? integer(*value) : std::nullopt;
                if (server || child.tag || !child.arguments.empty() || !child.children.empty() || child.properties.size() != 2 ||
                    !host || !endpoint_name(*host) || !port || !*port || *port > 65535)
                    return error("shadowsocks requires one server with host and port 1..65535");
                result.host = *host;
                result.port = static_cast<std::uint16_t>(*port);
                server = true;
            } else if (child.name == "connect-timeout-ms") {
                auto value = connect_timeout(child);
                if (timeout_seen || !value) return error("invalid shadowsocks connect-timeout-ms");
                result.connect_timeout_ms = *value;
                timeout_seen = true;
            } else if (child.name == "detour") {
                auto value = scalar(child);
                if (result.detour || !value || !valid_name(*value)) return error("invalid shadowsocks detour");
                result.detour = *value;
            } else if (child.name == "bootstrap-resolver" || child.name == "domain-resolver") {
                auto value = scalar(child);
                if (result.bootstrap_resolver || !value || !valid_name(*value)) return error("invalid shadowsocks bootstrap-resolver");
                result.bootstrap_resolver = *value;
            } else if (child.name == "method") {
                auto value = scalar(child);
                if (method || !value || (*value != "2022-blake3-aes-128-gcm" && *value != "2022-blake3-aes-256-gcm" &&
                    *value != "2022-blake3-chacha20-poly1305"))
                    return error("unsupported shadowsocks method");
                result.method = *value;
                method = true;
            } else if (child.name == "udp-over-tcp") {
                auto value = scalar(child);
                if (uot || !value || *value != "v2") return error("shadowsocks udp-over-tcp requires v2");
                result.udp_over_tcp = true;
                uot = true;
            } else if (child.name == "udp-mode") {
                auto value = scalar(child);
                if (result.udp_native || !value || *value != "native") return error("shadowsocks udp-mode requires native");
                result.udp_native = true;
            } else if (child.name == "key-file") {
                auto value = scalar(child);
                if (key || !value || !absolute_path(*value)) return error("shadowsocks key-file must be absolute");
                result.key_file = *value;
                key = true;
            } else if (child.name == "identity-key-file") {
                auto value = scalar(child);
                if (!value || !absolute_path(*value) || result.identity_key_files.size() >= 8 ||
                    std::ranges::find(result.identity_key_files, *value) != result.identity_key_files.end())
                    return error("invalid or duplicate shadowsocks identity-key-file");
                result.identity_key_files.push_back(*value);
            } else if (child.name == "tcp-fast-open") {
                if (result.tcp_fast_open || child.tag || !child.properties.empty() || !child.children.empty() || child.arguments.size() != 1 ||
                    child.arguments[0].tag || !std::holds_alternative<bool>(child.arguments[0].data))
                    return error("tcp-fast-open requires one boolean and cannot repeat");
                result.tcp_fast_open = std::get<bool>(child.arguments[0].data);
            } else if (child.name == "multiplex") {
                if (result.multiplex) return error("duplicate shadowsocks multiplex");
                auto parsed = parse_outbound_multiplex(child);
                if (!parsed) return std::unexpected(parsed.error());
                result.multiplex = std::move(*parsed);
            } else {
                auto option = parse_tcp_dial_option(child, result.tcp_options);
                if (!option) return std::unexpected(option.error());
                if (!*option) return error("unsupported shadowsocks node: " + child.name);
            }
        }
        if (!server || !method || !key) return error("shadowsocks requires server, method and key-file");
        if (result.udp_native && result.udp_over_tcp) return error("shadowsocks udp-mode and udp-over-tcp are mutually exclusive");
        if (result.method == "2022-blake3-chacha20-poly1305" && !result.identity_key_files.empty())
            return error("shadowsocks identity keys require an AES method");
        if (result.detour && result.tcp_fast_open) return error("tcp-fast-open belongs to the physical outbound, not a layered node");
        return result;
    }

    auto validate_shadowsocks(Config& result, std::string const& direct,
        std::optional<std::string> const& block, routing_detail::Route const& route) -> std::expected<void, std::string> {
        for (std::size_t i = 0; i < result.shadowsocks_outbounds.size(); ++i) {
            auto& outbound = result.shadowsocks_outbounds[i].config;
            if (outbound.bootstrap_resolver) {
                if (!result.dns || !dns_hostname(outbound.host) || dns_ipv4(outbound.host))
                    return error("shadowsocks bootstrap-resolver requires DNS configuration and a domain server host");
                outbound.bootstrap_index = result.dns->resolver_index(*outbound.bootstrap_resolver);
                if (!outbound.bootstrap_index)
                    return error("shadowsocks domain-resolver references unknown DNS server or view: " + *outbound.bootstrap_resolver);
            }
            auto const& name = result.shadowsocks_outbounds[i].name;
            if (name == direct || (block && name == *block) ||
                std::ranges::any_of(result.vless_outbounds, [&](auto const& other) { return other.name == name; }) ||
                std::ranges::any_of(std::span(result.shadowsocks_outbounds).first(i), [&](auto const& other) { return other.name == name; }))
                return error("outbound names must be unique");
            if (!routing_detail::referenced_outbound(result, route, name))
                return error("shadowsocks must be referenced by routing or a detour");
        }
        return {};
    }
}
