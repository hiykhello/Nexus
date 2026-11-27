// Named HTTP client configuration parser implementation.
module config;
import std;
import glaze;
import config.kdl_common;
import http.header;

namespace config {
    using namespace config::kdl;

    auto add_http_client_header(Node const& field, NamedHttpClient& client, std::size_t& bytes) -> bool {
        if (field.tag || !field.properties.empty() || !field.children.empty() ||
            field.arguments.size() != 2) return false;
        auto* name = kdl::string(field.arguments[0]);
        auto* value = kdl::string(field.arguments[1]);
        if (!name || !value || name->empty() || name->size() > 128 || value->size() > 1024 ||
            !std::ranges::all_of(*name, http::header_token) || !http::valid_header_field_value(*value))
            return false;

        auto normalized = *name;
        std::ranges::transform(normalized, normalized.begin(), [](char c) {
            return c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
        });
        constexpr std::array<std::string_view, 14> reserved{
            "accept-encoding", "connection", "content-length", "expect", "host", "http2-settings",
            "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer",
            "transfer-encoding", "upgrade"
        };
        if (std::ranges::find(reserved, normalized) != reserved.end() ||
            std::ranges::any_of(client.headers, [&](auto const& header) {
                return header.first == normalized;
            })) return false;

        auto trimmed = http::trim_header_ows(*value);
        auto charge = normalized.size() + trimmed.size() + 32;
        if (charge > 16384 - bytes) return false;
        bytes += charge;
        client.headers.emplace_back(std::move(normalized), trimmed);
        return true;
    }

    auto parse_http_clients(Node const& group) -> std::expected<std::vector<NamedHttpClient>, std::string> {
        if (group.tag || !group.arguments.empty() || !group.properties.empty() ||
            group.children.empty() || group.children.size() > 4096) return error("invalid http-clients block");
        std::vector<NamedHttpClient> clients;
        clients.reserve(group.children.size());
        std::unordered_set<std::string_view> seen_names;
        seen_names.reserve(group.children.size());
        for (auto const& node : group.children) {
            if (node.tag || !node.arguments.empty() || !node.properties.empty() || !valid_name(node.name) ||
                !seen_names.insert(node.name).second)
                return error("invalid or duplicate HTTP client name");
            NamedHttpClient client{.name = node.name};
            std::vector<std::string_view> fields;
            std::size_t header_bytes = 0;
            for (auto const& field : node.children) {
                if (field.name == "header") {
                    if (!add_http_client_header(field, client, header_bytes))
                        return error("invalid, reserved or duplicate HTTP client request header");
                    continue;
                }
                if (std::ranges::find(fields, field.name) != fields.end()) return error("duplicate HTTP client field");
                fields.push_back(field.name);
                if (field.name == "max-redirects") {
                    auto value = kdl::integer(field);
                    if (!value || *value > 5) return error("HTTP client max-redirects must be 0..5");
                    client.max_redirects = static_cast<unsigned>(*value);
                    continue;
                }
                if (field.name == "disable-path-mtu-discovery") {
                    auto value = kdl::boolean(field);
                    if (!value) return error("invalid HTTP client disable-path-mtu-discovery");
                    client.disable_path_mtu_discovery = *value;
                    continue;
                }
                if (field.name == "timeout-ms" || field.name == "max-response-bytes" ||
                    field.name == "max-udp-payload-size" || field.name == "record-size-limit") {
                    auto value = field.arguments.size() == 1 ? integer(field.arguments.front()) : std::nullopt;
                    if (field.tag || !field.properties.empty() || !field.children.empty() || !value || !*value)
                        return error("invalid HTTP client limit");
                    if (field.name == "timeout-ms" && *value <= 3600000) client.timeout_ms = static_cast<std::uint32_t>(*value);
                    else if (field.name == "max-response-bytes" && *value <= 8 * 1024 * 1024) client.max_bytes = static_cast<std::size_t>(*value);
                    else if (field.name == "max-udp-payload-size" && *value >= 1200 && *value <= 1500) client.max_udp_payload = *value;
                    else if (field.name == "record-size-limit" && *value >= 64 && *value <= 16385)
                        client.record_size_limit = static_cast<std::uint16_t>(*value);
                    else return error("HTTP client limit outside supported range");
                    continue;
                }
                auto value = scalar(field);
                if (!value) return error("invalid HTTP client field");
                if (field.name == "outbound" && valid_name(*value)) client.outbound = *value;
                else if (field.name == "domain-resolver" && valid_name(*value)) client.resolver = *value;
                else if (field.name == "ca-file" && absolute_path(*value)) client.ca_file = *value;
                else if (field.name == "ech-config-file" && absolute_path(*value)) client.ech_config_file = *value;
                else if (field.name == "fingerprint") {
                    auto fingerprint = parse_tls_fingerprint(*value);
                    if (!fingerprint) return error("invalid HTTP client TLS fingerprint");
                    client.fingerprint = *fingerprint;
                } else if (field.name == "key-exchange") {
                    if (*value == "x25519") client.key_exchange = TlsKeyExchange::x25519;
                    else if (*value == "x25519-mlkem768") client.key_exchange = TlsKeyExchange::x25519_mlkem768;
                    else if (*value == "x25519-mlkem768-only") client.key_exchange = TlsKeyExchange::x25519_mlkem768_only;
                    else return error("invalid HTTP client TLS key exchange");
                } else if (field.name == "protocol" && *value == "http/1.1") client.protocol = HttpProtocol::http1;
                else if (field.name == "protocol" && *value == "h2") client.protocol = HttpProtocol::http2;
                else if (field.name == "protocol" && *value == "h3") client.protocol = HttpProtocol::http3;
                else if (field.name == "protocol" && *value == "auto") client.protocol = HttpProtocol::automatic;
                else return error("invalid HTTP client field: " + field.name);
            }
            if (client.outbound.empty())
                return error("HTTP client requires outbound");
            if (client.protocol != HttpProtocol::http3 && (!client.ech_config_file.empty() || client.max_udp_payload))
                return error("HTTP client UDP payload and ECH require protocol h3");
            if (client.disable_path_mtu_discovery && client.protocol != HttpProtocol::http3)
                return error("HTTP client disable-path-mtu-discovery requires protocol h3");
            auto tcp = client.protocol == HttpProtocol::http1 || client.protocol == HttpProtocol::http2;
            if (client.record_size_limit && !tcp)
                return error("HTTP client record-size-limit requires protocol http/1.1 or h2");
            if (client.fingerprint == TlsFingerprint::tls12 &&
                (!tcp || client.key_exchange != TlsKeyExchange::x25519 || client.record_size_limit))
                return error("HTTP client TLS 1.2 requires explicit HTTP/1.1 or h2, X25519 and the default record size");
            clients.push_back(std::move(client));
        }
        return clients;
    }
}
