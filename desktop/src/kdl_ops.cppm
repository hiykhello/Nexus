export module desktop.kdl_ops;

import std;

export namespace desktop {
    struct InboundEndpointSpec {
        std::string protocol;
        bool enabled = false;
        std::string host = "127.0.0.1";
        std::uint16_t port = 0;
    };

    struct CoexistingInbounds {
        InboundEndpointSpec mixed{"mixed", false, "127.0.0.1", 7890};
        InboundEndpointSpec socks5{"socks5", false, "127.0.0.1", 1080};
        InboundEndpointSpec http{"http", false, "127.0.0.1", 8080};
    };

    [[nodiscard]] auto parse_port_u16(std::string_view text) -> std::optional<std::uint16_t>;

    [[nodiscard]] auto parse_inbound_endpoints(std::string_view kdl) -> CoexistingInbounds;

    [[nodiscard]] auto upsert_managed_inbound(std::string_view kdl,
                                              std::string_view proto,
                                              bool enabled,
                                              std::string_view host,
                                              std::uint16_t port) -> std::pair<bool, std::string>;

    [[nodiscard]] auto select_system_proxy_endpoint(CoexistingInbounds const& inb)
        -> std::optional<std::pair<std::string, std::uint16_t>>;

    [[nodiscard]] auto apply_outbound_mode(std::string_view kdl,
                                           std::string_view mode,
                                           std::string_view proxy_group = "proxy") -> std::pair<bool, std::string>;

    [[nodiscard]] auto detect_outbound_mode(std::string_view kdl) -> std::string;

    [[nodiscard]] auto escape_kdl_string(std::string_view text) -> std::string;

    [[nodiscard]] auto merge_raw_kdl_snippet(std::string_view kdl, std::string_view snippet) -> std::string;

    // Inserts a routing `rule ...` block inside `routing { tcp-program { ... } }` (creating blocks if absent).
    [[nodiscard]] auto insert_route_rule_kdl(std::string_view kdl, std::string_view rule_block) -> std::pair<bool, std::string>;

    // Inserts a DNS `rule ...` line inside an existing top-level `dns { ... }` block (or creates one if absent).
    [[nodiscard]] auto insert_dns_rule_kdl(std::string_view kdl, std::string_view rule_line) -> std::pair<bool, std::string>;
}
