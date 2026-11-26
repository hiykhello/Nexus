export module desktop.kdl_ops;

import std;

export namespace desktop {
    struct InboundEndpointSpec {
        bool enabled = false;
        std::string host = "127.0.0.1";
        std::uint16_t port = 0;
    };

    struct CoexistingInbounds {
        InboundEndpointSpec mixed{false, "127.0.0.1", 7890};
        InboundEndpointSpec socks5{false, "127.0.0.1", 1080};
        InboundEndpointSpec http{false, "127.0.0.1", 8080};
    };

    [[nodiscard]] auto parse_port_u16(std::string_view text) -> std::optional<std::uint16_t>;

    [[nodiscard]] auto parse_inbound_endpoints(std::string_view kdl) -> CoexistingInbounds;

    [[nodiscard]] auto select_system_proxy_endpoint(CoexistingInbounds const& inb)
        -> std::optional<std::pair<std::string, std::uint16_t>>;

    [[nodiscard]] auto merge_raw_kdl_snippet(std::string_view kdl, std::string_view snippet) -> std::string;

    // Inserts a KDL rule block into raw KDL routing { tcp-program { ... } } (raw KDL rule editor).
    [[nodiscard]] auto insert_route_rule_kdl(std::string_view kdl, std::string_view rule_block)
        -> std::pair<bool, std::string>;

    // Inserts a KDL rule line into raw KDL top-level dns { ... } (raw KDL DNS rule editor).
    [[nodiscard]] auto insert_dns_rule_kdl(std::string_view kdl, std::string_view rule_line)
        -> std::pair<bool, std::string>;
}
