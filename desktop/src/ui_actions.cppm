export module desktop.ui_actions;

import std;
import desktop.http_control;

export namespace desktop {
    struct InboundEndpointSpec {
        bool enabled = false;
        std::string host = "127.0.0.1";
        std::uint16_t port = 0;
    };

    struct CoexistingInbounds {
        InboundEndpointSpec mixed{false, "127.0.0.1", 7890};
        InboundEndpointSpec socks5{false, "127.0.0.1", 1080};
        InboundEndpointSpec http{false, "0.0.0.0", 7891};
    };

    [[nodiscard]] auto parse_port_u16(std::string_view text) -> std::optional<std::uint16_t>;

    [[nodiscard]] auto select_system_proxy_endpoint(CoexistingInbounds const& inb)
        -> std::optional<std::pair<std::string, std::uint16_t>>;

    struct RuleMatchDraft {
        std::string kind;
        std::string value;
        std::string action = "route";
        std::string outbound;
    };

    // Extracts a structured rule predicate, action, and target outbound from an active connection row.
    [[nodiscard]] auto extract_rule_match_from_connection(
        std::string_view target,
        int port,
        std::string_view protocol,
        std::string_view outbound,
        std::string_view default_proxy_outbound = "proxy",
        std::string_view rule_action = "") -> RuleMatchDraft;

    // Sorts outbound members with pinned favorites first, then by "latency", "name", or "default".
    [[nodiscard]] auto sort_outbound_members(
        std::vector<OutboundMemberSnapshot> members,
        std::string_view sort_mode,
        std::unordered_set<std::string> const& pinned_names) -> std::vector<OutboundMemberSnapshot>;

    // Selects up to max_count quick-switch nodes: active first, then pinned favorites, then fastest healthy.
    [[nodiscard]] auto pick_quick_nodes(
        std::vector<OutboundMemberSnapshot> const& members,
        std::unordered_set<std::string> const& pinned_names,
        std::size_t max_count = 6) -> std::vector<OutboundMemberSnapshot>;

    // Formats a validated host:port endpoint with RFC 3986 brackets around IPv6 literals (empty if host invalid).
    [[nodiscard]] auto format_host_port(std::string_view host, std::string_view port) -> std::string;

    // Builds a shell export command for enabled local HTTP/SOCKS proxy ports (empty if none active or host invalid).
    [[nodiscard]] auto build_proxy_export_command(
        std::string_view host,
        std::uint16_t http_port,
        std::uint16_t socks_port,
        std::string_view socks_host = {}) -> std::string;
}
