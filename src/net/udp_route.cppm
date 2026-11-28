export module net.udp_route;
export import net.udp_socket;
import rules;
import std;

export namespace net {
    enum class UdpTargetKind { invalid, ipv4, ipv6, domain };
    // The address bytes are borrowed for the duration of routing. A domain is
    // never accepted as a resolved candidate; it must be resolved by the caller.
    struct UdpTarget {
        UdpTargetKind kind=UdpTargetKind::invalid;
        std::span<std::uint8_t const> address;
        std::uint16_t port=0;
    };
    enum class UdpRouteError { invalid_target, blocked, unsupported, policy_error };
    struct UdpSelection {
        UdpEndpoint target;
        std::size_t outbound;
        std::optional<std::size_t> rule{},predicate{};
    };
    // The source points to the authenticated datagram sender when known and
    // is borrowed for the call; nullptr preserves unknown source metadata.
    // Check target/candidate consistency and normalize mapped IPv4, without
    // making a routing decision. Used after an ordered policy selects a route.
    [[nodiscard]] auto udp_validate_candidate(UdpTarget,UdpEndpoint) -> std::expected<UdpEndpoint,UdpRouteError>;
    [[nodiscard]] auto udp_select_preflight(rules::RouteProgram const&,UdpTarget,UdpEndpoint const* source=nullptr,std::optional<std::string_view> auth_user={},std::optional<std::string_view> source_interface={},rules::IngressMetadata ingress={})
        -> std::expected<std::optional<std::size_t>,UdpRouteError>;
    [[nodiscard]] auto udp_select(rules::RouteProgram const&,UdpTarget,UdpEndpoint,UdpEndpoint const* source=nullptr,std::optional<std::string_view> auth_user={},std::optional<std::string_view> source_interface={},rules::IngressMetadata ingress={})
        -> std::expected<UdpSelection,UdpRouteError>;
    [[nodiscard]] auto udp_preflight(rules::RouteProgram const&,UdpTarget,UdpEndpoint const* source=nullptr,std::optional<std::string_view> auth_user={}) -> std::expected<void,UdpRouteError>;
    [[nodiscard]] auto udp_route(rules::RouteProgram const&,UdpTarget,UdpEndpoint,UdpEndpoint const* source=nullptr,std::optional<std::string_view> auth_user={}) -> std::expected<UdpEndpoint,UdpRouteError>;
}
