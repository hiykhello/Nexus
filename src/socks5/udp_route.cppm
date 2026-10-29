export module nexus.socks5.udp_route;
export import nexus.socks5;
import nexus.rules;
import std;

export namespace nexus::socks5 {
    enum class UdpRouteError { invalid_target, blocked, unsupported, policy_error };
    // Outbound 0 is direct, 1 is block; other outbounds lack UDP support.
    // The resolver must supply an actual candidate, not a client assertion.
    [[nodiscard]] auto udp_preflight(rules::RouteMatcher const& policy, UdpDatagram const& packet)
        -> std::expected<void,UdpRouteError>;
    [[nodiscard]] auto udp_route(rules::RouteMatcher const& policy, UdpDatagram const& packet, UdpPeer candidate)
        -> std::expected<UdpPeer,UdpRouteError>;
    struct UdpSend { UdpPeer target; std::uint64_t token; };
    using UdpPrepareError = std::variant<UdpRouteError,Status>;
    // packet must come from this association's admit(); candidate must be an
    // actual resolved endpoint. Finish the token after the socket operation.
    [[nodiscard]] auto udp_prepare_send(UdpAssociation& association, rules::RouteMatcher const& policy,
                                        UdpDatagram const& packet, UdpPeer candidate)
        -> std::expected<UdpSend,UdpPrepareError>;
}
