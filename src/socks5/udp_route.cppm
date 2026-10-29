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
}
