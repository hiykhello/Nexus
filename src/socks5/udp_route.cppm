export module socks5.udp_route;
export import socks5;
export import net.udp_route;
import rules;
import std;

export namespace socks5 {
    using UdpRouteError=net::UdpRouteError;
    [[nodiscard]] constexpr auto udp_endpoint(UdpPeer peer) noexcept -> net::UdpEndpoint {
        auto family=peer.address_type==1 ? std::uint8_t{4} : peer.address_type==4 ? std::uint8_t{6} : std::uint8_t{0};
        return {family,peer.address,peer.port};
    }
    [[nodiscard]] constexpr auto udp_peer(net::UdpEndpoint peer) noexcept -> UdpPeer {
        auto type=peer.family==4 ? std::uint8_t{1} : peer.family==6 ? std::uint8_t{4} : std::uint8_t{0};
        return {type,peer.address,peer.port};
    }
    [[nodiscard]] constexpr auto udp_target(UdpDatagram const& packet) noexcept -> net::UdpTarget {
        auto kind=packet.address_type==1 ? net::UdpTargetKind::ipv4 : packet.address_type==4 ? net::UdpTargetKind::ipv6 :
            packet.address_type==3 ? net::UdpTargetKind::domain : net::UdpTargetKind::invalid;
        return {kind,std::span{packet.address}.first(packet.address_length),packet.port};
    }
    struct UdpSelection {
        UdpPeer target;
        std::size_t outbound;
        std::optional<std::size_t> rule{},predicate{};
    };
    [[nodiscard]] auto udp_select_preflight(rules::RouteMatcher const& policy,UdpDatagram const& packet,UdpPeer const* source=nullptr,std::optional<std::string_view> auth_user={})
        -> std::expected<std::optional<std::size_t>,UdpRouteError>;
    [[nodiscard]] auto udp_select(rules::RouteMatcher const& policy,UdpDatagram const& packet,UdpPeer candidate,UdpPeer const* source=nullptr,std::optional<std::string_view> auth_user={})
        -> std::expected<UdpSelection,UdpRouteError>;
    [[nodiscard]] auto udp_preflight(rules::RouteMatcher const& policy,UdpDatagram const& packet,UdpPeer const* source=nullptr,std::optional<std::string_view> auth_user={})
        -> std::expected<void,UdpRouteError>;
    [[nodiscard]] auto udp_route(rules::RouteMatcher const& policy,UdpDatagram const& packet,UdpPeer candidate,UdpPeer const* source=nullptr,std::optional<std::string_view> auth_user={})
        -> std::expected<UdpPeer,UdpRouteError>;
    struct UdpSend { UdpPeer target; std::uint64_t token; };
    using UdpPrepareError=std::variant<UdpRouteError,Status>;
    [[nodiscard]] auto udp_prepare_send(UdpAssociation& association,rules::RouteMatcher const& policy,
        UdpDatagram const& packet,UdpPeer candidate,std::optional<std::string_view> auth_user={}) -> std::expected<UdpSend,UdpPrepareError>;
}
