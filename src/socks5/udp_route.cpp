module socks5.udp_route;
import std;
import rules;

namespace socks5 {
    auto udp_select_preflight(rules::RouteMatcher const& policy,UdpDatagram const& packet,UdpPeer const* source,std::optional<std::string_view> auth_user)
        -> std::expected<std::optional<std::size_t>,UdpRouteError> {
        auto endpoint=source ? udp_endpoint(*source) : net::UdpEndpoint{};
        return net::udp_select_preflight(policy,udp_target(packet),source ? &endpoint : nullptr,auth_user);
    }
    auto udp_preflight(rules::RouteMatcher const& policy,UdpDatagram const& packet,UdpPeer const* source,std::optional<std::string_view> auth_user) -> std::expected<void,UdpRouteError> {
        auto endpoint=source ? udp_endpoint(*source) : net::UdpEndpoint{};
        return net::udp_preflight(policy,udp_target(packet),source ? &endpoint : nullptr,auth_user);
    }
    auto udp_select(rules::RouteMatcher const& policy,UdpDatagram const& packet,UdpPeer candidate,UdpPeer const* source,std::optional<std::string_view> auth_user)
        -> std::expected<UdpSelection,UdpRouteError> {
        auto endpoint=source ? udp_endpoint(*source) : net::UdpEndpoint{};
        auto selected=net::udp_select(policy,udp_target(packet),udp_endpoint(candidate),source ? &endpoint : nullptr,auth_user);
        if (!selected) return std::unexpected(selected.error());
        return UdpSelection{udp_peer(selected->target),selected->outbound,selected->rule,selected->predicate};
    }
    auto udp_route(rules::RouteMatcher const& policy,UdpDatagram const& packet,UdpPeer candidate,UdpPeer const* source,std::optional<std::string_view> auth_user)
        -> std::expected<UdpPeer,UdpRouteError> {
        auto endpoint=source ? udp_endpoint(*source) : net::UdpEndpoint{};
        auto selected=net::udp_route(policy,udp_target(packet),udp_endpoint(candidate),source ? &endpoint : nullptr,auth_user);
        if (!selected) return std::unexpected(selected.error());
        return udp_peer(*selected);
    }
    auto udp_prepare_send(UdpAssociation& association,rules::RouteMatcher const& policy,
                          UdpDatagram const& packet,UdpPeer candidate,std::optional<std::string_view> auth_user) -> std::expected<UdpSend,UdpPrepareError> {
        auto source=association.client_peer();
        if (!source) return std::unexpected(UdpPrepareError{Status::unauthorized_source});
        auto target=udp_route(policy,packet,candidate,&*source,auth_user);
        if (!target) return std::unexpected(UdpPrepareError{target.error()});
        auto token=association.begin_send(*target);
        if (!token) return std::unexpected(UdpPrepareError{token.error()});
        return UdpSend{*target,*token};
    }
}
