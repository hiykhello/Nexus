module nexus.socks5.udp_route;
import std;
import nexus.rules;

namespace nexus::socks5 {
    namespace {
        auto mapped(UdpPeer const& peer) -> bool {
            return peer.address_type==4 &&
                std::ranges::all_of(std::span(peer.address).first<10>(),[](auto value) { return value==0; }) &&
                peer.address[10]==255 && peer.address[11]==255;
        }
        auto canonical(UdpPeer peer) -> UdpPeer {
            if (mapped(peer)) {
                std::ranges::copy(std::span(peer.address).last<4>(),peer.address.begin());
                std::ranges::fill(std::span(peer.address).subspan(4),0);
                peer.address_type=1;
            }
            return peer;
        }
        auto valid(UdpPeer const& peer) -> bool {
            if (!peer.port || (peer.address_type!=1 && peer.address_type!=4)) return false;
            if (peer.address_type==1 && std::ranges::any_of(std::span(peer.address).subspan(4),[](auto byte) { return byte!=0; })) return false;
            return std::ranges::any_of(peer.address,[](auto byte) { return byte!=0; });
        }
        auto valid_packet(UdpDatagram const& packet) -> bool {
            return packet.port && ((packet.address_type==1 && packet.address_length==4) ||
                (packet.address_type==4 && packet.address_length==16) ||
                (packet.address_type==3 && packet.address_length));
        }
        auto domain(UdpDatagram const& packet) -> std::string_view {
            return {reinterpret_cast<char const*>(packet.address.data()),packet.address_length};
        }
        auto text(UdpPeer const& peer) -> std::string {
            auto const& a=peer.address;
            if (peer.address_type==1) return std::format("{}.{}.{}.{}",a[0],a[1],a[2],a[3]);
            auto word=[&](std::size_t i) { return (static_cast<unsigned>(a[i])<<8)|a[i+1]; };
            return std::format("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",word(0),word(2),word(4),word(6),word(8),word(10),word(12),word(14));
        }
        auto action(std::size_t selected) -> std::expected<void,UdpRouteError> {
            if (selected==0) return {};
            return std::unexpected(selected==1 ? UdpRouteError::blocked : UdpRouteError::unsupported);
        }
    }
    auto udp_preflight(rules::RouteMatcher const& policy, UdpDatagram const& packet) -> std::expected<void,UdpRouteError> {
        if (!valid_packet(packet)) return std::unexpected(UdpRouteError::invalid_target);
        if (packet.address_type!=3) return {};
        auto selected=policy.preflight(domain(packet));
        if (!selected) return std::unexpected(UdpRouteError::policy_error);
        return *selected ? action(**selected) : std::expected<void,UdpRouteError>{};
    }
    auto udp_route(rules::RouteMatcher const& policy, UdpDatagram const& packet, UdpPeer candidate)
        -> std::expected<UdpPeer,UdpRouteError> {
        if (!valid_packet(packet) || !valid(candidate) || candidate.port!=packet.port)
            return std::unexpected(UdpRouteError::invalid_target);
        UdpPeer literal{packet.address_type,{},packet.port};
        if (packet.address_type!=3) {
            std::copy_n(packet.address.begin(),packet.address_length,literal.address.begin());
            if (!valid(literal) || canonical(literal)!=canonical(candidate)) return std::unexpected(UdpRouteError::invalid_target);
        }
        auto preflight=udp_preflight(policy,packet);
        if (!preflight) return std::unexpected(preflight.error());
        auto ip=text(packet.address_type!=3 && mapped(literal) ? literal : candidate);
        std::optional<std::string_view> name;
        if (packet.address_type==3) name=domain(packet);
        auto selected=policy.match({.domain=name,.ip=ip});
        if (!selected) return std::unexpected(UdpRouteError::policy_error);
        auto allowed=action(*selected);
        if (!allowed) return std::unexpected(allowed.error());
        return canonical(candidate);
    }
    auto udp_prepare_send(UdpAssociation& association, rules::RouteMatcher const& policy,
                          UdpDatagram const& packet, UdpPeer candidate) -> std::expected<UdpSend,UdpPrepareError> {
        if (!association.client_peer()) return std::unexpected(UdpPrepareError{Status::unauthorized_source});
        auto target=udp_route(policy,packet,candidate);
        if (!target) return std::unexpected(UdpPrepareError{target.error()});
        auto token=association.begin_send(*target);
        if (!token) return std::unexpected(UdpPrepareError{token.error()});
        return UdpSend{*target,*token};
    }
}
