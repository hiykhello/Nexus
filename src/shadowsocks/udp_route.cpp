module nexus.shadowsocks.udp_route;
import std;
import nexus.rules;
namespace nexus::shadowsocks {
    namespace {
        struct Request { std::optional<std::string> domain; std::optional<UdpPeer> literal; std::uint16_t port; };
        auto parse(std::span<std::uint8_t const> a) -> std::optional<Request> {
            if (a.empty()) return {};
            std::size_t length=a[0]==1 ? 4 : a[0]==4 ? 16 : a[0]==3 && a.size()>=2 ? a[1] : 0;
            auto offset=a[0]==3 ? 2u : 1u;
            if (!length || a.size()!=offset+length+2) return {};
            auto port=static_cast<std::uint16_t>((static_cast<unsigned>(a[offset+length])<<8)|a[offset+length+1]);
            if (!port) return {};
            Request result{{},{},port};
            if (a[0]==3) result.domain=std::string(a.begin()+offset,a.begin()+offset+length);
            else { UdpPeer peer{static_cast<std::uint8_t>(a[0]==1 ? 4 : 6),{},port};
                std::ranges::copy(a.subspan(offset,length),peer.address.begin()); result.literal=peer; }
            return result;
        }
        auto mapped(UdpPeer const& p) -> bool {
            return p.family==6 && std::ranges::all_of(std::span{p.address}.first<10>(),[](auto b){return b==0;}) &&
                p.address[10]==255 && p.address[11]==255;
        }
        auto canonical(UdpPeer p) -> UdpPeer {
            if (mapped(p)) { std::ranges::copy(std::span{p.address}.last<4>(),p.address.begin());
                std::ranges::fill(std::span{p.address}.subspan(4),0); p.family=4; }
            return p;
        }
        auto text(UdpPeer const& p) -> std::string {
            auto const& a=p.address;
            if (p.family==4) return std::format("{}.{}.{}.{}",a[0],a[1],a[2],a[3]);
            auto word=[&](std::size_t i) { return (static_cast<unsigned>(a[i])<<8)|a[i+1]; };
            return std::format("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",word(0),word(2),word(4),word(6),word(8),word(10),word(12),word(14));
        }
        auto check(rules::Matcher const& policy,rules::MatchInput input) -> std::expected<void,UdpRouteError> {
            auto match=policy.match(input);
            if (!match) return std::unexpected(UdpRouteError::policy_error);
            if (match->has_value()) return std::unexpected(UdpRouteError::blocked);
            return {};
        }
    }
    auto UdpRoutedServer::preflight(UdpAccepted const& packet) const -> std::expected<void,UdpRouteError> {
        auto request=parse(packet.packet.address);
        if (!request) return std::unexpected(UdpRouteError::invalid_target);
        if (!request->domain) return {};
        if (auto simple=std::get_if<rules::Matcher>(&policy_)) return check(*simple,{.domain=*request->domain});
        auto route=std::get<rules::RouteMatcher>(policy_).preflight(*request->domain);
        if (!route) return std::unexpected(UdpRouteError::policy_error);
        if (!*route || **route==0) return {};
        return std::unexpected(**route==1 ? UdpRouteError::blocked : UdpRouteError::unsupported);
    }
    auto UdpRoutedServer::forward(UdpAccepted const& packet,UdpPeer resolved) -> std::expected<void,UdpRoutedFailure> {
        auto request=parse(packet.packet.address);
        if (!request || (resolved.family!=4 && resolved.family!=6) || resolved.port!=request->port ||
            (resolved.family==4 && std::ranges::any_of(std::span{resolved.address}.subspan(4),[](auto b){return b!=0;})))
            return std::unexpected(UdpRoutedFailure{UdpRouteError::invalid_target});
        if (request->literal && canonical(*request->literal)!=canonical(resolved))
            return std::unexpected(UdpRoutedFailure{UdpRouteError::invalid_target});
        auto initial=preflight(packet);
        if (!initial) return std::unexpected(UdpRoutedFailure{initial.error()});
        auto ip=text(request->literal && mapped(*request->literal) ? *request->literal : resolved);
        if (auto ordered=std::get_if<rules::RouteMatcher>(&policy_)) {
            std::optional<std::string_view> domain;
            if (request->domain) domain=*request->domain;
            auto route=ordered->match({.domain=domain,.ip=ip});
            if (!route) return std::unexpected(UdpRoutedFailure{UdpRouteError::policy_error});
            if (*route!=0) return std::unexpected(UdpRoutedFailure{*route==1 ? UdpRouteError::blocked : UdpRouteError::unsupported});
        } else {
            auto const& policy=std::get<rules::Matcher>(policy_);
            auto rule=check(policy,{.ip=ip});
            if (!rule) return std::unexpected(UdpRoutedFailure{rule.error()});
            if (mapped(resolved) || (request->literal && mapped(*request->literal))) {
                auto ipv4=text(canonical(resolved));
                rule=check(policy,{.ip=ipv4});
                if (!rule) return std::unexpected(UdpRoutedFailure{rule.error()});
            }
        }
        auto sent=server_.forward(packet,canonical(resolved));
        if (!sent) return std::unexpected(UdpRoutedFailure{sent.error()});
        return {};
    }
}
