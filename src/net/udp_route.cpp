module net.udp_route;
import std;
import rules;

namespace net {
    namespace {
        auto mapped(UdpEndpoint const& peer) -> bool {
            return peer.family==6 &&
                std::ranges::all_of(std::span(peer.address).first<10>(),[](auto value) { return value==0; }) &&
                peer.address[10]==255 && peer.address[11]==255;
        }
        auto canonical(UdpEndpoint peer) -> UdpEndpoint {
            if (mapped(peer)) {
                std::ranges::copy(std::span(peer.address).last<4>(),peer.address.begin());
                std::ranges::fill(std::span(peer.address).subspan(4),0);
                peer.family=4;
            }
            return peer;
        }
        auto valid(UdpEndpoint const& peer) -> bool {
            if (!peer.port || (peer.family!=4 && peer.family!=6)) return false;
            if (peer.family==4 && std::ranges::any_of(std::span(peer.address).subspan(4),[](auto byte) { return byte!=0; })) return false;
            return std::ranges::any_of(peer.address,[](auto byte) { return byte!=0; });
        }
        auto valid_target(UdpTarget target) -> bool {
            return target.port && ((target.kind==UdpTargetKind::ipv4 && target.address.size()==4) ||
                (target.kind==UdpTargetKind::ipv6 && target.address.size()==16) ||
                (target.kind==UdpTargetKind::domain && !target.address.empty() && target.address.size()<=255));
        }
        auto domain(UdpTarget target) -> std::string_view {
            return {reinterpret_cast<char const*>(target.address.data()),target.address.size()};
        }
        auto text(UdpEndpoint const& peer) -> std::string {
            auto const& a=peer.address;
            if (peer.family==4) return std::format("{}.{}.{}.{}",a[0],a[1],a[2],a[3]);
            auto word=[&](std::size_t i) { return (static_cast<unsigned>(a[i])<<8)|a[i+1]; };
            return std::format("{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",word(0),word(2),word(4),word(6),word(8),word(10),word(12),word(14));
        }
        auto action(std::size_t selected) -> std::expected<void,UdpRouteError> {
            if (selected==0) return {};
            return std::unexpected(selected==1 ? UdpRouteError::blocked : UdpRouteError::unsupported);
        }
        auto add_source(rules::MatchInput& input,UdpEndpoint const* source) -> bool {
            if (!source) return true;
            if (!valid(*source)) return false;
            input.source_port=source->port;
            input.source_ip_bytes=std::span(source->address).first(source->family==4 ? 4 : 16);
            return true;
        }
    }
    auto udp_validate_candidate(UdpTarget target,UdpEndpoint candidate) -> std::expected<UdpEndpoint,UdpRouteError> {
        if (!valid_target(target) || !valid(candidate) || !valid(canonical(candidate)) || candidate.port!=target.port)
            return std::unexpected(UdpRouteError::invalid_target);
        if (target.kind!=UdpTargetKind::domain) {
            UdpEndpoint literal{target.kind==UdpTargetKind::ipv4 ? std::uint8_t{4} : std::uint8_t{6},{},target.port};
            std::ranges::copy(target.address,literal.address.begin());
            if (!valid(literal) || !valid(canonical(literal)) || canonical(literal)!=canonical(candidate))
                return std::unexpected(UdpRouteError::invalid_target);
        }
        return canonical(candidate);
    }
    auto udp_select_preflight(rules::RouteMatcher const& policy,UdpTarget target,UdpEndpoint const* source,std::optional<std::string_view> auth_user,std::optional<std::string_view> source_interface,rules::IngressMetadata ingress)
        -> std::expected<std::optional<std::size_t>,UdpRouteError> {
        if (!valid_target(target)) return std::unexpected(UdpRouteError::invalid_target);
        if (source && !valid(*source)) return std::unexpected(UdpRouteError::invalid_target);
        if (target.kind!=UdpTargetKind::domain) return std::optional<std::size_t>{};
        rules::MatchInput input{.domain=domain(target),.port=target.port,.network=rules::Network::udp,.auth_user=auth_user,.source_interface=source_interface};
        if (!add_source(input,source)) return std::unexpected(UdpRouteError::invalid_target);
        auto selected=policy.preflight(ingress.apply(input));
        if (!selected) return std::unexpected(UdpRouteError::policy_error);
        if (*selected && **selected==1) return std::unexpected(UdpRouteError::blocked);
        return *selected;
    }
    auto udp_preflight(rules::RouteMatcher const& policy,UdpTarget target,UdpEndpoint const* source,std::optional<std::string_view> auth_user) -> std::expected<void,UdpRouteError> {
        auto selected=udp_select_preflight(policy,target,source,auth_user);
        if (!selected) return std::unexpected(selected.error());
        return *selected ? action(**selected) : std::expected<void,UdpRouteError>{};
    }
    auto udp_select(rules::RouteMatcher const& policy,UdpTarget target,UdpEndpoint candidate,UdpEndpoint const* source,std::optional<std::string_view> auth_user,std::optional<std::string_view> source_interface,rules::IngressMetadata ingress)
        -> std::expected<UdpSelection,UdpRouteError> {
        auto checked=udp_validate_candidate(target,candidate);
        if(!checked)return std::unexpected(checked.error());
        UdpEndpoint literal{target.kind==UdpTargetKind::ipv4 ? std::uint8_t{4} : std::uint8_t{6},{},target.port};
        if (target.kind!=UdpTargetKind::domain) std::ranges::copy(target.address,literal.address.begin());
        auto preflight=udp_select_preflight(policy,target,source,auth_user,source_interface,ingress);
        if (!preflight) return std::unexpected(preflight.error());
        auto ip=text(target.kind!=UdpTargetKind::domain && mapped(literal) ? literal : candidate);
        std::optional<std::string_view> name;
        if (target.kind==UdpTargetKind::domain) name=domain(target);
        rules::MatchInput input{.domain=name,.ip=ip,.port=target.port,.network=rules::Network::udp,.auth_user=auth_user,.source_interface=source_interface};
        if (!add_source(input,source)) return std::unexpected(UdpRouteError::invalid_target);
        auto selected=policy.match_with_rule(ingress.apply(input));
        if (!selected) return std::unexpected(UdpRouteError::policy_error);
        if (selected->outbound==1) return std::unexpected(UdpRouteError::blocked);
        return UdpSelection{*checked,selected->outbound,selected->rule,selected->predicate};
    }
    auto udp_route(rules::RouteMatcher const& policy,UdpTarget target,UdpEndpoint candidate,UdpEndpoint const* source,std::optional<std::string_view> auth_user)
        -> std::expected<UdpEndpoint,UdpRouteError> {
        auto selected=udp_select(policy,target,candidate,source,auth_user);
        if (!selected) return std::unexpected(selected.error());
        auto allowed=action(selected->outbound);
        if (!allowed) return std::unexpected(allowed.error());
        return selected->target;
    }
}
