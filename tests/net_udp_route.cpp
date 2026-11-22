import std;
import net.udp_route;
import net.udp_authorization;
import rules;

namespace n=net;
namespace r = ::rules;
int main() {
    r::RuleSet blocked{{{"ip-cidr","192.0.2.0/24"}}};
    r::RuleSet named{{{"domain-suffix","ok.test"}}};
    auto policy=r::RouteMatcher::compile(std::array{r::RouteRule{blocked,1},r::RouteRule{named,0}},2,3);
    auto direct=r::RouteMatcher::compile(std::span<r::RouteRule const>{},0,3);
    if (!policy || !direct) return 1;
    std::array<std::uint8_t,7> host{'o','k','.','t','e','s','t'};
    n::UdpTarget domain{n::UdpTargetKind::domain,host,53};
    n::UdpEndpoint allowed{4,{127,0,0,1},53},denied{4,{192,0,2,1},53};
    auto chosen=n::udp_select(*policy,domain,allowed);
    if (!chosen || chosen->target!=allowed || chosen->outbound!=0 ||
        n::udp_select(*policy,domain,denied).error()!=n::UdpRouteError::blocked) return 2;
    auto wrong=allowed; wrong.port=54;
    if (n::udp_route(*direct,domain,wrong).error()!=n::UdpRouteError::invalid_target) return 3;
    n::UdpEndpoint mapped{6,{0,0,0,0,0,0,0,0,0,0,255,255,192,0,2,1},53};
    n::UdpTarget literal{n::UdpTargetKind::ipv6,mapped.address,53};
    auto normalized=n::udp_route(*direct,literal,mapped);
    if (!normalized || *normalized!=denied || n::udp_route(*policy,literal,mapped).error()!=n::UdpRouteError::blocked) return 4;
    literal.address=std::span{mapped.address}.first(3);
    if (n::udp_preflight(*direct,literal).error()!=n::UdpRouteError::invalid_target) return 5;
    auto selected=n::udp_validate_candidate(domain,allowed);
    if(!selected || *selected!=allowed || n::udp_validate_candidate(domain,wrong) ||
        n::udp_validate_candidate(literal,mapped)) return 13;
    literal.address=mapped.address;
    auto mapped_selected=n::udp_validate_candidate(literal,mapped);
    if(!mapped_selected || *mapped_selected!=denied) return 14;
    auto different_literal=allowed;different_literal.address[3]=2;
    n::UdpTarget fixed{n::UdpTargetKind::ipv4,std::span(allowed.address).first(4),allowed.port};
    if(n::udp_validate_candidate(fixed,different_literal) || !n::udp_validate_candidate(fixed,allowed))return 15;
    r::RuleSet source{{{"and","",{{"source-ip-cidr","192.0.2.0/24",{}},{"source-port","5000",{}}}}},2};
    auto source_policy=r::RouteMatcher::compile(std::array{r::RouteRule{source,1}},0,2,r::SourceMetadata::provided);
    n::UdpEndpoint sender{4,{192,0,2,4},5000};
    if (!source_policy || n::udp_select_preflight(*source_policy,domain,&sender).error()!=n::UdpRouteError::blocked ||
        n::udp_select(*source_policy,domain,allowed,&sender).error()!=n::UdpRouteError::blocked) return 9;
    sender.port=5001;
    auto different=n::udp_select_preflight(*source_policy,domain,&sender);
    if (!different || !*different || **different!=0 || !n::udp_select(*source_policy,domain,allowed,&sender)) return 10;
    auto unknown=n::udp_select_preflight(*source_policy,domain);
    if (!unknown || *unknown) return 11;
    sender.family=3;
    if (n::udp_select(*source_policy,domain,allowed,&sender).error()!=n::UdpRouteError::invalid_target) return 12;
    n::UdpAuthorization auth;
    auto token=auth.begin(allowed);
    if (!token || auth.classify(allowed)!=n::UdpReplyAuthorization::pending || auth.accepts(allowed) ||
        auth.begin(denied).error()!=n::UdpAuthorizationError::busy || !auth.finish(*token,false) || auth.accepts(allowed)) return 6;
    token=auth.begin(allowed);
    if (!token || !auth.finish(*token,true) || !auth.accepts(allowed)) return 7;
    auth.close();
    if (auth.accepts(allowed) || auth.begin(allowed).error()!=n::UdpAuthorizationError::closed) return 8;
}
