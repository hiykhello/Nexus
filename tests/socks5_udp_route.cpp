import std;
import rules;
import socks5.udp_route;
namespace s=socks5;
namespace r = ::rules;
int main() {
    r::RuleSet domain{{{"domain-suffix","ok.test"}}};
    r::RuleSet blocked{{{"ip-cidr","192.0.2.0/24"}}};
    auto policy=r::RouteProgram::compile_policy(std::array{r::ProgramRule{blocked,{r::ProgramActionKind::route,1}},r::ProgramRule{domain,{r::ProgramActionKind::route,0}}},2,3);
    if (!policy) return 1;
    s::UdpDatagram packet; packet.address_type=3; packet.address_length=7; packet.port=53;
    std::ranges::copy(std::string_view("ok.test"),packet.address.begin());
    s::UdpPeer denied{1,{192,0,2,1},53}, allowed{1,{127,0,0,1},53};
    if (!s::udp_preflight(*policy,packet) || s::udp_route(*policy,packet,denied).error()!=s::UdpRouteError::blocked ||
        !s::udp_route(*policy,packet,allowed)) return 2;
    auto unresolved=s::udp_select_preflight(*policy,packet);
    if (!unresolved || unresolved->has_value()) return 15; // Earlier IP rule must be evaluated after DNS.
    auto chosen=s::udp_select(*policy,packet,allowed);
    if (!chosen || chosen->outbound!=0 || chosen->target!=allowed ||
        s::udp_select(*policy,packet,denied).error()!=s::UdpRouteError::blocked) return 16;
    auto other=packet; other.address[0]='x';
    auto tunnel=s::udp_select(*policy,other,allowed);
    if (!tunnel || tunnel->outbound!=2 || tunnel->target!=allowed) return 17;
    auto tunnel_policy=r::RouteProgram::compile_policy(std::array{r::ProgramRule{domain,{r::ProgramActionKind::route,2}}},0,3);
    if (!tunnel_policy) return 18;
    auto early=s::udp_select_preflight(*tunnel_policy,packet);
    if (!early || !early->has_value() || **early!=2 || s::udp_preflight(*tunnel_policy,packet).error()!=s::UdpRouteError::unsupported) return 19;
    auto selected=s::udp_select(*tunnel_policy,packet,allowed);
    if (!selected || selected->outbound!=2 || selected->target!=allowed) return 20;
    auto blocked_policy=r::RouteProgram::compile_policy(std::array{r::ProgramRule{domain,{r::ProgramActionKind::route,1}}},0,3);
    if (!blocked_policy || s::udp_select_preflight(*blocked_policy,packet).error()!=s::UdpRouteError::blocked ||
        s::udp_select(*blocked_policy,packet,allowed).error()!=s::UdpRouteError::blocked) return 21;
    if (!s::udp_preflight(*policy,other) || s::udp_route(*policy,other,allowed).error()!=s::UdpRouteError::unsupported) return 3;
    packet.address_type=1; packet.address_length=4; packet.address={127,0,0,1};
    auto direct=r::RouteProgram::compile_policy(std::span<r::ProgramRule const>{},0,3);
    if (!direct || !s::udp_route(*direct,packet,allowed) || s::udp_route(*direct,packet,denied).error()!=s::UdpRouteError::invalid_target) return 4;
    auto wrong=allowed; wrong.port=54;
    if (s::udp_route(*direct,packet,wrong).error()!=s::UdpRouteError::invalid_target) return 5;
    s::UdpPeer mapped{4,{0,0,0,0,0,0,0,0,0,0,255,255,192,0,2,1},53};
    packet.address_type=4; packet.address_length=16;
    std::ranges::copy(mapped.address,packet.address.begin());
    if (s::udp_route(*policy,packet,denied).error()!=s::UdpRouteError::blocked ||
        s::udp_route(*policy,packet,mapped).error()!=s::UdpRouteError::blocked) return 6;
    auto normalized=s::udp_route(*direct,packet,mapped);
    if (!normalized || *normalized!=denied) return 7;
    auto mapped_unspecified=mapped;
    std::ranges::fill(std::span(mapped_unspecified.address).last<4>(),0);
    std::ranges::copy(mapped_unspecified.address,packet.address.begin());
    if (s::udp_route(*direct,packet,mapped_unspecified).error()!=s::UdpRouteError::invalid_target) return 13;
    packet.address_type=3; packet.address_length=7;
    std::ranges::copy(std::string_view("ok.test"),packet.address.begin());
    if (s::udp_route(*direct,packet,mapped_unspecified).error()!=s::UdpRouteError::invalid_target ||
        s::udp_route(*policy,packet,mapped).error()!=s::UdpRouteError::blocked) return 14;
    packet.address_type=4; packet.address_length=16;
    std::ranges::copy(mapped.address,packet.address.begin());
    auto association=s::UdpAssociation::create({1,{127,0,0,1},1234},{1,{},0});
    if (!association || s::udp_prepare_send(*association,*direct,packet,mapped)) return 9;
    std::array<std::uint8_t,23> wire{0,0,0,4,0,0,0,0,0,0,0,0,0,0,255,255,192,0,2,1,0,53,'x'};
    auto admitted=association->admit({1,{127,0,0,1},5000},wire);
    if (!admitted) return 10;
    r::RuleSet source{{{"and","",{{"source-ip-cidr","127.0.0.0/8",{}},{"source-port","5000",{}}}}},2};
    auto source_policy=r::RouteProgram::compile_policy(std::array{r::ProgramRule{source,{r::ProgramActionKind::route,1}}},0,2,r::SourceMetadata::provided);
    if (!source_policy) return 22;
    auto source_blocked=s::udp_prepare_send(*association,*source_policy,*admitted,mapped);
    if (source_blocked || !std::holds_alternative<s::UdpRouteError>(source_blocked.error()) ||
        std::get<s::UdpRouteError>(source_blocked.error())!=s::UdpRouteError::blocked) return 23;
    auto blocked_send=s::udp_prepare_send(*association,*policy,*admitted,mapped);
    if (blocked_send || !std::holds_alternative<s::UdpRouteError>(blocked_send.error()) || association->accepts_reply(denied)) return 11;
    auto prepared=s::udp_prepare_send(*association,*direct,*admitted,mapped);
    if (!prepared || prepared->target!=denied || association->accepts_reply(denied) ||
        !association->finish_send(prepared->token,true) || !association->accepts_reply(denied)) return 12;
    packet.address_length=3;
    if (s::udp_route(*direct,packet,denied).error()!=s::UdpRouteError::invalid_target) return 8;
    std::println("SOCKS UDP domain and candidate routing passed");
}
