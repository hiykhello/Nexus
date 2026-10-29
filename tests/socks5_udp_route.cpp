import std;
import nexus.rules;
import nexus.socks5.udp_route;
namespace s=nexus::socks5;
namespace r=nexus::rules;
int main() {
    r::RuleSet domain{{{"domain-suffix","ok.test"}}};
    r::RuleSet blocked{{{"ip-cidr","192.0.2.0/24"}}};
    auto policy=r::RouteMatcher::compile(std::array{r::RouteRule{blocked,1},r::RouteRule{domain,0}},2,3);
    if (!policy) return 1;
    s::UdpDatagram packet; packet.address_type=3; packet.address_length=7; packet.port=53;
    std::ranges::copy(std::string_view("ok.test"),packet.address.begin());
    s::UdpPeer denied{1,{192,0,2,1},53}, allowed{1,{127,0,0,1},53};
    if (!s::udp_preflight(*policy,packet) || s::udp_route(*policy,packet,denied).error()!=s::UdpRouteError::blocked ||
        !s::udp_route(*policy,packet,allowed)) return 2;
    auto other=packet; other.address[0]='x';
    if (!s::udp_preflight(*policy,other) || s::udp_route(*policy,other,allowed).error()!=s::UdpRouteError::unsupported) return 3;
    packet.address_type=1; packet.address_length=4; packet.address={127,0,0,1};
    auto direct=r::RouteMatcher::compile(std::span<r::RouteRule const>{},0,3);
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
    packet.address_length=3;
    if (s::udp_route(*direct,packet,denied).error()!=s::UdpRouteError::invalid_target) return 8;
    std::println("SOCKS UDP domain and candidate routing passed");
}
