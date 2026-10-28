#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.rules;
import nexus.shadowsocks.udp_route;
import nexus.shadowsocks.udp_packet;
namespace s=nexus::shadowsocks;
int main() {
    auto policy=nexus::rules::Matcher::compile({{{"ip-cidr","192.0.2.0/24"},{"ip-cidr","2001:db8::/32"},
        {"ip-cidr","::ffff:127.0.0.0/104"},{"domain-suffix","blocked.example"}}});
    if (!policy) return 1;
    s::UdpRoutedServer server(std::move(*policy),4,4);
    std::array<std::uint8_t,16> key{}; s::UdpPeer client{4,{127,0,0,1},1000};
    auto t=std::chrono::steady_clock::time_point{};
    s::UdpPacket packet{{1},0,1000,{}, {1,192,0,2,1,0,80}, {1}};
    auto receive=[&] { auto wire=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
        return server.receive(key,wire,client,t,1000); };
    auto is_error=[](std::expected<void,s::UdpRoutedFailure> const& result,s::UdpRouteError expected) {
        return !result && std::get_if<s::UdpRouteError>(&result.error()) && std::get<s::UdpRouteError>(result.error())==expected;
    };
    auto accepted=receive();
    s::UdpPeer blocked{4,{192,0,2,1},80};
    if (!accepted || !is_error(server.forward(*accepted,blocked),s::UdpRouteError::blocked) || server.sockets()!=0) return 2;
    s::UdpPeer different{4,{192,0,2,2},80};
    if (!is_error(server.forward(*accepted,different),s::UdpRouteError::invalid_target)) return 3;
    packet.packet_id++; packet.address={3,15,'b','l','o','c','k','e','d','.','e','x','a','m','p','l','e',0,80};
    accepted=receive();
    if (!accepted || server.preflight(*accepted).error()!=s::UdpRouteError::blocked || server.sockets()!=0) return 4;
    packet.packet_id++; packet.address={3,7,'o','k','.','t','e','s','t',0,80}; accepted=receive();
    if (!accepted || !server.preflight(*accepted) || !is_error(server.forward(*accepted,blocked),s::UdpRouteError::blocked)) return 5;
    s::UdpPeer v6{6,{0x20,0x01,0x0d,0xb8},80};
    if (!is_error(server.forward(*accepted,v6),s::UdpRouteError::blocked)) return 6;
    s::UdpPeer mapped{6,{0,0,0,0,0,0,0,0,0,0,255,255,127,0,0,1},80};
    packet.packet_id++; packet.address={4,0,0,0,0,0,0,0,0,0,0,255,255,127,0,0,1,0,80}; accepted=receive();
    s::UdpPeer ipv4{4,{127,0,0,1},80};
    if (!accepted || !is_error(server.forward(*accepted,ipv4),s::UdpRouteError::blocked) ||
        !is_error(server.forward(*accepted,mapped),s::UdpRouteError::blocked)) return 7;
    packet.packet_id++; packet.address={3,7,'o','k','.','t','e','s','t',0,80}; accepted=receive();
    s::UdpPeer mapped_blocked{6,{0,0,0,0,0,0,0,0,0,0,255,255,192,0,2,1},80};
    if (!accepted || !is_error(server.forward(*accepted,mapped_blocked),s::UdpRouteError::blocked) || server.sockets()!=0) return 11;
    int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0); sockaddr_in addr{};
    addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (fd<0 || bind(fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))) return 8;
    socklen_t len=sizeof(addr); getsockname(fd,reinterpret_cast<sockaddr*>(&addr),&len);
    timeval timeout{2,0}; setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    auto port=ntohs(addr.sin_port); packet.packet_id++;
    packet.address={1,127,0,0,1,static_cast<std::uint8_t>(port>>8),static_cast<std::uint8_t>(port)};
    accepted=receive(); ipv4.port=port;
    if (!accepted || !server.forward(*accepted,ipv4) || server.sockets()!=1) return 9;
    std::array<std::uint8_t,8> data{}; if (recv(fd,data.data(),data.size(),0)!=1 || data[0]!=1) return 10;
    // Ordered policies must preserve first-match semantics across domain/IP.
    auto ordered_test=[&](std::vector<nexus::rules::RouteRule> rules,std::size_t fallback,
                          std::optional<s::UdpRouteError> preflight_error,
                          std::optional<s::UdpRouteError> forward_error) {
        auto compiled=nexus::rules::RouteMatcher::compile(rules,fallback,3);
        if (!compiled) return false;
        s::UdpRoutedServer routed(std::move(*compiled),4,4);
        s::UdpPacket query{{9},0,1000,{}, {3,7,'o','k','.','t','e','s','t',static_cast<std::uint8_t>(port>>8),static_cast<std::uint8_t>(port)}, {7}};
        auto wire=*s::encode_udp_packet(key,s::UdpDirection::client,query,{});
        auto request=routed.receive(key,wire,client,t,1000);
        if (!request) return false;
        auto before=routed.preflight(*request);
        if (preflight_error) return !before && before.error()==*preflight_error && routed.sockets()==0;
        if (!before) return false;
        auto result=routed.forward(*request,ipv4);
        if (forward_error) return is_error(result,*forward_error) && routed.sockets()==0;
        return result && recv(fd,data.data(),data.size(),0)==1 && data[0]==7;
    };
    nexus::rules::RuleSet domain{{{"domain-suffix","ok.test"}}};
    nexus::rules::RuleSet loopback{{{"ip-cidr","127.0.0.0/8"}}};
    if (!ordered_test({{domain,0},{loopback,1}},1,{},{})) return 12;
    if (!ordered_test({{loopback,1},{domain,0}},0,{},s::UdpRouteError::blocked)) return 13;
    if (!ordered_test({{domain,2}},0,s::UdpRouteError::unsupported,{})) return 14;
    if (!ordered_test({{loopback,2}},0,{},s::UdpRouteError::unsupported)) return 15;
    if (!ordered_test({{domain,1}},0,s::UdpRouteError::blocked,{})) return 16;
    ::close(fd);
    std::println("SS-2022 UDP route policy passed");
}
