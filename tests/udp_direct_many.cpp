#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.udp.direct;
import nexus.rules;
namespace p=nexus::packet;
namespace u=nexus::udp;
struct Socket { int fd; ~Socket() { if (fd>=0) ::close(fd); } };
template<class Direct,class Address,class Sock>
auto scenario(int family,Address client,Address loop,Sock address) -> bool {
    Socket server{::socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0)};
    if (server.fd<0 || ::bind(server.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) return false;
    socklen_t length=sizeof(address); if (::getsockname(server.fd,reinterpret_cast<sockaddr*>(&address),&length)) return false;
    std::uint16_t port;
    if constexpr (std::is_same_v<Sock,sockaddr_in>) port=ntohs(address.sin_port);
    else port=ntohs(address.sin6_port);
    Direct direct(nexus::rules::Matcher{},u::Mapping::endpoint_independent,u::Filtering::address_port_dependent,{65,1,1000});
    p::Bytes body{'o','k'};
    std::array<sockaddr_storage,65> origins{};
    std::array<socklen_t,65> origin_sizes{};
    for (int i=0;i<65;++i) {
        auto packet=[&] { if constexpr (std::is_same_v<Address,p::Address4>) return p::make_udp4(client,loop,1000+i,port,body);
                           else return p::make_udp6(client,loop,1000+i,port,body); }();
        if (!packet || !direct.submit(*packet,0)) return false;
        std::array<char,8> buffer{}; sockaddr_storage origin{}; socklen_t size=sizeof(origin);
        auto n=::recvfrom(server.fd,buffer.data(),buffer.size(),0,reinterpret_cast<sockaddr*>(&origin),&size);
        if (n!=2 || ::sendto(server.fd,buffer.data(),n,0,reinterpret_cast<sockaddr*>(&origin),size)!=n) return false;
        origins[i]=origin; origin_sizes[i]=size;
    }
    std::array<bool,65> seen{};
    for (int round=0;round<2;++round) {
        auto replies=direct.poll(round+1);
        if (!replies || replies->size()!=(round==0 ? 64u : 1u)) return false;
        for (auto const& packet : *replies) {
            std::uint16_t destination=0;
            if constexpr (std::is_same_v<Address,p::Address4>) {
                auto view=p::parse_udp4(packet); if (!view || !std::ranges::equal(view->payload,body)) return false;
                destination=view->destination_port;
            } else {
                auto view=p::parse_udp6(packet); if (!view || !std::ranges::equal(view->payload,body)) return false;
                destination=view->destination_port;
            }
            if (destination<1000 || destination>=1065 || seen[destination-1000]) return false;
            seen[destination-1000]=true;
        }
    }
    if (!std::ranges::all_of(seen,[](bool value) { return value; })) return false;
    // Every flow has two queued replies, keeping the early flows active across polls.
    for (int i=0;i<65;++i) for (int copy=0;copy<2;++copy)
        if (::sendto(server.fd,body.data(),body.size(),0,reinterpret_cast<sockaddr*>(&origins[i]),origin_sizes[i])!=2) return false;
    std::array<int,65> counts{};
    for (int round=0;round<3;++round) {
        auto replies=direct.poll(3+round); if (!replies) return false;
        for (auto const& packet : *replies) {
            std::uint16_t destination=0;
            if constexpr (std::is_same_v<Address,p::Address4>) {
                auto view=p::parse_udp4(packet); if (!view) return false; destination=view->destination_port;
            } else {
                auto view=p::parse_udp6(packet); if (!view) return false; destination=view->destination_port;
            }
            if (destination<1000 || destination>=1065 || ++counts[destination-1000]>2) return false;
        }
    }
    if (!std::ranges::all_of(counts,[](int count) { return count==2; })) return false;
    // Keep one flow alive and let the other 64 expire; then create a replacement.
    auto keep=[&] { if constexpr (std::is_same_v<Address,p::Address4>) return p::make_udp4(client,loop,1064,port,body);
                    else return p::make_udp6(client,loop,1064,port,body); }();
    if (!keep || !direct.submit(*keep,900)) return false;
    auto expired=direct.expire(1005); if (!expired || *expired!=64 || direct.size()!=1) return false;
    auto replacement=[&] { if constexpr (std::is_same_v<Address,p::Address4>) return p::make_udp4(client,loop,1065,port,body);
                           else return p::make_udp6(client,loop,1065,port,body); }();
    if (!replacement || !direct.submit(*replacement,1005) || direct.size()!=2) return false;
    return direct.stop(1006).has_value() && direct.size()==0;
}
int main() {
    sockaddr_in a{}; a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    sockaddr_in6 b{}; b.sin6_family=AF_INET6; b.sin6_addr=in6addr_loopback;
    if (!scenario<u::Direct4>(AF_INET,p::Address4{10,0,0,1},p::Address4{127,0,0,1},a) ||
        !scenario<u::Direct6>(AF_INET6,p::Address6{0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                              p::Address6{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},b)) return 1;
    std::println("UDP IPv4 and IPv6 65-flow polling rotates across the 64-flow limit");
}
