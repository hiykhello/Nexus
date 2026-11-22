#include <arpa/inet.h>
#include <cstdlib>
#include <new>
#include <sys/socket.h>
#include <unistd.h>
import std;
import udp.direct;
import rules;
namespace p = ::packet;
namespace u=udp;
namespace { int armed=0; bool fail=false, injected=false; }
void* operator new(std::size_t n) {
    if (fail) { fail=false; injected=true; throw std::bad_alloc(); }
    if (auto* memory=std::malloc(n ? n : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory,std::size_t) noexcept { std::free(memory); }
extern "C" ssize_t __real_recvfrom(int,void*,size_t,int,sockaddr*,socklen_t*);
extern "C" ssize_t __wrap_recvfrom(int fd,void* data,size_t size,int flags,sockaddr* from,socklen_t* length) {
    auto n=__real_recvfrom(fd,data,size,flags,from,length);
    if (armed && n>=0 && (flags & MSG_PEEK) && --armed==0) fail=true;
    return n;
}
struct Socket { int fd; ~Socket() { if (fd>=0) ::close(fd); } };
template<class Direct,class Addr,class Sock> bool scenario(int family,Addr client,Addr loop,Sock address) {
    Socket server{::socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0)};
    if (server.fd<0 || ::bind(server.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) return false;
    socklen_t length=sizeof(address); if (::getsockname(server.fd,reinterpret_cast<sockaddr*>(&address),&length)) return false;
    std::uint16_t port;
    if constexpr (std::is_same_v<Sock,sockaddr_in>) port=ntohs(address.sin_port);
    else port=ntohs(address.sin6_port);
    Direct direct(::rules::Matcher{},u::Mapping::endpoint_independent,u::Filtering::address_port_dependent,{2,2,1000});
    p::Bytes body{'o','k'};
    auto packet=[&] { if constexpr (std::is_same_v<Addr,p::Address4>) return p::make_udp4(client,loop,1234,port,body);
                       else return p::make_udp6(client,loop,1234,port,body); }();
    if (!packet || !direct.submit(*packet,0)) return false;
    std::array<char,16> data{}; sockaddr_storage origin{}; socklen_t origin_size=sizeof(origin);
    auto n=::recvfrom(server.fd,data.data(),data.size(),0,reinterpret_cast<sockaddr*>(&origin),&origin_size);
    if (n!=2 || ::sendto(server.fd,data.data(),n,0,reinterpret_cast<sockaddr*>(&origin),origin_size)!=n) return false;
    armed=1; injected=false; bool caught=false;
    try { (void)direct.poll(1); } catch (std::bad_alloc const&) { caught=true; }
    if (!caught || !injected) return false;
    auto retry=direct.poll(2); if (!retry || retry->size()!=1) return false;
    if constexpr (std::is_same_v<Addr,p::Address4>) { auto view=p::parse_udp4(retry->front()); if (!view || !std::ranges::equal(view->payload,body)) return false; }
    else { auto view=p::parse_udp6(retry->front()); if (!view || !std::ranges::equal(view->payload,body)) return false; }
    auto empty=direct.poll(3); if (!empty || !empty->empty()) return false;
    auto second=[&] { if constexpr (std::is_same_v<Addr,p::Address4>) return p::make_udp4(client,loop,1235,port,body);
                       else return p::make_udp6(client,loop,1235,port,body); }();
    if (!second || !direct.submit(*packet,4) || !direct.submit(*second,4)) return false;
    for (int i=0;i<2;++i) {
        origin_size=sizeof(origin);
        n=::recvfrom(server.fd,data.data(),data.size(),0,reinterpret_cast<sockaddr*>(&origin),&origin_size);
        if (n!=2 || ::sendto(server.fd,data.data(),n,0,reinterpret_cast<sockaddr*>(&origin),origin_size)!=n) return false;
    }
    armed=2; injected=false;
    auto first=direct.poll(5);
    if (!first || first->size()!=1 || !injected) return false;
    caught=false;
    try { (void)direct.poll(6); } catch (std::bad_alloc const&) { caught=true; }
    if (!caught) return false;
    auto last=direct.poll(6);
    if (!last || last->size()!=1) return false;
    std::uint16_t first_port=0,last_port=0;
    if constexpr (std::is_same_v<Addr,p::Address4>) {
        auto a=p::parse_udp4(first->front()), b=p::parse_udp4(last->front());
        if (!a || !b) return false; first_port=a->destination_port; last_port=b->destination_port;
    } else {
        auto a=p::parse_udp6(first->front()), b=p::parse_udp6(last->front());
        if (!a || !b) return false; first_port=a->destination_port; last_port=b->destination_port;
    }
    if (first_port!=1234 || last_port!=1235) return false;
    empty=direct.poll(7); return empty && empty->empty() && direct.stop(8).has_value();
}
int main() {
    sockaddr_in a{}; a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    sockaddr_in6 b{}; b.sin6_family=AF_INET6; b.sin6_addr=in6addr_loopback;
    if (!scenario<u::Direct4>(AF_INET,p::Address4{10,0,0,1},p::Address4{127,0,0,1},a) ||
        !scenario<u::Direct6>(AF_INET6,p::Address6{0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                              p::Address6{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},b)) return 1;
    std::println("UDP IPv4 and IPv6 replies survive allocation failure after peek");
}
