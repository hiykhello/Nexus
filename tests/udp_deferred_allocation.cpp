#include <arpa/inet.h>
#include <cstdlib>
#include <new>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.udp.engine;
import nexus.rules;
namespace p=nexus::packet;
namespace u=nexus::udp;
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
auto scenario(int family) -> bool {
    Socket server{::socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0)};
    sockaddr_storage address{}; socklen_t length;
    if (family==AF_INET) { auto* a=reinterpret_cast<sockaddr_in*>(&address); a->sin_family=AF_INET; a->sin_addr.s_addr=htonl(INADDR_LOOPBACK); length=sizeof(*a); }
    else { auto* a=reinterpret_cast<sockaddr_in6*>(&address); a->sin6_family=AF_INET6; a->sin6_addr=in6addr_loopback; length=sizeof(*a); }
    if (server.fd<0 || ::bind(server.fd,reinterpret_cast<sockaddr*>(&address),length) ||
        ::getsockname(server.fd,reinterpret_cast<sockaddr*>(&address),&length)) return false;
    p::MemoryLink link({1500,1,1500});
    u::MemoryEngine engine(link,nexus::rules::Matcher{},u::Mapping::endpoint_independent,u::Filtering::address_port_dependent,{2,2,1000});
    p::Bytes body{'o','k'}, sentinel{42};
    std::array<sockaddr_storage,2> origins{}; std::array<socklen_t,2> sizes{};
    for (int i=0;i<2;++i) {
        auto request=family==AF_INET
            ? p::make_udp4({10,0,0,1},{127,0,0,1},1234+i,ntohs(reinterpret_cast<sockaddr_in*>(&address)->sin_port),body)
            : p::make_udp6({0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                           {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},1234+i,
                           ntohs(reinterpret_cast<sockaddr_in6*>(&address)->sin6_port),body);
        if (!request || !link.send(p::Side::first,*request) || !engine.step(i)) return false;
        std::array<char,8> data{}; sockaddr_storage origin{}; socklen_t size=sizeof(origin);
        auto n=::recvfrom(server.fd,data.data(),data.size(),0,reinterpret_cast<sockaddr*>(&origin),&size);
        if (n!=2) return false;
        origins[i]=origin; sizes[i]=size;
    }
    for (int i=0;i<2;++i)
        if (::sendto(server.fd,body.data(),body.size(),0,reinterpret_cast<sockaddr*>(&origins[i]),sizes[i])!=2) return false;
    if (!link.send(p::Side::second,sentinel)) return false;
    armed=2; injected=false;
    auto first=engine.step(2);
    if (!first || !injected || !first->backpressured || first->ipv4_allocation_failed || first->ipv6_allocation_failed) return false;
    auto stalled=engine.step(3); if (!stalled || !stalled->backpressured || stalled->ipv4_allocation_failed || stalled->ipv6_allocation_failed) return false;
    auto discarded=link.receive(p::Side::first); if (!discarded || !*discarded || **discarded!=sentinel) return false;
    auto delivered=engine.step(4); if (!delivered || !delivered->delivered) return false;
    auto one=link.receive(p::Side::first); if (!one || !*one) return false;
    auto fault=engine.step(5);
    if (!fault || fault->ipv4_allocation_failed!=(family==AF_INET) || fault->ipv6_allocation_failed!=(family==AF_INET6) || fault->delivered) return false;
    auto recovered=engine.step(6); if (!recovered || !recovered->delivered) return false;
    auto two=link.receive(p::Side::first); if (!two || !*two) return false;
    std::uint16_t a=0,b=0;
    if (family==AF_INET) { auto x=p::parse_udp4(**one), y=p::parse_udp4(**two); if (!x || !y) return false; a=x->destination_port; b=y->destination_port; }
    else { auto x=p::parse_udp6(**one), y=p::parse_udp6(**two); if (!x || !y) return false; a=x->destination_port; b=y->destination_port; }
    return a==1234 && b==1235 && engine.stop(7).has_value();
}
int main() {
    if (!scenario(AF_INET) || !scenario(AF_INET6)) return 1;
    std::println("UDP engine drains queued replies before reporting deferred allocation failure");
}
