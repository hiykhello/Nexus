#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <new>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.udp.engine;
import nexus.rules;
namespace p=nexus::packet;
namespace u=nexus::udp;
namespace { int remaining=-1; }
void* operator new(std::size_t n) {
    if (remaining>0 && --remaining==0) { remaining=-1; throw std::bad_alloc(); }
    if (auto* memory=std::malloc(n ? n : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory,std::size_t) noexcept { std::free(memory); }
struct Socket { int fd; ~Socket() { if (fd>=0) ::close(fd); } };
auto scenario(int family) -> int {
    int faults=0, successes=0;
    for (int position=1;position<=20;++position) {
        Socket server{::socket(family,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
        sockaddr_storage storage{}; socklen_t length;
        if (family==AF_INET) {
            auto* a=reinterpret_cast<sockaddr_in*>(&storage); a->sin_family=AF_INET; a->sin_addr.s_addr=htonl(INADDR_LOOPBACK); length=sizeof(*a);
        } else {
            auto* a=reinterpret_cast<sockaddr_in6*>(&storage); a->sin6_family=AF_INET6; a->sin6_addr=in6addr_loopback; length=sizeof(*a);
        }
        if (server.fd<0 || ::bind(server.fd,reinterpret_cast<sockaddr*>(&storage),length)) return 1;
        if (::getsockname(server.fd,reinterpret_cast<sockaddr*>(&storage),&length)) return 2;
        p::MemoryLink link;
        u::MemoryEngine engine(link,nexus::rules::Matcher{},u::Mapping::endpoint_independent,
                               u::Filtering::address_port_dependent,{4,4,60000});
        std::array<std::uint8_t,3> payload{'u','d','p'};
        auto packet=family==AF_INET
            ? p::make_udp4({10,0,0,1},{127,0,0,1},1234,ntohs(reinterpret_cast<sockaddr_in*>(&storage)->sin_port),payload)
            : p::make_udp6({0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                           {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},1234,
                           ntohs(reinterpret_cast<sockaddr_in6*>(&storage)->sin6_port),payload);
        if (!packet || !link.send(p::Side::first,*packet)) return 3;
        remaining=position;
        auto result=engine.step(1); remaining=-1;
        if (!result || result->rejected) return 4;
        if (result->input_allocation_failed) ++faults; else ++successes;
        auto retry=engine.step(2); if (!retry || retry->rejected) return 5;
        std::array<std::uint8_t,16> output{};
        auto n=::recv(server.fd,output.data(),output.size(),0);
        if (n!=3 || !std::ranges::equal(std::span(output).first(3),payload)) return 6;
        n=::recv(server.fd,output.data(),output.size(),0);
        if (n>=0 || (errno!=EAGAIN && errno!=EWOULDBLOCK)) return 7;
        if (!engine.stop(3)) return 8;
    }
    if (!faults || !successes) return 9;
    std::println("UDP {} input survives {} allocation faults without duplicate sends",family==AF_INET ? "IPv4" : "IPv6",faults);
    return 0;
}
int main() { return scenario(AF_INET) || scenario(AF_INET6); }
