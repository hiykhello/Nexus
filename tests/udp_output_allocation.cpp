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
namespace { bool armed=false, fail=false, injected=false; }
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
    if (armed && n>=0 && !(flags & MSG_PEEK) && !from) { armed=false; fail=true; }
    return n;
}
struct Socket { int fd; ~Socket() { if (fd>=0) ::close(fd); } };
int main() {
    Socket server{::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0)};
    sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (server.fd<0 || ::bind(server.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) return 1;
    socklen_t length=sizeof(address); if (::getsockname(server.fd,reinterpret_cast<sockaddr*>(&address),&length)) return 2;
    auto policy=nexus::rules::Matcher::compile({{{"ip-cidr","192.0.2.0/24"}}}); if (!policy) return 3;
    p::MemoryLink link;
    u::MemoryEngine engine(link,std::move(*policy),u::Mapping::endpoint_independent,u::Filtering::address_port_dependent,{2,2,1000});
    p::Bytes body{'o','k'};
    auto request=p::make_udp4({10,0,0,1},{127,0,0,1},1234,ntohs(address.sin_port),body);
    if (!request || !link.send(p::Side::first,*request) || !engine.step(0)) return 4;
    std::array<char,8> data{}; sockaddr_storage origin{}; socklen_t size=sizeof(origin);
    auto n=::recvfrom(server.fd,data.data(),data.size(),0,reinterpret_cast<sockaddr*>(&origin),&size);
    if (n!=2 || ::sendto(server.fd,data.data(),n,0,reinterpret_cast<sockaddr*>(&origin),size)!=n) return 5;
    auto blocked=p::make_udp4({10,0,0,1},{192,0,2,1},1234,53,body);
    if (!blocked || !link.send(p::Side::first,*blocked)) return 6;
    armed=true; auto result=engine.step(1);
    if (!result || !injected || !result->input || !result->rejected || !result->backpressured || result->delivered) return 7;
    for (std::uint64_t now=2;now<5;++now) {
        fail=true; auto retry=engine.step(now);
        if (!retry || !retry->backpressured || retry->delivered) return 8;
    }
    auto retry=engine.step(5); if (!retry || !retry->delivered) return 9;
    auto reply=link.receive(p::Side::first); if (!reply || !*reply) return 10;
    auto view=p::parse_udp4(**reply); if (!view || !std::ranges::equal(view->payload,body)) return 11;
    auto empty=link.receive(p::Side::first); if (!empty || *empty || !engine.stop(6)) return 12;
    std::println("UDP output allocation failures preserve reply and same-step rejection");
}
