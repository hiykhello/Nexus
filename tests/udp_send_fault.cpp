#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.udp.engine;
import nexus.rules;
namespace p=nexus::packet;
namespace u=nexus::udp;
namespace { int mode=0, calls=0; }
extern "C" ssize_t __real_sendto(int,const void*,size_t,int,const sockaddr*,socklen_t);
extern "C" ssize_t __wrap_sendto(int fd,const void* data,size_t size,int flags,const sockaddr* dest,socklen_t length) {
    ++calls;
    if (!mode) return __real_sendto(fd,data,size,flags,dest,length);
    if (mode==2 && __real_sendto(fd,data,size,flags,dest,length)!=static_cast<ssize_t>(size)) return -1;
    mode=0; errno=EIO; return -1;
}
struct Socket { int fd; ~Socket() { if (fd>=0) ::close(fd); } };
auto scenario(int family,int fault) -> bool {
    Socket server{::socket(family,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    sockaddr_storage storage{}; socklen_t length;
    if (family==AF_INET) {
        auto* a=reinterpret_cast<sockaddr_in*>(&storage); a->sin_family=AF_INET; a->sin_addr.s_addr=htonl(INADDR_LOOPBACK); length=sizeof(*a);
    } else {
        auto* a=reinterpret_cast<sockaddr_in6*>(&storage); a->sin6_family=AF_INET6; a->sin6_addr=in6addr_loopback; length=sizeof(*a);
    }
    if (server.fd<0 || ::bind(server.fd,reinterpret_cast<sockaddr*>(&storage),length) ||
        ::getsockname(server.fd,reinterpret_cast<sockaddr*>(&storage),&length)) return false;
    p::MemoryLink link;
    u::MemoryEngine engine(link,nexus::rules::Matcher{},u::Mapping::endpoint_independent,u::Filtering::address_port_dependent,{1,2,1000});
    p::Bytes body{'u','d','p'};
    auto packet=family==AF_INET
        ? p::make_udp4({10,0,0,1},{127,0,0,1},1234,ntohs(reinterpret_cast<sockaddr_in*>(&storage)->sin_port),body)
        : p::make_udp6({0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                       {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},1234,
                       ntohs(reinterpret_cast<sockaddr_in6*>(&storage)->sin6_port),body);
    if (!packet || !link.send(p::Side::first,*packet)) return false;
    mode=fault; calls=0; auto step=engine.step(1);
    if (!step || !step->input || !step->rejected || !std::holds_alternative<std::error_code>(*step->rejected) ||
        std::get<std::error_code>(*step->rejected)!=std::error_code(EIO,std::generic_category()) || calls!=1) return false;
    auto retry=engine.step(2); if (!retry || retry->input || retry->rejected || calls!=1) return false;
    std::array<char,16> bytes{}; auto n=::recv(server.fd,bytes.data(),bytes.size(),0);
    if (fault==2) {
        if (n!=3 || !std::ranges::equal(std::span(bytes).first(3),body)) return false;
        n=::recv(server.fd,bytes.data(),bytes.size(),0);
    }
    if (n>=0 || (errno!=EAGAIN && errno!=EWOULDBLOCK)) return false;
    // The failed flow must release its only slot, even when the first datagram reached the server.
    if (!link.send(p::Side::first,*packet)) return false;
    auto next=engine.step(3);
    if (!next || !next->input || next->rejected || calls!=2) return false;
    sockaddr_storage origin{}; socklen_t origin_size=sizeof(origin);
    n=::recvfrom(server.fd,bytes.data(),bytes.size(),0,reinterpret_cast<sockaddr*>(&origin),&origin_size);
    if (n!=3 || !std::ranges::equal(std::span(bytes).first(3),body) ||
        ::sendto(server.fd,bytes.data(),n,0,reinterpret_cast<sockaddr*>(&origin),origin_size)!=n) return false;
    auto response=engine.step(4);
    if (!response || !response->delivered || response->rejected) return false;
    auto reply=link.receive(p::Side::first);
    if (!reply || !*reply) return false;
    if (family==AF_INET) {
        auto view=p::parse_udp4(**reply); if (!view || !std::ranges::equal(view->payload,body)) return false;
    } else {
        auto view=p::parse_udp6(**reply); if (!view || !std::ranges::equal(view->payload,body)) return false;
    }
    return engine.stop(5).has_value();
}
int main() {
    for (int family : {AF_INET,AF_INET6}) for (int fault : {1,2}) if (!scenario(family,fault)) return 1;
    std::println("UDP send failures before or after delivery do not cause automatic retries");
}
