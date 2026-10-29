#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.udp.engine;
import nexus.rules;
namespace p=nexus::packet;
namespace u=nexus::udp;
namespace { int mode=0, calls=0, blocked_fd=-1; }
extern "C" ssize_t __real_sendto(int,const void*,size_t,int,const sockaddr*,socklen_t);
extern "C" ssize_t __wrap_sendto(int fd,const void* data,size_t size,int flags,const sockaddr* dest,socklen_t length) {
    ++calls;
    if (mode==5) {
        if (blocked_fd<0) blocked_fd=fd;
        if (fd==blocked_fd) { errno=EAGAIN; return -1; }
        return __real_sendto(fd,data,size,flags,dest,length);
    }
    if (!mode) return __real_sendto(fd,data,size,flags,dest,length);
    if (mode==2 && __real_sendto(fd,data,size,flags,dest,length)!=static_cast<ssize_t>(size)) return -1;
    auto fault=mode; mode=0; errno=fault==3 ? EAGAIN : fault==4 ? EINTR : EIO; return -1;
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
auto fairness(int family) -> bool {
    Socket server{::socket(family,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    sockaddr_storage address{}; socklen_t length;
    if (family==AF_INET) {
        auto* a=reinterpret_cast<sockaddr_in*>(&address); a->sin_family=AF_INET; a->sin_addr.s_addr=htonl(INADDR_LOOPBACK); length=sizeof(*a);
    } else {
        auto* a=reinterpret_cast<sockaddr_in6*>(&address); a->sin6_family=AF_INET6; a->sin6_addr=in6addr_loopback; length=sizeof(*a);
    }
    if (server.fd<0 || ::bind(server.fd,reinterpret_cast<sockaddr*>(&address),length) ||
        ::getsockname(server.fd,reinterpret_cast<sockaddr*>(&address),&length)) return false;
    p::MemoryLink link; u::MemoryEngine engine(link,nexus::rules::Matcher{},u::Mapping::endpoint_independent,
                                              u::Filtering::address_port_dependent,{4,2,1000});
    auto make=[&](std::uint16_t source,std::uint8_t value) {
        std::array body{value};
        return family==AF_INET
            ? p::make_udp4({10,0,0,1},{127,0,0,1},source,ntohs(reinterpret_cast<sockaddr_in*>(&address)->sin_port),body)
            : p::make_udp6({0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                           {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},source,
                           ntohs(reinterpret_cast<sockaddr_in6*>(&address)->sin6_port),body);
    };
    auto a=make(1234,'a'), b=make(1234,'b'), c=make(1235,'c');
    if (!a || !b || !c || !link.send(p::Side::first,*a) || !link.send(p::Side::first,*b) || !link.send(p::Side::first,*c)) return false;
    mode=5; blocked_fd=-1;
    auto first=engine.step(1), second=engine.step(2), third=engine.step(3);
    if (!first || !second || !third || !first->input_backpressured || !second->input_backpressured || third->input_backpressured) return false;
    char byte{}; sockaddr_storage from{}; socklen_t from_size=sizeof(from);
    if (::recvfrom(server.fd,&byte,1,0,reinterpret_cast<sockaddr*>(&from),&from_size)!=1 || byte!='c') return false;
    mode=0;
    auto fourth=engine.step(4), fifth=engine.step(5);
    if (!fourth || !fifth || fourth->input_backpressured || fifth->input_backpressured) return false;
    sockaddr_storage first_origin{}, second_origin{}; socklen_t size1=sizeof(first_origin), size2=sizeof(second_origin);
    if (::recvfrom(server.fd,&byte,1,0,reinterpret_cast<sockaddr*>(&first_origin),&size1)!=1 || byte!='a' ||
        ::recvfrom(server.fd,&byte,1,0,reinterpret_cast<sockaddr*>(&second_origin),&size2)!=1 || byte!='b') return false;
    auto port=[](sockaddr_storage const& a) { return a.ss_family==AF_INET
        ? reinterpret_cast<sockaddr_in const*>(&a)->sin_port : reinterpret_cast<sockaddr_in6 const*>(&a)->sin6_port; };
    if (port(first_origin)!=port(second_origin)) return false;
    // Fill the bounded retry queue, leaving one more packet on the link.
    // When backpressure clears, every datagram must retain its original order.
    for (int i=0;i<33;++i) {
        auto packet=make(1234,static_cast<std::uint8_t>(i));
        if (!packet || !link.send(p::Side::first,*packet)) return false;
    }
    mode=5; blocked_fd=-1;
    for (int i=0;i<33;++i) {
        auto blocked=engine.step(6+i);
        if (!blocked || !blocked->input_backpressured || blocked->rejected) return false;
    }
    mode=0;
    for (int i=0;i<33;++i) {
        auto sent=engine.step(39+i);
        if (!sent || sent->input_backpressured || sent->rejected ||
            ::recv(server.fd,&byte,1,0)!=1 || static_cast<std::uint8_t>(byte)!=i) return false;
    }
    if (!link.send(p::Side::first,*a) || !link.send(p::Side::first,*b)) return false;
    mode=5; blocked_fd=-1;
    auto blocked1=engine.step(72), blocked2=engine.step(73);
    if (!blocked1 || !blocked2 || !blocked1->input_backpressured || !blocked2->input_backpressured ||
        !engine.stop(74)) return false;
    mode=0;
    auto after_stop=engine.step(75);
    if (!after_stop || after_stop->input || ::recv(server.fd,&byte,1,0)!=-1 || errno!=EAGAIN) return false;
    return engine.stop(76).has_value();
}
auto transient(int family, int fault) -> bool {
    Socket server{::socket(family,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    sockaddr_storage address{}; socklen_t length;
    if (family==AF_INET) {
        auto* a=reinterpret_cast<sockaddr_in*>(&address); a->sin_family=AF_INET; a->sin_addr.s_addr=htonl(INADDR_LOOPBACK); length=sizeof(*a);
    } else {
        auto* a=reinterpret_cast<sockaddr_in6*>(&address); a->sin6_family=AF_INET6; a->sin6_addr=in6addr_loopback; length=sizeof(*a);
    }
    if (server.fd<0 || ::bind(server.fd,reinterpret_cast<sockaddr*>(&address),length) ||
        ::getsockname(server.fd,reinterpret_cast<sockaddr*>(&address),&length)) return false;
    p::MemoryLink link; u::MemoryEngine engine(link,nexus::rules::Matcher{},u::Mapping::endpoint_independent,
                                              u::Filtering::address_port_dependent,{1,2,1000});
    p::Bytes body{'x'};
    auto packet=family==AF_INET
        ? p::make_udp4({10,0,0,1},{127,0,0,1},1234,ntohs(reinterpret_cast<sockaddr_in*>(&address)->sin_port),body)
        : p::make_udp6({0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                       {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},1234,
                       ntohs(reinterpret_cast<sockaddr_in6*>(&address)->sin6_port),body);
    if (!packet || !link.send(p::Side::first,*packet)) return false;
    mode=0; calls=0; auto first=engine.step(1);
    if (!first || first->rejected || calls!=1) return false;
    std::array<char,16> bytes{}; sockaddr_storage origin{}; socklen_t origin_size=sizeof(origin);
    if (::recvfrom(server.fd,bytes.data(),bytes.size(),0,reinterpret_cast<sockaddr*>(&origin),&origin_size)!=1) return false;
    // A previously authorized response remains valid during transient send failure.
    if (!link.send(p::Side::first,*packet) || ::sendto(server.fd,bytes.data(),1,0,
        reinterpret_cast<sockaddr*>(&origin),origin_size)!=1) return false;
    mode=fault; calls=0; auto blocked=engine.step(2);
    if (!blocked || !blocked->input_backpressured || blocked->rejected || !blocked->delivered || calls!=1) return false;
    auto reply=link.receive(p::Side::first); if (!reply || !*reply) return false;
    auto retried=engine.step(3);
    if (!retried || !retried->input || retried->input_backpressured || retried->rejected || calls!=2) return false;
    sockaddr_storage second{}; socklen_t second_size=sizeof(second);
    if (::recvfrom(server.fd,bytes.data(),bytes.size(),0,reinterpret_cast<sockaddr*>(&second),&second_size)!=1) return false;
    auto port=[](sockaddr_storage const& a) { return a.ss_family==AF_INET
        ? reinterpret_cast<sockaddr_in const*>(&a)->sin_port : reinterpret_cast<sockaddr_in6 const*>(&a)->sin6_port; };
    if (port(origin)!=port(second) || ::recv(server.fd,bytes.data(),bytes.size(),0)>=0 ||
        (errno!=EAGAIN && errno!=EWOULDBLOCK)) return false;
    return engine.stop(4).has_value();
}
int main() {
    for (int family : {AF_INET,AF_INET6}) for (int fault : {1,2}) if (!scenario(family,fault)) return 1;
    for (int family : {AF_INET,AF_INET6}) for (int fault : {3,4}) if (!transient(family,fault)) return 1;
    for (int family : {AF_INET,AF_INET6}) if (!fairness(family)) return 1;
    std::println("UDP transient send errors retry without losing existing flows; permanent errors do not retry");
}
