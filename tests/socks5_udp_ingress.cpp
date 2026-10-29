#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.rules;
import nexus.socks5.udp_ingress;
namespace s=nexus::socks5; namespace r=nexus::rules;
static bool fail_reply=false;
static int receive_error=0;
extern "C" ssize_t __real_sendto(int,const void*,size_t,int,const sockaddr*,socklen_t);
extern "C" ssize_t __real_recvfrom(int,void*,size_t,int,sockaddr*,socklen_t*);
extern "C" ssize_t __wrap_recvfrom(int fd,void* data,size_t size,int flags,sockaddr* source,socklen_t* length) {
    if (receive_error) { errno=std::exchange(receive_error,0); return -1; }
    return __real_recvfrom(fd,data,size,flags,source,length);
}
extern "C" ssize_t __wrap_sendto(int fd,const void* data,size_t size,int flags,const sockaddr* dest,socklen_t length) {
    if (fail_reply) { fail_reply=false; errno=EAGAIN; return -1; }
    return __real_sendto(fd,data,size,flags,dest,length);
}
struct Socket { int fd; ~Socket() { if(fd>=0) ::close(fd); } };
int main() {
    Socket client{::socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)},
           attacker{::socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)},
           target{::socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (client.fd<0 || attacker.fd<0 || target.fd<0 || ::bind(client.fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr)) ||
        ::bind(attacker.fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr)) || ::bind(target.fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))) return 1;
    socklen_t length=sizeof(addr); if (::getsockname(target.fd,reinterpret_cast<sockaddr*>(&addr),&length)) return 2;
    auto target_port=ntohs(addr.sin_port);
    auto policy=r::RouteMatcher::compile(std::span<r::RouteRule const>{},0,2);
    auto association=s::UdpAssociation::create({1,{127,0,0,1},1234},{1,{},0});
    if (!policy || !association) return 3;
    s::UdpIngress driver(*association,*policy);
    auto local=driver.open({1,{127,0,0,1},0}); if (!local || !local->port) return 4;
    sockaddr_in relay{}; relay.sin_family=AF_INET; relay.sin_addr.s_addr=htonl(INADDR_LOOPBACK); relay.sin_port=htons(local->port);
    std::vector<std::uint8_t> wire{0,0,0,1,127,0,0,1,static_cast<std::uint8_t>(target_port>>8),static_cast<std::uint8_t>(target_port),'h','i'};
    if (::sendto(client.fd,wire.data(),wire.size(),0,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))!=static_cast<ssize_t>(wire.size())) return 5;
    fail_reply=true;
    auto blocked_input=driver.step();
    if (!blocked_input || !blocked_input->input_backpressured || blocked_input->forwarded || fail_reply ||
        association->accepts_reply({1,{127,0,0,1},target_port})) return 5;
    bool sent=false; char bytes[32]{}; sockaddr_in origin{}; length=sizeof(origin); ssize_t n=-1;
    for(int i=0;i<100 && n<0;++i) {
        auto result=driver.step(); if (!result || result->input_error || result->output_error) return 6;
        sent |= result->forwarded;
        n=::recvfrom(target.fd,bytes,sizeof(bytes),0,reinterpret_cast<sockaddr*>(&origin),&length);
        if (n<0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!sent || n!=2 || std::string_view(bytes,2)!="hi") return 7;
    if (::sendto(attacker.fd,wire.data(),wire.size(),0,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))!=static_cast<ssize_t>(wire.size())) return 8;
    bool rejected=false;
    for(int i=0;i<100 && !rejected;++i) { auto result=driver.step(); if (!result) return 9;
        rejected=result->input_error && *result->input_error==s::UdpDirectError{s::Status::unauthorized_source}; }
    if (!rejected || ::sendto(target.fd,"ok",2,0,reinterpret_cast<sockaddr*>(&origin),length)!=2) return 10;
    fail_reply=true; bool blocked=false;
    for(int i=0;i<100 && !blocked;++i) { auto result=driver.step(); if (!result || result->output_error) return 11;
        blocked=result->backpressured; if (!blocked) std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    if (!blocked || fail_reply) return 11;
    std::array<std::uint8_t,64> response{}; n=-1;
    for(int i=0;i<100 && n<0;++i) { auto result=driver.step(); if (!result || result->output_error) return 11;
        n=::recv(client.fd,response.data(),response.size(),0); if (n<0) std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    if (n<0) return 12;
    auto parsed=s::parse_udp_datagram(std::span(response).first(n));
    if (!parsed || parsed->port!=target_port || !std::ranges::equal(parsed->data,std::array<std::uint8_t,2>{'o','k'})) return 13;
    association->close(); auto stopped=driver.step();
    if (stopped || stopped.error()!=s::UdpDirectError{s::Status::association_closed}) return 14;
    Socket reuse{::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0)};
    if (reuse.fd<0 || ::bind(reuse.fd,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))) return 15;
    auto second=s::UdpAssociation::create({1,{127,0,0,1},1234},{1,{},0});
    if (!second) return 16;
    s::UdpIngress faulty(*second,*policy);
    auto endpoint=faulty.open({1,{127,0,0,1},0}); if (!endpoint) return 17;
    for (int temporary : {EAGAIN,EINTR}) {
        receive_error=temporary;
        auto result=faulty.step();
        if (!result || result->input_error || receive_error) return 18;
    }
    receive_error=EIO;
    auto failed=faulty.step();
    if (failed || failed.error()!=s::UdpDirectError{std::error_code(EIO,std::generic_category())} || receive_error) return 19;
    auto closed=faulty.step();
    if (closed || closed.error()!=s::UdpDirectError{s::Status::association_closed}) return 20;
    Socket recovered{::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0)};
    relay.sin_port=htons(endpoint->port);
    if (recovered.fd<0 || ::bind(recovered.fd,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))) return 21;
    auto third=s::UdpAssociation::create({1,{127,0,0,1},1234},{1,{},0});
    if (!third) return 22;
    s::UdpIngress domains(*third,*policy,true);
    auto domain_endpoint=domains.open({1,{127,0,0,1},0}); if (!domain_endpoint) return 23;
    relay.sin_port=htons(domain_endpoint->port);
    std::vector<std::uint8_t> named{0,0,0,3,4,'t','e','s','t',static_cast<std::uint8_t>(target_port>>8),static_cast<std::uint8_t>(target_port),'d'};
    if (::sendto(client.fd,named.data(),named.size(),0,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))!=static_cast<ssize_t>(named.size())) return 24;
    auto waiting=domains.step(); auto request=domains.pending_domain();
    if (!waiting || !waiting->domain_pending || !request || request->address_type!=3 || request->data.size()!=1 || request->data[0]!='d') return 25;
    if (domains.send_resolved({1,{127,0,0,1},static_cast<std::uint16_t>(target_port+1)}) || !domains.pending_domain()) return 26;
    fail_reply=true;
    auto retry=domains.send_resolved({1,{127,0,0,1},target_port});
    if (retry || !domains.pending_domain() || third->accepts_reply({1,{127,0,0,1},target_port})) return 33;
    if (!domains.send_resolved({1,{127,0,0,1},target_port}) || domains.pending_domain()) return 27;
    length=sizeof(origin); n=::recvfrom(target.fd,bytes,sizeof(bytes),0,reinterpret_cast<sockaddr*>(&origin),&length);
    if (n!=1 || bytes[0]!='d') return 28;
    if (::sendto(client.fd,named.data(),named.size(),0,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))!=static_cast<ssize_t>(named.size()) ||
        ::sendto(target.fd,"r",1,0,reinterpret_cast<sockaddr*>(&origin),length)!=1) return 29;
    bool delivered=false;
    for (int i=0;i<100 && !delivered;++i) {
        auto result=domains.step(); if (!result || !result->domain_pending || result->output_error) return 30;
        delivered=result->delivered;
        if (!delivered) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!delivered || !domains.pending_domain() || ::recv(client.fd,response.data(),response.size(),0)<0) return 31;
    domains.discard_domain();
    if (domains.pending_domain() || domains.send_resolved({1,{127,0,0,1},target_port})) return 32;
    r::RuleSet blocked_name{{{"domain-suffix","test"}}};
    auto deny=r::RouteMatcher::compile(std::array{r::RouteRule{blocked_name,1}},0,2);
    auto fourth=s::UdpAssociation::create({1,{127,0,0,1},1234},{1,{},0});
    if (!deny || !fourth) return 34;
    s::UdpIngress blocked_driver(*fourth,*deny,true);
    auto block_endpoint=blocked_driver.open({1,{127,0,0,1},0}); if (!block_endpoint) return 35;
    relay.sin_port=htons(block_endpoint->port);
    if (::sendto(client.fd,named.data(),named.size(),0,reinterpret_cast<sockaddr*>(&relay),sizeof(relay))!=static_cast<ssize_t>(named.size())) return 36;
    auto denied=blocked_driver.step();
    if (!denied || denied->domain_pending || blocked_driver.pending_domain() ||
        !denied->input_error || *denied->input_error!=s::UdpDirectError{s::UdpRouteError::blocked}) return 37;
    s::UdpPeer loopback6{4,{},0}; loopback6.address[15]=1;
    auto fifth=s::UdpAssociation::create(loopback6,{4,{},0});
    if (!fifth) return 38;
    s::UdpIngress invalid6(*fifth,*policy);
    auto wildcard6=loopback6; wildcard6.address[15]=0;
    auto mapped6=wildcard6; mapped6.address[10]=255; mapped6.address[11]=255; mapped6.address[12]=127; mapped6.address[15]=1;
    if (invalid6.open(wildcard6) || invalid6.open(mapped6)) return 60;
    s::UdpIngress ipv6(*fifth,*policy);
    auto endpoint6=ipv6.open(loopback6); if (!endpoint6) return 39;
    Socket client6{::socket(AF_INET6,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    Socket attacker6{::socket(AF_INET6,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    sockaddr_in6 addr6{}; addr6.sin6_family=AF_INET6; addr6.sin6_addr=in6addr_loopback;
    if (client6.fd<0 || attacker6.fd<0 || ::bind(client6.fd,reinterpret_cast<sockaddr*>(&addr6),sizeof(addr6)) ||
        ::bind(attacker6.fd,reinterpret_cast<sockaddr*>(&addr6),sizeof(addr6))) return 40;
    addr6.sin6_port=htons(endpoint6->port);
    if (::sendto(client6.fd,wire.data(),wire.size(),0,reinterpret_cast<sockaddr*>(&addr6),sizeof(addr6))!=static_cast<ssize_t>(wire.size())) return 41;
    bool forwarded6=false; n=-1;
    for (int i=0;i<100 && n<0;++i) {
        auto result=ipv6.step(); if (!result || result->input_error || result->output_error) return 42;
        forwarded6 |= result->forwarded; length=sizeof(origin);
        n=::recvfrom(target.fd,bytes,sizeof(bytes),0,reinterpret_cast<sockaddr*>(&origin),&length);
        if (n<0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!forwarded6 || n!=2 || std::string_view(bytes,2)!="hi") return 43;
    if (::sendto(attacker6.fd,wire.data(),wire.size(),0,reinterpret_cast<sockaddr*>(&addr6),sizeof(addr6))!=static_cast<ssize_t>(wire.size())) return 44;
    auto rejected6=ipv6.step();
    if (!rejected6 || !rejected6->input_error || *rejected6->input_error!=s::UdpDirectError{s::Status::unauthorized_source}) return 45;
    if (::sendto(target.fd,"v6",2,0,reinterpret_cast<sockaddr*>(&origin),length)!=2) return 46;
    n=-1;
    for (int i=0;i<100 && n<0;++i) {
        auto result=ipv6.step(); if (!result || result->output_error) return 47;
        n=::recv(client6.fd,response.data(),response.size(),0);
        if (n<0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (n<0) return 48;
    parsed=s::parse_udp_datagram(std::span(response).first(n));
    if (!parsed || !std::ranges::equal(parsed->data,std::array<std::uint8_t,2>{'v','6'})) return 49;
    Socket target6{::socket(AF_INET6,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0)};
    sockaddr_in6 upstream6{}; upstream6.sin6_family=AF_INET6; upstream6.sin6_addr=in6addr_loopback;
    if (target6.fd<0 || ::bind(target6.fd,reinterpret_cast<sockaddr*>(&upstream6),sizeof(upstream6))) return 51;
    length=sizeof(upstream6);
    if (::getsockname(target6.fd,reinterpret_cast<sockaddr*>(&upstream6),&length)) return 52;
    s::UdpDatagram packet6; packet6.address_type=4; packet6.address_length=16; packet6.address[15]=1;
    packet6.port=ntohs(upstream6.sin6_port); std::array<std::uint8_t,1> payload6{'6'}; packet6.data=payload6;
    auto wire6=s::encode_udp_datagram(packet6); if (!wire6) return 53;
    if (::sendto(client6.fd,wire6->data(),wire6->size(),0,reinterpret_cast<sockaddr*>(&addr6),sizeof(addr6))!=static_cast<ssize_t>(wire6->size())) return 54;
    sockaddr_in6 origin6{}; n=-1;
    for (int i=0;i<100 && n<0;++i) {
        auto result=ipv6.step(); if (!result || result->input_error || result->output_error) return 55;
        length=sizeof(origin6); n=::recvfrom(target6.fd,bytes,sizeof(bytes),0,reinterpret_cast<sockaddr*>(&origin6),&length);
        if (n<0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (n!=1 || bytes[0]!='6' || ::sendto(target6.fd,"z",1,0,reinterpret_cast<sockaddr*>(&origin6),length)!=1) return 56;
    n=-1;
    for (int i=0;i<100 && n<0;++i) {
        auto result=ipv6.step(); if (!result || result->output_error) return 57;
        n=::recv(client6.fd,response.data(),response.size(),0);
        if (n<0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (n<0) return 58;
    parsed=s::parse_udp_datagram(std::span(response).first(n));
    if (!parsed || parsed->address_type!=4 || parsed->port!=packet6.port || parsed->data.size()!=1 || parsed->data[0]!='z') return 59;
    ipv6.close();
    Socket reuse6{::socket(AF_INET6,SOCK_DGRAM|SOCK_CLOEXEC,0)};
    if (reuse6.fd<0 || ::bind(reuse6.fd,reinterpret_cast<sockaddr*>(&addr6),sizeof(addr6))) return 50;
    std::println("SOCKS UDP ingress forwards and filters real datagrams");
}
