#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.rules;
import nexus.socks5.udp_ingress;
namespace s=nexus::socks5; namespace r=nexus::rules;
static bool fail_reply=false;
extern "C" ssize_t __real_sendto(int,const void*,size_t,int,const sockaddr*,socklen_t);
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
    std::println("SOCKS UDP ingress forwards and filters real datagrams");
}
