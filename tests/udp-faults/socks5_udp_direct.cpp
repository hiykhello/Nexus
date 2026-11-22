#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
import std;
import rules;
import socks5.udp_direct;
namespace s=socks5;
namespace r = ::rules;
static bool fail_send=false;
extern "C" ssize_t __real_sendto(int,const void*,size_t,int,const sockaddr*,socklen_t);
extern "C" ssize_t __wrap_sendto(int fd,const void* data,size_t size,int flags,const sockaddr* dest,socklen_t length) {
    if (fail_send) { fail_send=false; errno=EAGAIN; return -1; }
    return __real_sendto(fd,data,size,flags,dest,length);
}
struct Socket { int fd; ~Socket() { if (fd>=0) ::close(fd); } };
static auto ipv6_test() -> bool {
    Socket server{::socket(AF_INET6,SOCK_DGRAM|SOCK_CLOEXEC,0)};
    sockaddr_in6 address{}; address.sin6_family=AF_INET6; address.sin6_addr=in6addr_loopback;
    if (server.fd<0 || ::bind(server.fd,reinterpret_cast<sockaddr*>(&address),sizeof(address))) return false;
    socklen_t length=sizeof(address);
    if (::getsockname(server.fd,reinterpret_cast<sockaddr*>(&address),&length)) return false;
    timeval timeout{2,0}; ::setsockopt(server.fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    auto policy=r::RouteMatcher::compile(std::span<r::RouteRule const>{},0,2);
    s::UdpPeer client{4,{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1},3000};
    s::UdpPeer target=client; target.port=ntohs(address.sin6_port);
    auto association=s::UdpAssociation::create(client,{4,{},0});
    if (!policy || !association) return false;
    s::UdpDirect direct(*association,*policy);
    std::vector<std::uint8_t> wire{0,0,0,4};
    wire.insert(wire.end(),target.address.begin(),target.address.end());
    wire.insert(wire.end(),{static_cast<std::uint8_t>(target.port>>8),static_cast<std::uint8_t>(target.port),'6'});
    auto packet=association->admit(client,wire);
    if (!packet || !direct.send(*packet,target)) return false;
    sockaddr_in6 from{}; length=sizeof(from); char byte{};
    if (::recvfrom(server.fd,&byte,1,0,reinterpret_cast<sockaddr*>(&from),&length)!=1 || byte!='6' ||
        ::sendto(server.fd,"v",1,0,reinterpret_cast<sockaddr*>(&from),length)!=1) return false;
    for (int i=0;i<100;++i) {
        auto result=direct.poll();
        if (!result) return false;
        if (*result) {
            auto response=s::parse_udp_datagram((**result).wire);
            return (**result).client==client && response && response->address_type==4 &&
                response->port==target.port && std::ranges::equal(response->data,std::array<std::uint8_t,1>{'v'});
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return false;
}
int main() {
    Socket server{::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0)}, attacker{::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0)};
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (server.fd<0 || attacker.fd<0 || ::bind(server.fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr)) ||
        ::bind(attacker.fd,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))) return 1;
    socklen_t size=sizeof(addr); if (::getsockname(server.fd,reinterpret_cast<sockaddr*>(&addr),&size)) return 2;
    timeval timeout{2,0}; ::setsockopt(server.fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    auto policy=r::RouteMatcher::compile(std::span<r::RouteRule const>{},0,2);
    auto association=s::UdpAssociation::create({1,{127,0,0,1},1000},{1,{},0});
    if (!policy || !association) return 3;
    s::UdpDirect direct(*association,*policy);
    s::UdpPeer client{1,{127,0,0,1},2000}, target{1,{127,0,0,1},ntohs(addr.sin_port)};
    std::vector<std::uint8_t> wire{0,0,0,1,127,0,0,1,static_cast<std::uint8_t>(target.port>>8),static_cast<std::uint8_t>(target.port),'h','i'};
    auto packet=association->admit(client,wire);
    if (!packet) return 4;
    fail_send=true;
    auto failed=direct.send(*packet,target);
    if (failed || fail_send || association->accepts_reply(target) ||
        !std::holds_alternative<std::error_code>(failed.error()) ||
        std::get<std::error_code>(failed.error())!=std::errc::resource_unavailable_try_again ||
        !direct.send(*packet,target)) return 4;
    std::array<char,32> buffer{}; sockaddr_in from{}; size=sizeof(from);
    if (::recvfrom(server.fd,buffer.data(),buffer.size(),0,reinterpret_cast<sockaddr*>(&from),&size)!=2 ||
        std::string_view(buffer.data(),2)!="hi") return 5;
    if (::sendto(attacker.fd,"X",1,0,reinterpret_cast<sockaddr*>(&from),size)!=1 ||
        ::sendto(server.fd,"ok",2,0,reinterpret_cast<sockaddr*>(&from),size)!=2) return 6;
    std::optional<s::UdpDirectReply> reply;
    for (int i=0;i<100 && !reply;++i) {
        auto result=direct.poll(); if (!result) return 7;
        if (*result) reply=std::move(**result);
        else std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!reply || reply->client!=client) return 8;
    auto decoded=s::parse_udp_datagram(reply->wire);
    if (!decoded || decoded->port!=target.port || decoded->address_type!=1 ||
        !std::ranges::equal(decoded->data,std::array<std::uint8_t,2>{'o','k'})) return 9;
    // Control owner closes the association before the next drive step.
    // That step must close the still-live socket and discard pending replies.
    if (::sendto(server.fd,"late",4,0,reinterpret_cast<sockaddr*>(&from),size)!=4) return 10;
    association->close();
    if (direct.poll().error()!=s::UdpDirectError{s::Status::association_closed}) return 10;
    if (direct.send(*packet,target).error()!=s::UdpDirectError{s::Status::association_closed}) return 10;
    Socket reused{::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0)};
    if (reused.fd<0 || ::bind(reused.fd,reinterpret_cast<sockaddr*>(&from),sizeof(from))) return 11;
    if (!ipv6_test()) return 12;
    std::println("SOCKS UDP direct IPv4/IPv6 sockets retry, filter replies and close");
}
