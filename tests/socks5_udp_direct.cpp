#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.rules;
import nexus.socks5.udp_direct;
namespace s=nexus::socks5;
namespace r=nexus::rules;
struct Socket { int fd; ~Socket() { if (fd>=0) ::close(fd); } };
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
    if (!packet || !direct.send(*packet,target)) return 4;
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
    direct.close();
    if (direct.poll().error()!=s::UdpDirectError{s::Status::association_closed}) return 10;
    Socket reused{::socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0)};
    if (reused.fd<0 || ::bind(reused.fd,reinterpret_cast<sockaddr*>(&from),sizeof(from))) return 11;
    std::println("SOCKS UDP direct socket filters reply sources and closes");
}
