#include <arpa/inet.h>
#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>
import std;
import rules;
import net.udp_route;
import uot.direct;
namespace n=net;
namespace r = ::rules;
namespace s=socks5;
namespace u=uot;
static bool fail_send=false;
extern "C" ssize_t __real_sendto(int,const void*,size_t,int,const sockaddr*,socklen_t);
extern "C" ssize_t __wrap_sendto(int fd,const void* data,size_t size,int flags,const sockaddr* to,socklen_t length) {
    if (fail_send) { fail_send=false; errno=EAGAIN; return -1; }
    return __real_sendto(fd,data,size,flags,to,length);
}
struct Socket { int fd; ~Socket(){if(fd>=0) ::close(fd);} };
auto run(int family) -> bool {
    Socket good{::socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0)}, bad{::socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0)};
    if (good.fd<0 || bad.fd<0) return false;
    sockaddr_storage addr{}; socklen_t len;
    if (family==AF_INET) { auto& a=*reinterpret_cast<sockaddr_in*>(&addr); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); len=sizeof(a); }
    else { auto& a=*reinterpret_cast<sockaddr_in6*>(&addr); a.sin6_family=AF_INET6; a.sin6_addr=in6addr_loopback; len=sizeof(a); }
    if (::bind(good.fd,reinterpret_cast<sockaddr*>(&addr),len) || ::bind(bad.fd,reinterpret_cast<sockaddr*>(&addr),len)) return false;
    auto make_peer=[&](int fd) {
        sockaddr_storage a{}; socklen_t l=sizeof(a); n::UdpEndpoint p{};
        if (::getsockname(fd,reinterpret_cast<sockaddr*>(&a),&l)) return p;
        if (family==AF_INET) { p={4,{127,0,0,1},ntohs(reinterpret_cast<sockaddr_in*>(&a)->sin_port)}; }
        else { p.family=6; p.address[15]=1; p.port=ntohs(reinterpret_cast<sockaddr_in6*>(&a)->sin6_port); }
        return p;
    };
    auto good_peer=make_peer(good.fd), bad_peer=make_peer(bad.fd);
    auto direct_policy=r::RouteMatcher::compile(std::span<r::RouteRule const>{},0,3);
    auto block_policy=r::RouteMatcher::compile(std::span<r::RouteRule const>{},1,3);
    auto tunnel_policy=r::RouteMatcher::compile(std::span<r::RouteRule const>{},2,3);
    if (!direct_policy || !block_policy || !tunnel_policy) return false;
    n::UdpTarget packet{family==AF_INET ? n::UdpTargetKind::ipv4 : n::UdpTargetKind::ipv6,
        std::span{good_peer.address}.first(family==AF_INET ? 4 : 16),good_peer.port};
    std::array<std::uint8_t,2> data{'o','k'};
    r::RuleSet source_rules{{{"source-port","1234",{}}},2};
    auto source_policy=r::RouteMatcher::compile(std::array{r::RouteRule{source_rules,1}},0,2,r::SourceMetadata::provided);
    if (!source_policy) return false;
    n::UdpEndpoint source{4,{127,0,0,1},1234};
    u::Direct source_blocked(*source_policy);
    auto denied=source_blocked.send(packet,good_peer,data,&source);
    if (denied || denied.error()!=u::DirectError{n::UdpRouteError::blocked}) return false;
    u::Direct blocked(*block_policy), unsupported(*tunnel_policy), direct(*direct_policy);
    auto blocked_result=blocked.send(packet,good_peer,data), unsupported_result=unsupported.send(packet,good_peer,data);
    if (blocked_result || blocked_result.error()!=u::DirectError{n::UdpRouteError::blocked} ||
        unsupported_result || unsupported_result.error()!=u::DirectError{n::UdpRouteError::unsupported} || !direct.send(packet,good_peer,data)) return false;
    timeval timeout{2,0}; ::setsockopt(good.fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    sockaddr_storage origin{}; socklen_t origin_len=sizeof(origin); std::array<std::uint8_t,64> bytes{};
    if (::recvfrom(good.fd,bytes.data(),bytes.size(),0,reinterpret_cast<sockaddr*>(&origin),&origin_len)!=2) return false;
    packet.port=bad_peer.port; fail_send=true;
    auto failed=direct.send(packet,bad_peer,data);
    if (failed || fail_send || failed.error()!=u::DirectError{std::make_error_code(std::errc::resource_unavailable_try_again)}) return false;
    if (::sendto(bad.fd,"x",1,0,reinterpret_cast<sockaddr*>(&origin),origin_len)!=1 ||
        ::sendto(good.fd,"ok",2,0,reinterpret_cast<sockaddr*>(&origin),origin_len)!=2) return false;
    bool saw_drop=false; std::optional<u::DirectReply> reply;
    for (int i=0;i<200 && !reply;++i) {
        bool dropped=false; auto result=direct.poll(bytes,&dropped); if (!result) return false;
        saw_drop|=dropped; reply=*result;
        if (!reply) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!saw_drop || !reply || reply->source!=good_peer || reply->size!=2 || bytes[0]!='o' || bytes[1]!='k') return false;
    direct.close();
    return direct.send(packet,bad_peer,data).error()==u::DirectError{s::Status::association_closed} &&
           direct.poll(bytes).error()==u::DirectError{s::Status::association_closed};
}
int main() { return run(AF_INET) && run(AF_INET6) ? 0 : 1; }
