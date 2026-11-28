#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import xudp;
import xudp.server_sessions;
import xudp.server_direct;
import rules;
import net.udp_route;
namespace x=xudp; namespace n=net; namespace r = ::rules;
struct Socket { int fd; ~Socket() { if(fd>=0) ::close(fd); } };
auto run(int family) -> bool {
    Socket origin{::socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0)}, attacker{::socket(family,SOCK_DGRAM|SOCK_CLOEXEC,0)};
    if (origin.fd<0 || attacker.fd<0) return false;
    sockaddr_storage addr{}; socklen_t length;
    if (family==AF_INET) { auto& a=*reinterpret_cast<sockaddr_in*>(&addr); a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); length=sizeof(a); }
    else { auto& a=*reinterpret_cast<sockaddr_in6*>(&addr); a.sin6_family=AF_INET6; a.sin6_addr=in6addr_loopback; length=sizeof(a); }
    if (::bind(origin.fd,reinterpret_cast<sockaddr*>(&addr),length) || ::bind(attacker.fd,reinterpret_cast<sockaddr*>(&addr),length)) return false;
    sockaddr_storage bound{}; socklen_t bound_len=sizeof(bound); if (::getsockname(origin.fd,reinterpret_cast<sockaddr*>(&bound),&bound_len)) return false;
    n::UdpEndpoint peer{}; peer.family=family==AF_INET ? 4 : 6;
    if (family==AF_INET) { peer.address[0]=127; peer.address[3]=1; peer.port=ntohs(reinterpret_cast<sockaddr_in*>(&bound)->sin_port); }
    else { peer.address[15]=1; peer.port=ntohs(reinterpret_cast<sockaddr_in6*>(&bound)->sin6_port); }
    x::Address target; target.family=family==AF_INET ? x::Family::ipv4 : x::Family::ipv6; target.length=family==AF_INET ? 4 : 16; target.port=peer.port;
    std::copy_n(peer.address.begin(),target.length,target.bytes.begin());
    auto policy=r::RouteProgram::compile_policy(std::span<r::ProgramRule const>{},0,3);
    auto block=r::RouteProgram::compile_policy(std::span<r::ProgramRule const>{},1,3);
    if (!policy || !block) return false;
    x::ServerDirect direct(*policy,2),denied(*block,1);
    r::RuleSet source_rule{{{"source-port","1234",{}}},2};
    auto source_policy=r::RouteProgram::compile_policy(std::array{r::ProgramRule{source_rule,{r::ProgramActionKind::route,1}}},0,2,r::SourceMetadata::provided);
    if (!source_policy) return false;
    n::UdpEndpoint source{4,{127,0,0,1},1234};
    x::ServerDirect source_denied(*source_policy,1,&source);
    source.port=4321; // The owner retains its own connection snapshot.
    x::Address domain; domain.family=x::Family::domain; domain.length=7; domain.port=peer.port;
    std::ranges::copy(std::string_view("ok.test"),domain.bytes.begin());
    auto preflight=source_denied.preflight(domain);
    auto source_open=source_denied.receive({3,x::Kind::open,true,false,target});
    std::array<std::uint8_t,1> source_data{1};
    auto source_send=source_denied.send(source_open.token,target,peer,source_data);
    if (preflight || preflight.error()!=x::ServerDirectFailure{n::UdpRouteError::blocked} ||
        source_send || source_send.error()!=x::ServerDirectFailure{n::UdpRouteError::blocked}) return false;
    auto a=direct.receive({1,x::Kind::open,true,false,target}); auto b=direct.receive({2,x::Kind::open,true,false,target});
    auto rejected=denied.receive({1,x::Kind::open,true,false,target}); std::array<std::uint8_t,2> data{'o','k'};
    auto no=denied.send(rejected.token,target,peer,data);
    if (a.action!=x::ServerAction::opened || b.action!=x::ServerAction::opened || no || no.error()!=x::ServerDirectFailure{n::UdpRouteError::blocked}) return false;
    if (!direct.send(a.token,target,peer,data) || !direct.send(b.token,target,peer,data)) return false;
    timeval timeout{2,0}; ::setsockopt(origin.fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    std::array<sockaddr_storage,2> src{}; std::array<socklen_t,2> sizes{sizeof(sockaddr_storage),sizeof(sockaddr_storage)}; std::array<std::uint8_t,64> buffer{};
    for (int i=0;i<2;++i) if (::recvfrom(origin.fd,buffer.data(),buffer.size(),0,reinterpret_cast<sockaddr*>(&src[i]),&sizes[i])!=2) return false;
    // A distinct source is not authorized, even when it knows the socket address.
    if (::sendto(attacker.fd,"x",1,0,reinterpret_cast<sockaddr*>(&src[0]),sizes[0])!=1) return false;
    if (::sendto(origin.fd,"a",1,0,reinterpret_cast<sockaddr*>(&src[0]),sizes[0])!=1 || ::sendto(origin.fd,"b",1,0,reinterpret_cast<sockaddr*>(&src[1]),sizes[1])!=1) return false;
    bool dropped=false, got_a=false,got_b=false;
    for (int i=0;i<400 && !(dropped && got_a && got_b);++i) {
        bool one=false; auto result=direct.poll(buffer,&one); if (!result) return false; dropped|=one;
        if (*result) { if ((**result).source!=target || (**result).size!=1) return false;
            if ((**result).token==a.token && buffer[0]=='a') got_a=true;
            else if ((**result).token==b.token && buffer[0]=='b') got_b=true;
            else return false;
        } else std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (!dropped || !got_a || !got_b) return false;
    if (direct.receive({1,x::Kind::end}).action!=x::ServerAction::ended) return false;
    auto renewed=direct.receive({1,x::Kind::open,true,false,target});
    if (renewed.action!=x::ServerAction::opened || renewed.token==a.token || direct.send(a.token,target,peer,data)) return false;
    // Send queued to the old socket after close must not appear on the new one.
    (void)::sendto(origin.fd,"z",1,0,reinterpret_cast<sockaddr*>(&src[0]),sizes[0]);
    if (!direct.send(renewed.token,target,peer,{})) return false;
    sockaddr_storage third{}; socklen_t third_len=sizeof(third);
    if (::recvfrom(origin.fd,buffer.data(),buffer.size(),0,reinterpret_cast<sockaddr*>(&third),&third_len)!=0) return false;
    if (::sendto(origin.fd,"",0,0,reinterpret_cast<sockaddr*>(&third),third_len)!=0) return false;
    bool got_empty=false;
    for (int i=0;i<200 && !got_empty;++i) {
        auto result=direct.poll(buffer); if (!result) return false;
        if (*result) { if ((**result).token!=renewed.token || (**result).size) return false; got_empty=true; }
        else std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    direct.close(); return got_empty && !direct.send(renewed.token,target,peer,data);
}
auto idle_expiration() -> bool {
    using namespace std::chrono_literals; using Clock=std::chrono::steady_clock;
    auto policy=r::RouteProgram::compile_policy(std::span<r::ProgramRule const>{},0,3); if (!policy) return false;
    x::ServerDirect direct(*policy,2); x::Address target; target.length=4; target.bytes[0]=127; target.bytes[3]=1; target.port=53;
    auto now=Clock::time_point{}+100s;
    auto first=direct.receive({1,x::Kind::open,false,false,target},now);
    auto second=direct.receive({2,x::Kind::open,false,false,target},now+1s);
    if (direct.expire_one(now-1s,10s) || direct.expire_one(now+9s,10s)) return false;
    std::array<std::uint8_t,1> data{1};
    if (direct.receive({1,x::Kind::data,true,false,{}, {},data},now+9s).action!=x::ServerAction::datagram) return false;
    auto expired=direct.expire_one(now+11s,10s);
    if (!expired || *expired!=second.token || direct.contains(second.token) || !direct.contains(first.token)) return false;
    auto replacement=direct.receive({2,x::Kind::open,false,false,target},now+11s);
    if (replacement.action!=x::ServerAction::opened || replacement.token==second.token) return false;
    expired=direct.expire_one(now+19s,10s);
    return expired && *expired==first.token && direct.contains(replacement.token) && !direct.contains(first.token);
}
int main() {
    if (!idle_expiration()) return 2;
    if (!run(AF_INET) || !run(AF_INET6)) return 1;
    std::cout << "XUDP server direct UDP session isolation and routing passed\n";
}
