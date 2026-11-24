#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
import std;
import dns.corosio_local;
import rules;
import dns.message;
import dns.corosio_query;
import dns.cache;
import dns.local_config;
import shadowsocks.udp_dispatch;
import shadowsocks.udp_packet;
import ss_udp.inbounds;
namespace s=shadowsocks;
namespace io = ::corosio;
using namespace std::chrono_literals;
struct Fixture {
    io::io_context context{io::make_io_context(io::has_uring)};
    dns::AddressCache cache{8};
    std::optional<std::expected<void,s::detail::UdpResolveError>> result;
};
auto run(Fixture& f,s::detail::UdpResolveOperation& operation,std::uint16_t port,std::chrono::milliseconds timeout) -> capy::task<> {
    f.result=co_await operation.run(io::endpoint(io::ipv4_address::loopback(),port),1,std::chrono::steady_clock::now()+timeout);
}
int main(int argc,char** argv) {
    if (argc!=3) return 1;
    int target=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); sockaddr_in addr{};
    addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if (target<0 || bind(target,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))) return 2;
    socklen_t len=sizeof(addr); getsockname(target,reinterpret_cast<sockaddr*>(&addr),&len); auto port=ntohs(addr.sin_port);
    std::string_view mode=argv[2];
    auto policy=mode=="blocked" ? ::rules::Matcher::compile({{{"ip-cidr","127.0.0.0/8"}}}) : ::rules::Matcher::compile({});
    if (!policy) return 3;
    s::UdpDispatcher dispatcher(std::move(*policy),4,4,4,1024); Fixture f;
    std::array<std::uint8_t,16> key{}; auto now=std::chrono::steady_clock::now();
    auto wall=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    s::UdpPacket packet{{1},0,wall,{}, {3,6,'a','.','t','e','s','t',static_cast<std::uint8_t>(port>>8),static_cast<std::uint8_t>(port)}, {1,2,3}};
    auto wire=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{});
    auto pending=dispatcher.begin(key,wire,{4,{127,0,0,1},1234},now,wall,now+2s); if (!pending) return 4;
    auto token=pending->token;
    std::vector<s::detail::UdpResolveHop> hops;
    if (mode=="chain-cancel") hops.push_back({"dns.test",53,2,false});
    s::detail::UdpResolveOperation operation(dispatcher,f.context,f.cache,std::move(*pending),false,
        dns::detail::AddressStrategy::ipv4_only,false,false,std::move(hops));
    capy::run_async(f.context.get_executor())(run(f,operation,static_cast<std::uint16_t>(std::stoi(argv[1])),mode=="timeout" ? 100ms : 2s));
    f.context.restart(); (void)f.context.run_for(mode=="cancel" || mode=="chain-cancel" || mode=="stale" ? 100ms : 3s);
    if (mode=="cancel" || mode=="chain-cancel" || mode=="stale") {
        if (mode=="cancel" || mode=="chain-cancel") operation.cancel(); else if (!dispatcher.cancel(token)) return 9;
        f.context.restart(); (void)f.context.run_for(1s);
    }
    if (!f.result || dispatcher.pending()!=0) return 5;
    std::array<std::uint8_t,16> buf{}; auto n=recv(target,buf.data(),buf.size(),0); ::close(target);
    if (mode=="success") return *f.result && n==3 && buf[0]==1 ? 0 : 6;
    if (*f.result || n>=0 || dispatcher.sockets()!=0) return 7;
    auto expected=(mode=="cancel" || mode=="chain-cancel") ? s::detail::UdpResolveError::canceled :
        mode=="stale" || mode=="blocked" ? s::detail::UdpResolveError::dispatch : s::detail::UdpResolveError::dns;
    return f.result->error()==expected ? 0 : 8;
}
