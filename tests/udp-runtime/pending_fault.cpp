#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
import std;
import dns.corosio_local;
import crypto;
import rules;
import dns.message;
import dns.corosio_query;
import dns.cache;
import dns.local_config;
import shadowsocks.udp_dispatch;
import shadowsocks.udp_packet;
import ss_udp.listener;
namespace s=shadowsocks;
namespace io=nex::corosio;
using namespace std::chrono_literals;
auto enable_udp_pending_fault() noexcept -> void;
auto udp_pending_fault_injected() noexcept -> bool;
int main(int argc,char** argv) {
    if (argc!=2) return 1;
    enable_udp_pending_fault();
    auto context=io::make_io_context(io::has_uring && std::string_view(argv[1])=="uring");
    auto policy=::rules::Matcher::compile({}); if (!policy) return 2;
    std::array<std::uint8_t,16> key{};
    s::detail::UdpListenerRegistry registry(1);
    auto state=registry.add(key,std::move(*policy),4,4,1); if (!state) return 3;
    auto upstream=io::endpoint(io::ipv4_address::loopback(),53);
    {
        s::detail::UdpListener listener(context,**state,upstream);
        if (listener.start(io::endpoint(io::ipv4_address::loopback(),0))) return 4;
        auto wall=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
        s::UdpPacket packet{{1},0,wall,{}, {3,6,'a','.','t','e','s','t',0,80},{1}};
        auto wire=s::encode_udp_packet(key,s::UdpDirection::client,packet,{}); if (!wire) return 5;
        auto fd=::socket(AF_INET,SOCK_DGRAM,0); if (fd<0) return 6;
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK); address.sin_port=htons(listener.local_endpoint().port());
        auto sent=::sendto(fd,wire->data(),wire->size(),0,reinterpret_cast<sockaddr*>(&address),sizeof(address));
        ::close(fd); if (sent!=static_cast<ssize_t>(wire->size())) return 7;
        context.restart(); (void)context.run_for(1s);
        if (!udp_pending_fault_injected() || listener.running() || !listener.drained() || listener.pending_for_test()!=0) return 8;
    }
    {
        s::detail::UdpListener replacement(context,**state,upstream);
        if (replacement.start(io::endpoint(io::ipv4_address::loopback(),0))) return 9;
        replacement.stop(); context.restart(); (void)context.run_for(1s);
        if (!replacement.drained() || replacement.pending_for_test()!=0) return 10;
    }
    std::println("UDP pending request released after listener exception and replacement");
}
