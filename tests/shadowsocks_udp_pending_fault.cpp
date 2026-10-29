#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/resolver.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/udp_socket.hpp>
import std;
import nexus.crypto;
import nexus.rules;
import nexus.dns.message;
import nexus.dns.cache;
import nexus.shadowsocks.udp_dispatch;
import nexus.shadowsocks.udp_packet;
#include "../src/shadowsocks/corosio_udp_listener.hpp"
namespace s=nexus::shadowsocks;
namespace io=boost::corosio;
using namespace std::chrono_literals;
bool injected=false;
extern "C" void nexus_test_udp_pending() { injected=true; throw std::bad_alloc(); }
int main(int argc,char** argv) {
    if (argc!=2) return 1;
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context=std::string_view(argv[1])=="uring" ? io::io_context(io::uring) : io::io_context(io::epoll);
#else
    io::io_context context(io::epoll);
#endif
    auto policy=nexus::rules::Matcher::compile({}); if (!policy) return 2;
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
        if (!injected || listener.running() || !listener.drained() || listener.pending_for_test()!=0) return 8;
    }
    {
        s::detail::UdpListener replacement(context,**state,upstream);
        if (replacement.start(io::endpoint(io::ipv4_address::loopback(),0))) return 9;
        replacement.stop(); context.restart(); (void)context.run_for(1s);
        if (!replacement.drained() || replacement.pending_for_test()!=0) return 10;
    }
    std::println("UDP pending request released after listener exception and replacement");
}
