#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
import std;
import nexus.rules;
import nexus.dns.message;
import nexus.dns.cache;
import nexus.shadowsocks.udp_dispatch;
import nexus.shadowsocks.udp_packet;
#include "../src/shadowsocks/corosio_udp_resolve_owner.hpp"
namespace s=nexus::shadowsocks;
namespace io=boost::corosio;
using namespace std::chrono_literals;
int main(int argc,char** argv) {
    if (argc!=3) return 1;
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    nexus::dns::AddressCache cache{8}; auto policy=nexus::rules::Matcher::compile({}); if (!policy) return 2;
    s::UdpDispatcher dispatcher(std::move(*policy),4,4,4,1024);
    s::detail::UdpResolveOwner owner(dispatcher,context,cache,2);
    auto now=std::chrono::steady_clock::now();
    auto wall=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    std::array<std::uint8_t,16> key{};
    s::UdpPacket packet{{1},0,wall,{}, {3,6,'a','.','t','e','s','t',0,80},{1}};
    auto begin=[&] { auto wire=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{}); ++packet.packet_id;
        return dispatcher.begin(key,wire,{4,{127,0,0,1},1234},now,wall,now+2s); };
    auto upstream=io::endpoint(io::ipv4_address::loopback(),static_cast<std::uint16_t>(std::stoi(argv[1])));
    for (int i=0;i<2;++i) {
        auto pending=begin(); if (!pending) return 3;
        auto duplicate=*pending;
        if (!owner.start(std::move(*pending),upstream,1,now,now+2s,nexus::dns::detail::AddressStrategy::ipv4_only)) return 3;
        if (owner.start(std::move(duplicate),upstream,1,now,now+2s).error()!=s::detail::UdpResolveStartError::duplicate || dispatcher.pending()!=static_cast<std::size_t>(i+1)) return 8;
    }
    auto third=begin(); if (!third || owner.start(std::move(*third),upstream,1,now,now+2s).error()!=s::detail::UdpResolveStartError::full || dispatcher.pending()!=2) return 4;
    context.restart(); (void)context.run_for(100ms);
    if (std::string_view(argv[2])=="expired") owner.cancel_expired(now+2s); else owner.stop();
    if (dispatcher.pending()!=0) return 5;
    context.restart(); (void)context.run_for(1s);
    if (!owner.drained() || owner.active()!=0 || owner.succeeded()!=0 || owner.failed()!=2 || dispatcher.sockets()!=0) return 6;
    owner.stop();
    auto late=begin(); if (!late || owner.start(std::move(*late),upstream,1,now,now+2s).error()!=s::detail::UdpResolveStartError::stopped || dispatcher.pending()!=0) return 7;
    std::println("SS-2022 UDP concurrent DNS owner cancellation drained");
}
