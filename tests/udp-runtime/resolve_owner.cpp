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
namespace io=nex::corosio;
using namespace std::chrono_literals;
bool inject_dns_failure=false;
extern "C" void nexus_test_dns_received() {
    if (std::exchange(inject_dns_failure,false)) throw std::runtime_error("injected DNS receive failure");
}
int main(int argc,char** argv) {
    if (argc!=3 && argc!=4) return 1;
    auto context=io::make_io_context(io::has_uring && !(argc==4 && std::string_view(argv[3])=="epoll"));
    dns::AddressCache cache{8}; auto policy=::rules::Matcher::compile({}); if (!policy) return 2;
    s::UdpDispatcher dispatcher(std::move(*policy),4,4,4,1024);
    s::detail::UdpResolveOwner owner(dispatcher,context,cache,2);
    auto now=std::chrono::steady_clock::now();
    auto wall=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    std::array<std::uint8_t,16> key{};
    s::UdpPacket packet{{1},0,wall,{}, {3,6,'a','.','t','e','s','t',0,80},{1}};
    auto begin=[&] { auto wire=*s::encode_udp_packet(key,s::UdpDirection::client,packet,{}); ++packet.packet_id;
        return dispatcher.begin(key,wire,{4,{127,0,0,1},1234},now,wall,now+2s); };
    auto upstream=io::endpoint(io::ipv4_address::loopback(),static_cast<std::uint16_t>(std::stoi(argv[1])));
    bool exception=std::string_view(argv[2])=="exception";
    inject_dns_failure=exception;
    for (int i=0;i<2;++i) {
        auto pending=begin(); if (!pending) return 3;
        auto duplicate=*pending;
        if (!owner.start(std::move(*pending),upstream,1,now,now+2s,dns::detail::AddressStrategy::ipv4_only)) return 3;
        if (owner.start(std::move(duplicate),upstream,1,now,now+2s).error()!=s::detail::UdpResolveStartError::duplicate || dispatcher.pending()!=static_cast<std::size_t>(i+1)) return 8;
    }
    auto third=begin(); if (!third || owner.start(std::move(*third),upstream,1,now,now+2s).error()!=s::detail::UdpResolveStartError::full || dispatcher.pending()!=2) return 4;
    context.restart(); (void)context.run_for(100ms);
    auto free_cache_slots=[&] {
        std::vector<dns::CacheToken> tokens;
        while (auto token=cache.begin_query({1,"probe.test",1})) tokens.push_back(*token);
        auto count=tokens.size();
        for (auto token:tokens) if (!cache.cancel_query(token)) std::terminate();
        return count;
    };
    if (exception) {
        for (int i=0;i<20 && owner.failed()==0;++i) { context.restart(); (void)context.run_for(50ms); }
        if (inject_dns_failure || owner.failed()!=1 || owner.active()!=1 || dispatcher.pending()!=1 || free_cache_slots()!=4095) return 9;
    }
    if (std::string_view(argv[2])=="expired") owner.cancel_expired(now+2s); else owner.stop();
    if (dispatcher.pending()!=0) return 5;
    context.restart(); (void)context.run_for(1s);
    if (!owner.drained() || owner.active()!=0 || owner.succeeded()!=0 || owner.failed()!=2 || dispatcher.sockets()!=0 || free_cache_slots()!=4096) return 6;
    owner.stop();
    auto late=begin(); if (!late || owner.start(std::move(*late),upstream,1,now,now+2s).error()!=s::detail::UdpResolveStartError::stopped || dispatcher.pending()!=0) return 7;
    std::println("SS-2022 UDP concurrent DNS owner cancellation drained");
}
