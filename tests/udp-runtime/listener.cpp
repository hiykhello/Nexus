import std;
import dns.corosio_local;
import crypto;
import rules;
import dns.message;
import dns.corosio_query;
import dns.cache;
import dns.local_config;
import shadowsocks.udp_dispatch;
import relay;
import ss_udp.inbounds;
namespace io = ::corosio;
using namespace std::chrono_literals;
#ifdef NEXUS_TEST_UDP_SEND_DELAY
auto configure_udp_send_faults(std::string_view mode) noexcept -> void;
auto udp_send_queue_observed() noexcept -> bool;
auto check_udp_send_results(std::string_view mode,int result) noexcept -> int;
#endif
int main(int argc,char** argv) {
    if (argc!=4) return 1;
    auto backend=std::getenv("NEXUS_TEST_UDP_BACKEND");
    auto context=io::make_io_context(io::has_uring && !(backend && std::string_view(backend)=="epoll"));
    auto policy=std::string_view(argv[3])=="block" ?
        ::rules::Matcher::compile({{{"ip-cidr","127.0.0.2/32"},{"domain-suffix","blocked.test"}}}) :
        ::rules::Matcher::compile({});
    if (!policy) return 2;
    std::array<std::uint8_t,32> key{}; std::iota(key.begin(),key.end(),0);
    namespace detail=shadowsocks::detail;
    detail::UdpListenerRegistry registry(2);
    auto psk=std::span{key}.first(std::stoi(argv[1]));
    auto mode=std::string_view(argv[3]);
#ifdef NEXUS_TEST_UDP_SEND_DELAY
    configure_udp_send_faults(mode);
#endif
    auto limit=mode=="capacity" ? 2 : mode=="expiry" ? 1 : 64;
    std::array ordered_rules{::rules::ProgramRule{{{{"ip-cidr","127.0.0.2/32"},{"domain-suffix","blocked.test"}}},{::rules::ProgramActionKind::route,1}}};
    auto ordered=::rules::RouteProgram::compile_policy(ordered_rules,0,2);
    if (!ordered) return 17;
    auto state=(mode=="ordered" || mode=="tcp-dns") ? registry.add(psk,std::move(*ordered),limit) : registry.add(psk,std::move(*policy),limit);
    if (!state) return 10;
    if (std::string_view(argv[3])=="restart") {
        auto empty=[] { return *::rules::Matcher::compile({}); };
        auto duplicate=registry.add(psk,empty());
        auto invalid=registry.add(std::span{key}.first(15),empty());
        auto other_key=key; other_key[0]^=0xff;
        auto other=registry.add(std::span{other_key}.first(psk.size()),empty());
        other_key[1]^=0xff;
        auto full=registry.add(std::span{other_key}.first(psk.size()),empty());
        if (duplicate || duplicate.error()!=detail::UdpRegistryError::duplicate_key ||
            invalid || invalid.error()!=detail::UdpRegistryError::invalid_key || !other ||
            full || full.error()!=detail::UdpRegistryError::full) return 11;
    }
    auto upstream=io::endpoint(io::ipv4_address::loopback(),static_cast<std::uint16_t>(std::stoi(argv[2])));
    auto slow_timer=std::string_view(argv[3])=="timer-stop";
    detail::UdpResolveOptions dns_options;
    std::optional<detail::UdpDnsRouting> dns_routing;
    if (mode=="dns-routes" || mode=="dns-chain" || mode=="dns-chain-system") {
        auto second=std::getenv("NEXUS_TEST_DNS_PORT");
        if (!second) return 18;
        dns_routing=detail::UdpDnsRouting{{{upstream,false},
            {io::endpoint(io::ipv4_address::loopback(),static_cast<std::uint16_t>(std::stoi(second))),false}},
            {{"A.TEST",true,1}},0};
        if (mode=="dns-chain" || mode=="dns-chain-system") {
            if (mode=="dns-chain-system") dns_routing->servers[0].endpoint=io::endpoint(io::ipv4_address::loopback(),0);
            dns_routing->servers[1].host=mode=="dns-chain-system" ? "localhost" : "dns.test";
            dns_routing->servers[1].resolver=0;
            dns_routing->rules.clear(); dns_routing->fallback=1;
            auto cycle=*dns_routing; cycle.servers[0].host="dns.test"; cycle.servers[0].resolver=1;
            detail::UdpListener cyclic(context,**state,upstream,64,5ms,{},cycle);
            if (cyclic.start(io::endpoint(io::ipv4_address::loopback(),0))!=std::make_error_code(std::errc::invalid_argument)) return 20;
        }
        auto invalid=*dns_routing; invalid.fallback=2;
        detail::UdpListener probe(context,**state,upstream,64,5ms,{},invalid);
        if (probe.start(io::endpoint(io::ipv4_address::loopback(),0))!=std::make_error_code(std::errc::invalid_argument)) return 19;
    }
    if (mode=="system-dns" || mode=="system-stall") dns_routing=detail::UdpDnsRouting{{{io::endpoint(io::ipv4_address::loopback(),0),false}}, {},0};
    if (mode=="tcp-dns") {
        dns_routing=detail::UdpDnsRouting{{{upstream,true}}, {},0};
        dns_options.edns=true; dns_options.disable_cache=true;
    }
    if (dns_routing) {
        relay::DnsRouting config;
        config.final=dns_routing->fallback;
        config.disable_cache=dns_options.disable_cache; config.edns=dns_options.edns;
        for (auto const& server:dns_routing->servers) {
            relay::DnsServer entry;
            entry.ipv6=server.endpoint.address().is_v6(); entry.port=server.endpoint.port(); entry.tcp=server.tcp_only;
            if (entry.ipv6) entry.address=server.endpoint.address().to_v6().to_bytes();
            else { auto bytes=server.endpoint.address().to_v4().to_bytes(); std::copy(bytes.begin(),bytes.end(),entry.address.begin()); }
            entry.host=server.host; entry.resolver=server.resolver; config.servers.push_back(std::move(entry));
        }
        for (auto const& rule:dns_routing->rules) config.rules.push_back({rule.domain,rule.suffix,rule.server});
        auto adapted=relay::detail::udp_dns_config(config);
        if (!adapted) return 21;
        dns_options=adapted->options; dns_routing=std::move(adapted->routing);
        using relay::DnsStrategy;
        using dns::detail::AddressStrategy;
        std::array strategies{std::pair{DnsStrategy::automatic,AddressStrategy::prefer_ipv4},
            std::pair{DnsStrategy::prefer_ipv4,AddressStrategy::prefer_ipv4},
            std::pair{DnsStrategy::prefer_ipv6,AddressStrategy::prefer_ipv6},
            std::pair{DnsStrategy::ipv4_only,AddressStrategy::ipv4_only},
            std::pair{DnsStrategy::ipv6_only,AddressStrategy::ipv6_only}};
        for (auto [input,expected]:strategies) {
            config.strategy=input; auto mapped=relay::detail::udp_dns_config(config);
            if (!mapped || mapped->options.strategy!=expected) return 23;
        }
        config.strategy=static_cast<DnsStrategy>(255);
        if (relay::detail::udp_dns_config(config)) return 22;
    }
    auto listener=std::make_unique<shadowsocks::detail::UdpListener>(context,**state,upstream,64,slow_timer ? 10s : 5ms,dns_options,std::move(dns_routing));
    auto listen=std::string_view(argv[3])=="ipv6" ? io::endpoint(io::ipv6_address::loopback(),0) :
        io::endpoint(io::ipv4_address::loopback(),0);
    std::array listens{listen,listen};
    if (mode=="multi6") listens[1]=io::endpoint(io::ipv6_address::loopback(),0);
    if (mode=="multi") {
        io::udp_socket reserve(context);
        if (reserve.open(listen.address().family()) || reserve.bind(listen)) return 14;
        auto occupied=reserve.local_endpoint(); reserve.close();
        std::array duplicates{occupied,occupied};
        if (!listener->start(duplicates)) return 15;
        // The first bind must have been rolled back, including its port.
        io::udp_socket probe(context);
        if (probe.open(listen.address().family()) || probe.bind(occupied)) return 16;
        probe.close();
    }
    if ((mode=="multi" || mode=="multi6") ? listener->start(listens) : listener->start(listen)) return 3;
    std::println("{}",listener->local_endpoint().port());
    if (mode=="multi" || mode=="multi6") std::println("{}",listener->local_endpoint(1).port());
    std::fflush(nullptr);
    if (slow_timer) {
        context.restart(); (void)context.run_for(20ms);
        if (!listener->running() || !listener->timer_waiting()) return 12;
        listener->stop();
        context.restart(); (void)context.run_for(200ms);
        return listener->drained() ? 0 : 13;
    }
    auto restart=mode=="restart" || mode=="reconfigure";
    if (mode=="reconfigure") {
        auto policy=::rules::Matcher::compile({{{"ip-cidr","127.0.0.2/32"}}});
        if (!policy || registry.find(psk)!=*state || registry.reconfigure(**state,std::move(*policy))) return 24;
    }
    if (restart) {
        shadowsocks::detail::UdpListener duplicate(context,**state,upstream);
        if (duplicate.start(listen)!=std::make_error_code(std::errc::operation_not_permitted)) return 7;
    }
    auto until=std::chrono::steady_clock::now()+(mode=="expiry" ? 67s : 3s);
    auto replace_at=std::chrono::steady_clock::now()+1s;
    int result=0;
    while (std::chrono::steady_clock::now()<until) {
        context.restart(); (void)context.run_for(5ms);
        if (!listener->running()) { result=4; break; }
#ifdef NEXUS_TEST_UDP_SEND_DELAY
        if (mode=="send-stop" && udp_send_queue_observed()) break;
#endif
        if (restart && std::chrono::steady_clock::now()>=replace_at) {
            listener->stop();
            context.restart(); (void)context.run_for(1s);
            if (!listener->drained() || listener->relay_sockets()!=0) return 8;
            listener.reset();
            if (mode=="reconfigure") {
                auto policy=::rules::Matcher::compile({{{"ip-cidr","127.0.0.2/32"}}});
                if (!policy || !registry.reconfigure(**state,std::move(*policy))) return 25;
            }
            listener=std::make_unique<shadowsocks::detail::UdpListener>(context,**state,upstream);
            if (listener->start(listen)) return 9;
            std::println("{}",listener->local_endpoint().port()); std::fflush(nullptr);
            restart=false;
        }
    }
    listener->stop();
    if (listener->relay_sockets()!=0 && result==0) result=6;
    auto deadline=std::chrono::steady_clock::now()+(mode=="system-stall" ? 10s : 1s);
    while (!listener->drained() && std::chrono::steady_clock::now()<deadline) {
        context.restart(); (void)context.run_for(100ms);
    }
    if (!listener->drained()) {
        std::cerr << "UDP listener did not drain before the deadline\n";
        // The listener contract forbids destruction with in-flight operations.
        std::_Exit(5);
    }
#ifdef NEXUS_TEST_UDP_SEND_DELAY
    return check_udp_send_results(mode,result);
#else
    return result;
#endif
}
