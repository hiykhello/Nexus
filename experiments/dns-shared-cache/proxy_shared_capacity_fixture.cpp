// One or two real SOCKS inbounds. The experimental variant owns a single
// shared-capacity snapshot; the baseline retains each Server's normal cache.
import std;
import dns.message;
import proxy.dns_backend;
import proxy;

auto main(int argc,char** argv) -> int {
    if (argc!=5) return 2;
    auto parse=[](char const* text) -> std::optional<unsigned> {
        std::string_view input(text); unsigned value=0;
        auto [end,error]=std::from_chars(input.data(),input.data()+input.size(),value);
        if (error!=std::errc{} || end!=input.data()+input.size()) return {};
        return value;
    };
    auto dns_port=parse(argv[1]),group_count=parse(argv[2]),capacity=parse(argv[3]),workers=parse(argv[4]);
    if (!dns_port || !group_count || !capacity || !workers || !*dns_port || *dns_port>65535 ||
        !*group_count || *group_count>2 || *capacity<*group_count || *capacity>8192 || !*workers || *workers>8) return 2;
    namespace p=proxy;
#ifdef NEXUS_TEST_DNS_GROUP
    using Cache=dns_hp_experiment::GroupSnapshot;
    std::vector<std::size_t> groups(*group_count,1);
    Cache cache(groups,Cache::SharedCapacity{*capacity},*group_count * *workers,0,8*1024*1024);
#endif
    p::DnsServer upstream; upstream.address[0]=127; upstream.address[3]=1; upstream.port=static_cast<std::uint16_t>(*dns_port);
    p::DnsRouting routing{{upstream},{},0};
    std::vector<std::unique_ptr<p::Server>> servers;
    std::vector<std::uint16_t> ports;
    for (unsigned group=0;group<*group_count;++group) {
        auto server=p::Server::create(); if (!server || !(*server)->set_dns_routing(routing)) return 3;
#ifdef NEXUS_TEST_DNS_GROUP
        if (!(*server)->set_dns_group_for_test(cache,group,group * *workers)) return 4;
#endif
        auto port=(*server)->start(0,p::Inbound::socks5,*workers); if (!port) return 5;
        ports.push_back(*port); servers.push_back(std::move(*server));
    }
#ifdef NEXUS_TEST_DNS_GROUP
    constexpr std::string_view mode="group";
#else
    constexpr std::string_view mode="baseline";
#endif
    std::cout<<"ready "<<*group_count;
    for (auto port:ports) std::cout<<' '<<port;
    std::cout<<' '<<mode<<std::endl;
    std::string command;
    for (;;) {
        if (!std::getline(std::cin,command)) return 6;
        if (command=="stop") break;
        if (command!="stats") return 6;
#ifdef NEXUS_TEST_DNS_GROUP
        std::cout<<"stats";
        for (unsigned group=0;group<*group_count;++group) std::cout<<' '<<cache.size(group);
        std::cout<<' '<<cache.charged_bytes()<<std::endl;
#else
        std::cout<<"stats unavailable"<<std::endl;
#endif
    }
    bool healthy=true;
    for (auto& server:servers) { healthy&=server->healthy(); server->stop(); }
    std::cout<<"stopped"<<std::endl;
    return healthy ? 0 : 7;
}
