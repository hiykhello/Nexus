// Real FakeIP sessions use the same group coordinator and drain on stop.
import std;
import dns.message;
import dns.fakeip_shared;
import dns.shared_cache;
import dns.shared_coordinator;
import proxy;

extern "C" void nexus_test_dns_shared_access(void const*) noexcept {}

auto main(int argc,char** argv) -> int {
    using namespace std::chrono_literals;
    namespace d=dns;
    namespace p=proxy;
    namespace hp=dns_hp_experiment;
    if (argc!=2) return 2;
    auto upstream=std::strtoul(argv[1],nullptr,10);
    if (!upstream || upstream>65535) return 2;
    constexpr std::uint32_t base=0xc6120000;
    auto fakeip=std::make_shared<d::FakeIpShared>(1);
    if (!fakeip->add(base,base+3,base+1,base+2,30s,0s) || !fakeip->seal()) return 3;
    auto seed=[&](std::uint16_t id,std::string name) -> std::optional<d::Address> {
        d::Question question{std::move(name),1};
        auto query=d::make_query(id,question); if (!query) return {};
        auto response=fakeip->respond(base,*query,7); if (!response) return {};
        auto answer=d::parse_addresses((*response)->wire(),id,question);
        if (!answer || answer->addresses.size()!=1 || answer->addresses[0].size!=4 || !(*response)->finish(true)) return {};
        return answer->addresses[0];
    };
    auto shared=seed(1,"shared.example.test"),pending=seed(2,"pending.example.test");
    if (!shared || !pending) return 4;
    std::array<std::size_t,1> groups{1};
    hp::GroupSnapshot cache(groups,hp::GroupSnapshot::SharedCapacity{64},2,0,1024*1024);
    hp::Coordinator coordinator(8,32);
    hp::ViewRegistry views(8,65536,32);
    p::Server server;
    p::DnsServer dns; dns.address[0]=127; dns.address[3]=1; dns.port=static_cast<std::uint16_t>(upstream);
    p::DnsRouting routing; routing.servers.push_back(dns); routing.strategy=p::DnsStrategy::ipv4_only;
    if (!server.set_fakeip(fakeip,7) || !server.set_dns_routing(std::move(routing)) ||
        !server.set_dns_group_for_test(cache,0,0) || !server.set_dns_coordinator_for_test(coordinator,views)) return 5;
    views.seal();
    auto port=server.start(0,p::Inbound::socks5,2); if (!port) return 6;
    auto print_address=[](d::Address const& address) {
        for (std::size_t i=0;i<4;++i) {
            if (i) std::cout << '.';
            std::cout << static_cast<unsigned>(address.bytes[i]);
        }
    };
    std::cout << *port << ' '; print_address(*shared); std::cout << ' '; print_address(*pending); std::cout << std::endl;
    std::atomic<bool> stopping=false;
    std::thread poller([&] { while (!stopping) server.poll(5ms); });
    std::string command;
    while (std::getline(std::cin,command) && command!="stop") {
        if (command!="counts") break;
        auto [flights,waiters]=coordinator.counts();
        std::cout << flights << ' ' << waiters << ' ' << coordinator.direct_active() << std::endl;
    }
    stopping=true; poller.join(); server.stop();
    if (coordinator.counts()!=std::pair<std::size_t,std::size_t>{0,0} || coordinator.direct_active()) return 7;
    return command=="stop" ? 0 : 8;
}
