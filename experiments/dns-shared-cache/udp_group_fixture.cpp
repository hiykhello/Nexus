import std;
import ss_udp.shared_coordinator;
import rules;
import relay;

namespace {
    namespace p = relay;
    namespace u = relay::udp_runtime;
    using Cache=dns_hp_experiment::GroupSnapshot;

    auto parse_port(char const* text) -> std::optional<std::uint16_t> {
        auto value=std::strtoul(text,nullptr,10);
        if (!value || value>65535) return std::nullopt;
        return static_cast<std::uint16_t>(value);
    }
    template<class Udp>
    auto run(std::array<std::uint16_t,4> ports) -> int {
        using namespace std::chrono_literals;
        std::array<std::size_t,1> capacities{1};
        std::array<std::unique_ptr<Cache>,2> caches;
        for (auto& cache:caches) cache=std::make_unique<Cache>(capacities,Cache::SharedCapacity{256},1,10000,8*1024*1024);
        std::array<std::unique_ptr<dns::detail::RefreshBudget>,2> budgets;
        std::array<std::unique_ptr<dns_hp_experiment::Coordinator>,2> coordinators;
        std::array<std::unique_ptr<dns_hp_experiment::ViewRegistry>,2> views;
        if constexpr (std::same_as<Udp,u::GroupRefreshUdpInbounds>) {
            for (auto& budget:budgets) budget=std::make_unique<dns::detail::RefreshBudget>(8);
        }
        if constexpr (std::same_as<Udp,u::CoordinatorUdpInbounds>) {
            for (std::size_t i=0;i<views.size();++i) {
                coordinators[i]=std::make_unique<dns_hp_experiment::Coordinator>(8,64);
                views[i]=std::make_unique<dns_hp_experiment::ViewRegistry>(16,65536,64);
            }
        }
        auto policy=::rules::RouteMatcher::compile({},0,1);
        if (!policy) return 3;
        std::array<std::uint8_t,16> first{},second{};
        std::iota(first.begin(),first.end(),0); std::iota(second.begin(),second.end(),16);
        Udp owner;
        if (!owner.add(first,ports[0],*policy) || !owner.add(second,ports[1],*policy)) return 4;
        p::DnsRouting routing;
        routing.strategy=p::DnsStrategy::ipv4_only;
        p::DnsServer upstream;
        upstream.address[0]=127; upstream.address[3]=1; upstream.port=ports[2];
        routing.servers.push_back(std::move(upstream));
        auto start=[&](std::size_t generation) -> bool {
            auto& setup=owner.setup();
            if constexpr (std::same_as<Udp,u::GroupRefreshUdpInbounds>) {
                if (!setup.bind(*caches[generation],0,0,budgets[generation].get())) return false;
            } else if (!setup.bind(*caches[generation],0,0)) return false;
            if constexpr (std::same_as<Udp,u::CoordinatorUdpInbounds>) {
                if (!setup.bind_coordinator(*coordinators[generation],*views[generation],routing,true)) return false;
                views[generation]->seal();
            }
            return !owner.start(routing);
        };
        if (!start(0)) return 5;
        std::cout << "ready" << std::endl;
        std::mutex mutex;
        std::vector<std::string> commands;
        bool input_ended=false;
        std::thread reader([&] {
            std::string line;
            while (std::getline(std::cin,line)) {
                std::lock_guard lock(mutex);
                commands.push_back(line);
                if (line=="stop") break;
            }
            std::lock_guard lock(mutex); input_ended=true;
        });
        std::size_t generation=0;
        int error=0;
        for (;;) {
            owner.poll(2ms);
            if (!owner.healthy()) { error=6; break; }
            std::string command;
            {
                std::lock_guard lock(mutex);
                if (!commands.empty()) { command=std::move(commands.front()); commands.erase(commands.begin()); }
                else if (input_ended) { error=7; break; }
            }
            if (command.empty()) continue;
            if (command=="stop") break;
            if (command!="restart" || generation) { error=8; break; }
            owner.stop();
            if constexpr (std::same_as<Udp,u::GroupRefreshUdpInbounds>)
                if (budgets[0]->active()) { error=9; break; }
            if constexpr (std::same_as<Udp,u::CoordinatorUdpInbounds>)
                if (coordinators[0]->counts()!=std::pair<std::size_t,std::size_t>{0,0} || coordinators[0]->direct_active()) { error=10; break; }
            routing.servers[0].port=ports[3];
            generation=1;
            if (!start(generation)) { error=11; break; }
            std::cout << "ready" << std::endl;
        }
        owner.stop();
        if constexpr (std::same_as<Udp,u::GroupRefreshUdpInbounds>)
            if (budgets[generation]->active()) error=12;
        if constexpr (std::same_as<Udp,u::CoordinatorUdpInbounds>)
            if (coordinators[generation]->counts()!=std::pair<std::size_t,std::size_t>{0,0} || coordinators[generation]->direct_active()) error=13;
        if (error) std::_Exit(error); // The command reader may still be blocked on stdin.
        reader.join();
        return 0;
    }
}
int main(int argc,char** argv) {
    if (argc!=5) return 1;
    std::array<std::uint16_t,4> ports{};
    for (std::size_t i=0;i<ports.size();++i) {
        auto value=parse_port(argv[i+1]); if (!value) return 2; ports[i]=*value;
    }
    auto mode=std::getenv("NEXUS_TEST_UDP_CACHE");
    if (mode && std::string_view(mode)=="refresh") return run<u::GroupRefreshUdpInbounds>(ports);
    if (mode && std::string_view(mode)=="coordinator") return run<u::CoordinatorUdpInbounds>(ports);
    if (!mode || std::string_view(mode)=="group") return run<u::GroupUdpInbounds>(ports);
    return 2;
}
