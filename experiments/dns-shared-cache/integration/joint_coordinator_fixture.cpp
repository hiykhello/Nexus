// Exercise the actual proxy workers and SS UDP listeners with one experimental
// cache/coordinator per configuration generation.
import std;
import dns.corosio_local;
import dns.message;
import dns.corosio_query;
import dns.cache;
import dns.shared_cache;
import dns.shared_coordinator;
import capy;
import corosio;
import relay;
import rules;
import ss_udp.shared_coordinator;

namespace {
    namespace p = relay;
    namespace u = relay::udp_runtime;
    using Cache=dns_hp_experiment::GroupSnapshot;
    std::mutex access_mutex;
    struct ThreadAccess { std::size_t epoch=std::numeric_limits<std::size_t>::max(); void const* binding=nullptr; };
    thread_local ThreadAccess thread_access;
    std::size_t access_epoch=0,access_workers=0,access_calls=0;

    auto stats() -> std::pair<std::size_t,std::size_t> {
        std::lock_guard lock(access_mutex);
        auto result=std::pair{access_workers,access_calls};
        ++access_epoch; access_workers=0; access_calls=0;
        return result;
    }
    auto port(char const* input) -> std::optional<std::uint16_t> {
        char* end=nullptr;
        auto value=std::strtoul(input,&end,10);
        if (end==input || *end || !value || value>65535) return std::nullopt;
        return static_cast<std::uint16_t>(value);
    }
}

extern "C" void nexus_test_dns_shared_access(void const* binding) noexcept {
    std::lock_guard lock(access_mutex);
    if (thread_access.epoch==access_epoch) {
        if (thread_access.binding!=binding) std::abort();
        ++access_calls; return;
    }
    if (access_workers==8) std::abort();
    thread_access={access_epoch,binding};
    ++access_workers; ++access_calls;
}

auto main(int argc,char** argv) -> int {
    if (argc!=5) return 2;
    std::array<std::uint16_t,4> ports{};
    for (std::size_t i=0;i<ports.size();++i) {
        auto parsed=port(argv[i+1]); if (!parsed) return 2;
        ports[i]=*parsed;
    }
    bool optimistic=std::getenv("NEXUS_TEST_DNS_OPTIMISTIC")!=nullptr;
    std::array<std::size_t,3> capacities{1,1,1};
    constexpr std::size_t readers=5;
    std::array<std::unique_ptr<Cache>,2> caches;
    std::array<std::unique_ptr<dns_hp_experiment::Coordinator>,2> coordinators;
    std::array<std::unique_ptr<dns_hp_experiment::ViewRegistry>,2> registries;
    for (std::size_t i=0;i<caches.size();++i) {
        caches[i]=std::make_unique<Cache>(capacities,Cache::SharedCapacity{48},readers,
                                          optimistic ? 10000 : 0,8*1024*1024);
        coordinators[i]=std::make_unique<dns_hp_experiment::Coordinator>(8,64);
        registries[i]=std::make_unique<dns_hp_experiment::ViewRegistry>(16,65536,64);
    }
    std::array<std::unique_ptr<p::Server>,2> servers;
    for (auto& server:servers) {
        auto created=p::Server::create(); if (!created) return 3;
        server=std::move(*created);
    }
    u::CoordinatorUdpInbounds udp;
    auto policy=::rules::RouteMatcher::compile({},0,1); if (!policy) return 10;
    for (std::size_t i=0;i<2;++i) {
        std::array<std::uint8_t,16> key{};
        std::iota(key.begin(),key.end(),static_cast<unsigned>(i*16));
        if (!udp.add(key,ports[i+2],*policy)) return 11;
    }
    p::DnsRouting routing;
    auto setup=[&](std::size_t generation,std::uint16_t root_port,std::uint16_t leaf_port) -> bool {
        p::DnsServer root; root.address[0]=127; root.address[3]=1; root.port=root_port;
        p::DnsServer leaf; leaf.host="shared.example.test"; leaf.port=leaf_port; leaf.resolver=0;
        routing.servers.clear(); routing.servers.push_back(std::move(root)); routing.servers.push_back(std::move(leaf));
        routing.final=1;
        for (std::size_t i=0;i<servers.size();++i) {
            if (!servers[i]->set_dns_routing(routing) ||
                !servers[i]->set_dns_group_for_test(*caches[generation],i,i*2) ||
                !servers[i]->set_dns_coordinator_for_test(*coordinators[generation],*registries[generation],optimistic))
                return false;
        }
        auto& cache=udp.setup();
        if (!cache.bind(*caches[generation],2,4) ||
            !cache.bind_coordinator(*coordinators[generation],*registries[generation],routing,optimistic))
            return false;
        registries[generation]->seal();
        return true;
    };
    if (servers[0]->set_dns_group_for_test(*caches[0],capacities.size(),0) ||
        servers[0]->set_dns_group_for_test(*caches[0],0,readers) || !setup(0,ports[0],ports[1])) return 4;
    auto start=[&]() -> bool {
        std::array<std::uint16_t,2> listeners{};
        for (std::size_t i=0;i<servers.size();++i) {
            auto bound=servers[i]->start(0,p::Inbound::socks5,2);
            if (!bound) return false;
            listeners[i]=*bound;
        }
        if (servers[0]->set_dns_group_for_test(*caches[0],0,0) || udp.start(routing) ||
            udp.setup().bind(*caches[0],2,4)) return false;
        std::cout << listeners[0] << ' ' << listeners[1] << std::endl;
        return true;
    };
    if (!start()) return 5;

    std::mutex command_mutex;
    std::vector<std::string> commands;
    bool input_ended=false;
    std::thread input([&] {
        std::string line;
        while (std::getline(std::cin,line)) {
            std::lock_guard lock(command_mutex);
            commands.push_back(line);
            if (line=="stop") break;
        }
        std::lock_guard lock(command_mutex); input_ended=true;
    });
    std::size_t generation=0;
    int error=0;
    for (;;) {
        udp.poll(std::chrono::milliseconds(2));
        if (!udp.healthy()) { error=12; break; }
        std::string command;
        {
            std::lock_guard lock(command_mutex);
            if (!commands.empty()) { command=std::move(commands.front()); commands.erase(commands.begin()); }
            else if (input_ended) { error=9; break; }
        }
        if (command.empty()) continue;
        if (command=="stop") break;
        if (command=="counts") {
            auto [flights,waiters]=coordinators[generation]->counts();
            std::cout << flights << ' ' << waiters << ' ' << coordinators[generation]->direct_active() << std::endl;
            continue;
        }
        if (!command.starts_with("restart ") || generation) { error=6; break; }
        std::istringstream values(command.substr(8));
        unsigned next_root=0,next_leaf=0;
        if (!(values>>next_root>>next_leaf) || !next_root || next_root>65535 || !next_leaf || next_leaf>65535) {
            error=7; break;
        }
        udp.stop();
        for (auto& server:servers) server->stop();
        if (coordinators[0]->counts()!=std::pair<std::size_t,std::size_t>{0,0} || coordinators[0]->direct_active()) {
            error=15; break;
        }
        auto [seen,calls]=stats(); std::cout << seen << ' ' << calls << std::endl;
        if (!setup(1,static_cast<std::uint16_t>(next_root),static_cast<std::uint16_t>(next_leaf)) || !start()) {
            error=8; break;
        }
        generation=1;
    }
    udp.stop();
    for (auto& server:servers) server->stop();
    if (coordinators[generation]->counts()!=std::pair<std::size_t,std::size_t>{0,0} ||
        coordinators[generation]->direct_active()) error=15;
    if (error) std::_Exit(error); // Input may still be blocked on stdin.
    auto [seen,calls]=stats(); std::cout << seen << ' ' << calls << std::endl;
    input.join();
    return 0;
}
