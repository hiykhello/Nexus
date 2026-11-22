// Two real TCP servers and SS UDP inbounds share a group cache generation.
import std;
import dns.cache;
import dns.shared_cache;
import proxy;
import rules;
import ss_udp.shared_cache;

namespace {
    namespace p=proxy;
    namespace u=proxy::udp_runtime;
    using Cache=dns_hp_experiment::GroupSnapshot;
    using Budget=dns::detail::RefreshBudget;
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
    using Udp=u::GroupRefreshUdpInbounds;
#else
    using Udp=u::GroupUdpInbounds;
#endif
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
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
    bool optimistic=std::getenv("NEXUS_TEST_DNS_OPTIMISTIC")!=nullptr;
#else
    constexpr bool optimistic=false;
#endif
    std::array<std::size_t,3> groups{1,1,1};
    constexpr std::size_t readers=5;
    std::array<std::unique_ptr<Cache>,2> caches;
    std::array<std::unique_ptr<Budget>,2> budgets;
    for (std::size_t i=0;i<caches.size();++i) {
        caches[i]=std::make_unique<Cache>(groups,Cache::SharedCapacity{48},readers,
                                          optimistic ? 10000 : 0,8*1024*1024);
        if (optimistic) budgets[i]=std::make_unique<Budget>(8);
    }
    std::array<std::unique_ptr<p::Server>,2> servers;
    for (auto& server:servers) {
        auto created=p::Server::create(); if (!created) return 3;
        server=std::move(*created);
    }
    Udp udp;
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
                !servers[i]->set_dns_group_for_test(*caches[generation],i,i*2
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
                    ,budgets[generation].get()
#endif
                )) return false;
        }
        return udp.setup().bind(*caches[generation],2,4,budgets[generation].get());
    };
    if (servers[0]->set_dns_group_for_test(*caches[0],groups.size(),0) ||
        servers[0]->set_dns_group_for_test(*caches[0],0,readers) || !setup(0,ports[0],ports[1])) return 4;
    auto start=[&]() -> bool {
        std::array<std::uint16_t,2> local{};
        for (std::size_t i=0;i<servers.size();++i) {
            auto bound=servers[i]->start(0,p::Inbound::socks5,2); if (!bound) return false;
            local[i]=*bound;
        }
        if (servers[0]->set_dns_group_for_test(*caches[0],0,0) || udp.start(routing) ||
            udp.setup().bind(*caches[0],2,4)) return false;
        std::cout << local[0] << ' ' << local[1] << std::endl;
        return true;
    };
    if (!start()) return 5;
    std::mutex command_mutex;
    std::vector<std::string> commands;
    bool input_ended=false;
    std::thread input([&] {
        std::string command;
        while (std::getline(std::cin,command)) {
            std::lock_guard lock(command_mutex);
            commands.push_back(command);
            if (command=="stop") break;
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
        if (!command.starts_with("restart ") || generation) { error=6; break; }
        std::istringstream values(command.substr(8));
        unsigned next_root=0,next_leaf=0;
        if (!(values>>next_root>>next_leaf) || !next_root || next_root>65535 || !next_leaf || next_leaf>65535) {
            error=7; break;
        }
        udp.stop();
        for (auto& server:servers) server->stop();
        if (budgets[0] && budgets[0]->active()) { error=14; break; }
        auto [seen,calls]=stats(); std::cout << seen << ' ' << calls << std::endl;
        if (!setup(1,static_cast<std::uint16_t>(next_root),static_cast<std::uint16_t>(next_leaf)) || !start()) {
            error=8; break;
        }
        generation=1;
    }
    udp.stop();
    for (auto& server:servers) server->stop();
    if (budgets[generation] && budgets[generation]->active()) error=14;
    if (error) std::_Exit(error); // Input may still be blocked on stdin.
    auto [seen,calls]=stats(); std::cout << seen << ' ' << calls << std::endl;
    input.join();
    return 0;
}
