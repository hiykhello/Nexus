// Test-only use of actual Server workers with a shared experimental owner.
#ifdef NEXUS_TEST_DNS_GROUP_UDP
#include <poll.h>
#include <cerrno>
#include <sys/random.h>
#ifndef NEXUS_DNS_USE_MODULES
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/udp_socket.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#endif
#endif
import std;
import dns.corosio_local;
import dns.message;
import dns.corosio_query;
import dns.cache;
import dns.shared_cache;
#ifdef NEXUS_TEST_DNS_COORDINATOR
import dns.shared_coordinator;
#endif
#ifdef NEXUS_DNS_USE_MODULES
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
#endif
import proxy;
#ifdef NEXUS_TEST_DNS_GROUP_UDP
import config;
import crypto;
import rules;
import dns.local_config;
import shadowsocks.udp_dispatch;
#include "../../src/tools/udp_inbound.hpp"
#endif

namespace {
std::mutex mutex;
std::array<std::thread::id,8> ids;
std::array<void const*,8> bindings{};
std::size_t workers=0,calls=0;
auto stats() -> std::pair<std::size_t,std::size_t> {
    std::lock_guard lock(mutex); auto result=std::pair{workers,calls}; workers=0; calls=0; return result;
}
}
extern "C" void nexus_test_dns_shared_access(void const* binding) noexcept {
    std::lock_guard lock(mutex); auto id=std::this_thread::get_id();
    for (std::size_t i=0;i<workers;++i) if (ids[i]==id) {
        if (bindings[i]!=binding) std::abort(); ++calls; return;
    }
    if (workers==ids.size()) std::abort();
    ids[workers]=id; bindings[workers]=binding; ++workers; ++calls;
}
int main(int argc,char** argv) {
#ifdef NEXUS_TEST_DNS_GROUP_UDP
    if (argc!=5) return 2;
#else
    if (argc!=3) return 2;
#endif
    auto first_port=std::stoi(argv[1]); if (first_port<1 || first_port>65535) return 2;
    auto first_leaf=std::stoi(argv[2]); if (first_leaf<1 || first_leaf>65535) return 2;
    namespace p=proxy;
    using Cache=dns_hp_experiment::GroupSnapshot;
#ifdef NEXUS_TEST_DNS_GROUP_UDP
    std::array<std::size_t,3> capacities{16,16,16};
    constexpr std::size_t readers=5;
#else
    std::array<std::size_t,2> capacities{16,16};
    constexpr std::size_t readers=4;
#endif
#ifdef NEXUS_TEST_DNS_SHARED_CAPACITY
    capacities.fill(1);
#endif
    std::array<std::unique_ptr<Cache>,2> caches;
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
    bool optimistic=std::getenv("NEXUS_TEST_DNS_OPTIMISTIC")!=nullptr;
    std::array<std::unique_ptr<dns::detail::RefreshBudget>,2> budgets;
    if (optimistic) for (auto& budget:budgets) budget=std::make_unique<dns::detail::RefreshBudget>(8);
#elif defined(NEXUS_TEST_DNS_COORDINATOR)
    bool optimistic=std::getenv("NEXUS_TEST_DNS_OPTIMISTIC")!=nullptr;
#else
    constexpr bool optimistic=false;
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
    std::array<std::unique_ptr<dns_hp_experiment::Coordinator>,2> coordinators;
    std::array<std::unique_ptr<dns_hp_experiment::ViewRegistry>,2> registries;
    for (std::size_t i=0;i<coordinators.size();++i) {
        coordinators[i]=std::make_unique<dns_hp_experiment::Coordinator>(8,64);
        registries[i]=std::make_unique<dns_hp_experiment::ViewRegistry>(16,65536,64);
    }
#endif
    for (auto& cache:caches) {
#ifdef NEXUS_TEST_DNS_SHARED_CAPACITY
        cache=std::make_unique<Cache>(capacities,Cache::SharedCapacity{capacities.size()*16},readers,
                                      optimistic ? 10000 : 0,8*1024*1024);
#else
        cache=std::make_unique<Cache>(capacities,readers,optimistic ? 10000 : 0,8*1024*1024);
#endif
    }
    std::array<std::unique_ptr<p::Server>,2> servers;
    for (auto& server:servers) {
        auto created=p::Server::create(); if (!created) return 3; server=std::move(*created);
    }
#ifdef NEXUS_TEST_DNS_GROUP_UDP
    UdpInbounds udp;
    auto policy=::rules::RouteMatcher::compile({},0,1); if (!policy) return 10;
    for (std::size_t i=0;i<2;++i) {
        auto port=std::stoi(argv[i+3]); if (port<1 || port>65535) return 2;
        std::array<std::uint8_t,16> key{}; std::iota(key.begin(),key.end(),static_cast<unsigned>(i*16));
        if (!udp.add(key,static_cast<std::uint16_t>(port),*policy)) return 11;
    }
#endif
    p::DnsRouting routing;
    auto setup=[&](std::size_t generation,std::uint16_t port,std::uint16_t leaf_port) -> bool {
        p::DnsServer root; root.address[0]=127; root.address[3]=1; root.port=port;
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
#ifdef NEXUS_TEST_DNS_COORDINATOR
            if (!servers[i]->set_dns_coordinator_for_test(*coordinators[generation],*registries[generation],optimistic)) return false;
#endif
        }
#ifdef NEXUS_TEST_DNS_GROUP_UDP
        if (!udp.set_dns_group_for_test(*caches[generation],2,4
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
            ,budgets[generation].get()
#endif
        )) return false;
#ifdef NEXUS_TEST_DNS_COORDINATOR
        if (!udp.set_dns_coordinator_for_test(*coordinators[generation],*registries[generation],routing,optimistic)) return false;
#endif
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
        registries[generation]->seal();
#endif
        return true;
    };
    if (servers[0]->set_dns_group_for_test(*caches[0],capacities.size(),0) ||
        servers[0]->set_dns_group_for_test(*caches[0],0,readers) || !setup(0,first_port,first_leaf)) return 4;
    auto start=[&]() -> bool {
        std::array<std::uint16_t,2> ports{};
        for (std::size_t i=0;i<servers.size();++i) {
            auto port=servers[i]->start(0,p::Inbound::socks5,2); if (!port) return false; ports[i]=*port;
        }
        if (servers[0]->set_dns_group_for_test(*caches[0],0,0)) return false;
#ifdef NEXUS_TEST_DNS_GROUP_UDP
        if (udp.start(routing) || udp.set_dns_group_for_test(*caches[0],2,4)) return false;
#endif
        std::cout<<ports[0]<<' '<<ports[1]<<std::endl; return true;
    };
    if (!start()) return 5;
    std::string line; bool restarted=false;
    for (;;) {
#ifdef NEXUS_TEST_DNS_GROUP_UDP
        udp.poll(std::chrono::milliseconds(2)); if (!udp.healthy()) return 12;
        pollfd input{0,POLLIN,0}; if (::poll(&input,1,0)<0) return 13;
        if (!(input.revents&(POLLIN|POLLHUP))) continue;
#endif
        if (!std::getline(std::cin,line)) break;
        if (line=="stop") break;
#ifdef NEXUS_TEST_DNS_COORDINATOR
        if (line=="counts") {
            auto [flights,waiters]=coordinators[restarted ? 1 : 0]->counts();
            std::cout<<flights<<' '<<waiters<<' '<<coordinators[restarted ? 1 : 0]->direct_active()<<std::endl;
            continue;
        }
#endif
        if (!line.starts_with("restart ") || restarted) return 6;
        std::istringstream command(line.substr(8)); unsigned next=0,next_leaf=0;
        if (!(command>>next>>next_leaf) || !next || next>65535 || !next_leaf || next_leaf>65535) return 7;
#ifdef NEXUS_TEST_DNS_GROUP_UDP
        udp.stop();
#endif
        for (auto& server:servers) server->stop();
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
        if (budgets[0] && budgets[0]->active()) return 14;
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
        if (coordinators[0]->counts()!=std::pair<std::size_t,std::size_t>{0,0} || coordinators[0]->direct_active()) return 15;
#endif
        auto [seen,observed]=stats(); std::cout<<seen<<' '<<observed<<std::endl;
        if (!setup(1,static_cast<std::uint16_t>(next),static_cast<std::uint16_t>(next_leaf)) || !start()) return 8;
        restarted=true;
    }
#ifdef NEXUS_TEST_DNS_GROUP_UDP
    udp.stop();
#endif
    for (auto& server:servers) server->stop();
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
    if (budgets[restarted ? 1 : 0] && budgets[restarted ? 1 : 0]->active()) return 14;
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
    auto& coordinator=*coordinators[restarted ? 1 : 0];
    if (coordinator.counts()!=std::pair<std::size_t,std::size_t>{0,0} || coordinator.direct_active()) return 15;
#endif
    auto [seen,observed]=stats(); std::cout<<seen<<' '<<observed<<std::endl;
    return line=="stop" ? 0 : 9;
}
