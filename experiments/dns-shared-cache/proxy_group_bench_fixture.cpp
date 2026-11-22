// Real proxy and SS UDP listeners, built without cache-access instrumentation.
#include <poll.h>
#include <time.h>
#ifdef NEXUS_DNS_USE_MODULES
#include <cerrno>
#include <sys/random.h>
#else
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
import std;
import dns.corosio_local;
import dns.message;
import dns.corosio_query;
import dns.cache;
#ifdef NEXUS_TEST_DNS_GROUP
import dns.shared_cache;
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
import dns.shared_coordinator;
#endif
#ifdef NEXUS_DNS_USE_MODULES
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
#endif
import proxy;
import config;
import crypto;
import rules;
import dns.local_config;
import shadowsocks.udp_dispatch;
#include "../../src/tools/udp_inbound.hpp"

auto main(int argc, char** argv) -> int {
    if (argc != 5) return 2;
    auto dns_port = std::stoi(argv[1]);
    auto workers = std::stoi(argv[2]);
    std::array<int, 2> udp_ports{std::stoi(argv[3]), std::stoi(argv[4])};
    if (dns_port < 1 || dns_port > 65535 || workers < 2 || workers > 8 ||
        std::ranges::any_of(udp_ports, [](int port) { return port < 1 || port > 65535; }) ||
        udp_ports[0] == udp_ports[1]) return 2;

    namespace p = proxy;
#ifdef NEXUS_TEST_DNS_GROUP
#ifdef NEXUS_TEST_DNS_SHARED_CAPACITY
    std::array<std::size_t, 3> capacities{1, 1, 1};
    auto cache = std::make_unique<dns_hp_experiment::GroupSnapshot>(
        capacities, dns_hp_experiment::GroupSnapshot::SharedCapacity{768},
        static_cast<std::size_t>(workers * 2 + 1), 0, 8 * 1024 * 1024);
#else
    std::array<std::size_t, 3> capacities{256, 256, 256};
    auto cache = std::make_unique<dns_hp_experiment::GroupSnapshot>(
        capacities, static_cast<std::size_t>(workers * 2 + 1), 0, 8 * 1024 * 1024);
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
    dns_hp_experiment::Coordinator coordinator(256,4096);
    dns_hp_experiment::ViewRegistry views(64,512 * 1024,8192);
#endif
#endif
    std::array<std::unique_ptr<p::Server>, 2> servers;
    p::DnsServer upstream;
    upstream.address[0] = 127; upstream.address[3] = 1; upstream.port = dns_port;
    p::DnsRouting routing{{upstream}, {}, 0};
    for (std::size_t i = 0; i < servers.size(); ++i) {
        auto created = p::Server::create();
        if (!created) return 3;
        servers[i] = std::move(*created);
        if (!servers[i]->set_dns_routing(routing)) return 4;
#ifdef NEXUS_TEST_DNS_GROUP
        if (!servers[i]->set_dns_group_for_test(*cache, i, i * workers)) return 4;
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
        if (!servers[i]->set_dns_coordinator_for_test(coordinator,views)) return 4;
#endif
    }
    UdpInbounds udp;
    auto policy = ::rules::RouteMatcher::compile({}, 0, 1);
    if (!policy) return 5;
    for (std::size_t i = 0; i < udp_ports.size(); ++i) {
        std::array<std::uint8_t, 16> key{};
        std::iota(key.begin(), key.end(), static_cast<unsigned>(i * 16));
        if (!udp.add(key, static_cast<std::uint16_t>(udp_ports[i]), *policy)) return 6;
    }
#ifdef NEXUS_TEST_DNS_GROUP
    if (!udp.set_dns_group_for_test(*cache, 2, workers * 2)) return 6;
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
    if (!udp.set_dns_coordinator_for_test(coordinator,views,routing)) return 6;
    views.seal();
#endif
    std::array<std::uint16_t, 2> ports{};
    for (std::size_t i = 0; i < servers.size(); ++i) {
        auto port = servers[i]->start(0, p::Inbound::socks5, workers);
        if (!port) return 7;
        ports[i] = *port;
    }
    if (udp.start(routing)) return 8;
#ifdef NEXUS_TEST_DNS_COORDINATOR
    constexpr auto mode = "coordinator";
#elif defined(NEXUS_TEST_DNS_GROUP)
    constexpr auto mode = "group";
#else
    constexpr auto mode = "shared";
#endif
    std::cout << "ready " << ports[0] << ' ' << ports[1] << ' ' << mode << std::endl;
#ifdef NEXUS_TEST_UDP_DIAGNOSTICS
    struct PollSample { std::int64_t begin_ns,elapsed_us,cpu_us; };
    auto trace=std::getenv("NEXUS_DNS_BENCH_TRACE_LOOP")!=nullptr;
    std::vector<PollSample> samples;
    std::size_t dropped_samples=0;
    if (trace) samples.reserve(128);
    auto wall=[] { return std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count(); };
    auto cpu=[] {
        timespec value{};
        if (::clock_gettime(CLOCK_THREAD_CPUTIME_ID,&value)) return std::int64_t{};
        return static_cast<std::int64_t>(value.tv_sec)*1'000'000'000+value.tv_nsec;
    };
    auto previous_wall=trace ? wall() : 0;
    auto previous_cpu=trace ? cpu() : 0;
#endif
    std::string command;
    for (;;) {
        udp.poll(std::chrono::milliseconds(1));
#ifdef NEXUS_TEST_UDP_DIAGNOSTICS
        if (trace) {
            auto now_wall=wall(),now_cpu=cpu();
            if (now_wall-previous_wall>=5'000'000) {
                if (samples.size()<128) samples.push_back({previous_wall,(now_wall-previous_wall)/1000,(now_cpu-previous_cpu)/1000});
                else ++dropped_samples;
            }
            previous_wall=now_wall; previous_cpu=now_cpu;
        }
#endif
        if (!udp.healthy() || !servers[0]->healthy() || !servers[1]->healthy()) return 9;
        pollfd input{0, POLLIN, 0};
        if (::poll(&input, 1, 0) < 0) return 10;
        if (!(input.revents & (POLLIN | POLLHUP))) continue;
        if (!std::getline(std::cin, command) || command != "stop") return 11;
        auto before = std::chrono::steady_clock::now();
        udp.stop();
        for (auto& server : servers) server->stop();
#ifdef NEXUS_TEST_DNS_COORDINATOR
        if (coordinator.counts()!=std::pair<std::size_t,std::size_t>{0,0} || coordinator.direct_active()) return 12;
#endif
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - before).count();
#ifdef NEXUS_TEST_UDP_DIAGNOSTICS
        for (auto const& sample:samples)
            std::cerr << "bench-poll " << sample.begin_ns << ' ' << sample.elapsed_us << ' ' << sample.cpu_us << '\n';
        if (trace) std::cerr << "bench-poll-dropped " << dropped_samples << '\n';
#endif
        std::cout << "stopped " << elapsed << std::endl;
        return 0;
    }
}
