import std;
#ifdef NEXUS_TEST_DNS_GROUP
import dns.message;
import dns.cache;
import dns.shared_cache;
#endif
import relay;

// Uses the same proxy path in each build; no cache-access instrumentation.
auto main(int argc, char** argv) -> int {
    if (argc != 3) return 2;
    int dns_port = std::stoi(argv[1]);
    int workers = std::stoi(argv[2]);
    if (dns_port < 1 || dns_port > 65535 || workers < 2 || workers > 16) return 2;
#ifdef NEXUS_TEST_DNS_GROUP
    std::array<std::size_t,1> capacities{256};
    auto cache=std::make_unique<dns_hp_experiment::GroupSnapshot>(capacities,workers,0,8*1024*1024);
#endif
    relay::Server server;
    if (!server.set_dns_upstream(std::array<std::uint8_t, 4>{127, 0, 0, 1}, dns_port)) return 3;
#ifdef NEXUS_TEST_DNS_GROUP
    if (!server.set_dns_group_for_test(*cache,0,0)) return 3;
#endif
    auto bound = server.start(0, relay::Inbound::socks5, workers);
    if (!bound) return 4;
#if defined(NEXUS_TEST_DNS_PER_WORKER)
    constexpr auto mode = "per-worker";
#elif defined(NEXUS_TEST_DNS_SNAPSHOT)
    constexpr auto mode = "snapshot";
#elif defined(NEXUS_TEST_DNS_GROUP)
    constexpr auto mode = "group";
#else
    constexpr auto mode = "shared";
#endif
    std::cout << "ready " << *bound << ' ' << mode << std::endl;
    std::string command;
    while (std::getline(std::cin, command)) {
        auto before = std::chrono::steady_clock::now();
        if (command == "stop") {
            server.stop();
            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - before).count();
            std::cout << "stopped " << elapsed << std::endl;
            return 0;
        }
        if (!command.starts_with("restart ")) return 5;
        int replacement = std::stoi(command.substr(8));
        if (replacement < 1 || replacement > 65535) return 6;
        server.stop();
        if (!server.set_dns_upstream(std::array<std::uint8_t, 4>{127, 0, 0, 1}, replacement)) return 7;
#ifdef NEXUS_TEST_DNS_GROUP
        cache=std::make_unique<dns_hp_experiment::GroupSnapshot>(capacities,workers,0,8*1024*1024);
        if (!server.set_dns_group_for_test(*cache,0,0)) return 7;
#endif
        bound = server.start(*bound, relay::Inbound::socks5, workers);
        if (!bound) return 8;
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - before).count();
        std::cout << "ready " << *bound << ' ' << mode << ' ' << elapsed << std::endl;
    }
    return 9;
}
