import std;
import platform.network_state;

namespace network = ::platform::network;

auto main() -> int {
    using namespace std::chrono_literals;
    network::Monitor monitor;
    if (auto result=monitor.start(network::Clock::now()+2s);!result) {
        std::println("initial network snapshot failed, error={} system={}",
            static_cast<int>(result.error().code),result.error().system.message());
        return 1;
    }
    auto baseline=monitor.get();
    if (!baseline || baseline->links.empty()) return 2;
    std::println("ready generation={}",baseline->generation);
    std::fflush(nullptr);
    for (char change;std::cin>>change;) {
        auto refreshed=monitor.poll(network::Clock::now()+2s);
        auto view=monitor.get();
        if (!refreshed || !*refreshed || !view || view->generation<=baseline->generation) return 3;
        for (auto const& link : view->links)
            std::println("link {} {} {} {}",link.index,link.name,link.kind,link.up());
        for (auto const& route : view->routes)
            if (route.default_route()) std::println("default {} {} {}",route.family,route.index,route.priority);
        std::println("generation={} baseline={} addresses={}",view->generation,baseline->generation,view->addresses.size());
        std::fflush(nullptr);
    }
}
