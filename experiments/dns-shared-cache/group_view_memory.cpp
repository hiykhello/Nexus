// Independent-process memory sample for the experimental view registry.
#include <malloc.h>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
import std;
import dns.message;
#include "../../src/dns-shared/group_view_registry.hpp"

namespace hp=dns_hp_experiment;
namespace io=boost::corosio;
namespace {
struct Server {
    std::array<std::uint8_t,16> address{};
    bool ipv6=false; std::uint16_t port=0; bool tcp=false;
    std::string host; std::optional<std::size_t> resolver;
};
struct Routing { std::vector<Server> servers; unsigned strategy=0; bool disable_cache=false,edns=false; };
struct Memory { std::size_t allocated=0,rss_kib=0; };
auto sample() -> Memory {
    auto heap=mallinfo2(); Memory memory{static_cast<std::size_t>(heap.uordblks+heap.hblkhd),0};
    std::ifstream input("/proc/self/smaps_rollup"); std::string line;
    while (std::getline(input,line)) if (line.starts_with("Rss:")) {
        std::istringstream values(line.substr(4)); values>>memory.rss_kib; break;
    }
    if (!memory.rss_kib) throw std::runtime_error("smaps RSS unavailable");
    return memory;
}
auto target(std::size_t value) -> io::endpoint {
    io::ipv4_address::bytes_type bytes{10,static_cast<std::uint8_t>(value>>16),
                                      static_cast<std::uint8_t>(value>>8),static_cast<std::uint8_t>(value)};
    return {io::ipv4_address(bytes),5300};
}
}
int main(int argc,char** argv) {
    try {
        if (argc!=4) return 2;
        auto profiles=std::stoul(argv[1]),views=std::stoul(argv[2]),bindings=std::stoul(argv[3]);
        if (!profiles || profiles>2 || views<profiles || views>8192 || bindings>32) return 2;
        // Construct configuration before the baseline so it is not confused
        // with registry and executor-local storage.
        std::vector<Routing> configurations(profiles);
        for (std::size_t i=0;i<profiles;++i) {
            Server server; server.address[0]=127; server.address[3]=static_cast<std::uint8_t>(1+i); server.port=5300;
            configurations[i].servers.push_back(server);
        }
        auto before=sample();
        hp::ViewRegistry registry(profiles,65536,views);
        std::vector<hp::ViewRegistry::Profile> handles; handles.reserve(profiles);
        for (auto const& config:configurations) {
            auto profile=registry.register_profile(config,0);
            if (!profile) throw std::runtime_error("profile allocation failed"); handles.push_back(*profile);
        }
        registry.seal();
        for (std::size_t i=0;i<views;++i) {
            auto id=registry.view(handles[i%profiles],target(i));
            if (!id || *id!=i+1) throw std::runtime_error("unexpected view mapping");
        }
        std::vector<std::unique_ptr<hp::ViewBinding>> workers; workers.reserve(bindings);
        for (std::size_t i=0;i<bindings;++i) {
            auto binding=std::make_unique<hp::ViewBinding>(registry,handles);
            for (std::size_t j=0;j<profiles;++j) {
                auto id=binding->view(j,target(j));
                if (!id || *id!=j+1) throw std::runtime_error("binding lookup failed");
            }
            workers.push_back(std::move(binding));
        }
        if (registry.counts()!=std::pair<std::size_t,std::size_t>{profiles,views}) throw std::runtime_error("unexpected view count");
        auto after=sample();
        std::println("{},{},{},{},{},{},{},{},{}",profiles,views,bindings,registry.policy_bytes(),
                     before.allocated,after.allocated,static_cast<std::int64_t>(after.allocated)-static_cast<std::int64_t>(before.allocated),
                     before.rss_kib,after.rss_kib);
    } catch (std::exception const& error) { std::println(stderr,"view memory: {}",error.what()); return 1; }
}
