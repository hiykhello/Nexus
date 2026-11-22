// Throughput-only microbenchmark of generation-local view lookup. This does
// not run DNS, proxy traffic, or measure request latency.
#include <time.h>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
import std;
import dns.message;
#include "../../src/dns-shared/group_view_registry.hpp"

namespace hp=dns_hp_experiment;
namespace io=boost::corosio;
using Clock=std::chrono::steady_clock;
namespace {
struct Server {
    std::array<std::uint8_t,16> address{};
    bool ipv6=false; std::uint16_t port=0; bool tcp=false;
    std::string host; std::optional<std::size_t> resolver;
};
struct Routing {
    std::vector<Server> servers;
    unsigned strategy=0; bool disable_cache=false,edns=false;
};
auto cpu_ns() -> std::uint64_t {
    timespec time{};
    if (::clock_gettime(CLOCK_THREAD_CPUTIME_ID,&time)) throw std::runtime_error("thread CPU clock failed");
    return static_cast<std::uint64_t>(time.tv_sec)*1000000000ull+static_cast<std::uint64_t>(time.tv_nsec);
}
struct Result { std::uint64_t checksum=0,cpu=0,failures=0; };
auto measure(hp::ViewRegistry& registry,std::array<hp::ViewRegistry::Profile,2> profiles,
             std::array<io::endpoint,2> endpoints,std::array<std::array<std::uint64_t,2>,2> ids,
             unsigned threads,unsigned count,unsigned variant,bool rotating) -> std::tuple<std::uint64_t,std::uint64_t,std::uint64_t,std::uint64_t> {
    std::barrier start(static_cast<std::ptrdiff_t>(threads+1));
    std::vector<Result> results(threads); std::vector<std::jthread> workers; workers.reserve(threads);
    for (unsigned thread=0;thread<threads;++thread) workers.emplace_back([&,thread] {
        hp::ViewBinding local(registry,profiles); std::uint64_t random=0x9e3779b97f4a7c15ull+thread;
        start.arrive_and_wait(); auto begin=cpu_ns();
        for (unsigned i=0;i<count;++i) {
            random=random*6364136223846793005ull+1442695040888963407ull;
            auto profile=static_cast<unsigned>((random>>32)&1);
            auto target=rotating ? static_cast<unsigned>((random>>33)&1) : profile;
            std::expected<std::uint64_t,hp::ViewRegistry::Error> view=ids[profile][target];
            if (variant==1) view=registry.view(profiles[profile],endpoints[target]);
            else if (variant==2) view=local.view(profile,endpoints[target]);
            if (!view || *view!=ids[profile][target]) ++results[thread].failures;
            else results[thread].checksum+=*view;
        }
        results[thread].cpu=cpu_ns()-begin;
    });
    auto begin=Clock::now(); start.arrive_and_wait(); workers.clear();
    auto elapsed=std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now()-begin).count();
    std::uint64_t checksum=0,cpu=0,failures=0;
    for (auto const& result:results) { checksum+=result.checksum; cpu+=result.cpu; failures+=result.failures; }
    return {static_cast<std::uint64_t>(elapsed),cpu,checksum,failures};
}
}
int main(int argc,char** argv) {
    try {
        unsigned count=argc==2 ? static_cast<unsigned>(std::stoul(argv[1])) : 200000;
        if (!count || count>5000000 || argc>2) return 2;
        hp::ViewRegistry registry(2,65536,8); Routing first,second; Server server;
        server.address[0]=127; server.address[3]=1; server.port=5300; first.servers.push_back(server);
        server.address[3]=2; second.servers.push_back(server);
        auto first_profile=registry.register_profile(first,0),second_profile=registry.register_profile(second,0);
        if (!first_profile || !second_profile) throw std::runtime_error("benchmark profile setup failed");
        registry.seal();
        std::array profiles{*first_profile,*second_profile};
        std::array endpoints{io::endpoint(io::ipv4_address::loopback(),5300),io::endpoint(io::ipv4_address::loopback(),5301)};
        std::array<std::array<std::uint64_t,2>,2> ids{};
        for (unsigned i=0;i<2;++i) for (unsigned j=0;j<2;++j) {
            auto id=registry.view(profiles[i],endpoints[j]); if (!id) throw std::runtime_error("benchmark view setup failed"); ids[i][j]=*id;
        }
        std::puts("round,threads,mode,scenario,operations,wall_ns,thread_cpu_ns,checksum,failures");
        std::array<std::string_view,3> names{"direct","registry","binding"};
        for (unsigned round=0;round<3;++round) for (auto threads:{1u,2u,4u,8u}) for (bool rotating:{false,true}) {
            std::optional<std::uint64_t> expected;
            for (unsigned n=0;n<3;++n) {
                auto variant=round==1 ? 2-n : n;
                auto [wall,cpu,checksum,failures]=measure(registry,profiles,endpoints,ids,threads,count,variant,rotating);
                if (!expected) expected=checksum;
                if (failures || checksum!=*expected) throw std::runtime_error("benchmark lost or misidentified an operation");
                std::println("{},{},{},{},{},{},{},{},{}",round+1,threads,names[variant],rotating ? "rotating" : "stable",
                             std::uint64_t(threads)*count,wall,cpu,checksum,failures);
            }
        }
    } catch (std::exception const& error) { std::println(stderr,"view benchmark: {}",error.what()); return 1; }
}
