// Isolated container experiment, not an implementation of DNS cache semantics.
#include <xenium/harris_michael_hash_map.hpp>
#include <xenium/reclamation/hazard_pointer.hpp>
#include <algorithm>
#include <array>
#include <barrier>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using Clock = std::chrono::steady_clock;
using Map = std::unordered_map<std::string, std::string>;
using Concurrent = xenium::harris_michael_hash_map<std::string, std::string,
    xenium::policy::reclaimer<xenium::reclamation::hazard_pointer<>>>;
struct Shard { std::mutex mutex; Map map; };

int main(int argc, char** argv) {
    if (argc != 4) { std::cerr << "usage: read_bench per-worker|sharded|xenium threads hot|uniform\n"; return 2; }
    std::string mode=argv[1], distribution=argv[3];
    int threads=std::atoi(argv[2]);
    if ((mode!="per-worker" && mode!="sharded" && mode!="xenium") || threads<1 || threads>128 ||
        (distribution!="hot" && distribution!="uniform")) return 2;
    constexpr std::size_t count=256, iterations=100000, sample_every=100;
    std::vector<std::string> keys;
    for (std::size_t i=0;i<count;++i) keys.push_back("host-"+std::to_string(i)+".example.test");
    std::vector<Map> local(mode=="per-worker" ? threads : 0);
    std::array<Shard,16> shards;
    Concurrent concurrent;
    auto shard_index=[](std::string const& key) { return std::hash<std::string>{}(key)%16; };
    for (auto const& key:keys) {
        std::string value=key+":192.0.2.10,2001:db8::10";
        if (mode=="per-worker") for (auto& map:local) map.emplace(key,value);
        else if (mode=="sharded") shards[shard_index(key)].map.emplace(key,value);
        else if (!concurrent.emplace(key,value)) std::abort();
    }
    std::barrier gate(threads+1);
    std::vector<std::thread> workers;
    std::vector<std::vector<long long>> samples(threads);
    std::vector<std::size_t> sums(threads);
    for (int t=0;t<threads;++t) workers.emplace_back([&,t] {
        auto& sample=samples[t]; sample.reserve(iterations/sample_every);
        std::size_t sum=0;
        std::uint64_t rng=0x9e3779b97f4a7c15ULL+static_cast<unsigned>(t);
        gate.arrive_and_wait();
        for (std::size_t i=0;i<iterations;++i) {
            rng^=rng<<13; rng^=rng>>7; rng^=rng<<17;
            auto const& key=keys[distribution=="hot" ? 0 : rng%count];
            auto start=i%sample_every==0 ? Clock::now() : Clock::time_point{};
            std::string value;
            if (mode=="per-worker") value=local[t].at(key);
            else if (mode=="sharded") {
                auto& shard=shards[shard_index(key)];
                std::lock_guard lock(shard.mutex); value=shard.map.at(key);
            } else {
                auto found=concurrent.find(key);
                if (found==concurrent.end()) std::abort();
                value=found->second;
            }
            if (i%sample_every==0) sample.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now()-start).count());
            sum+=value.size();
        }
        sums[t]=sum;
    });
    auto start=Clock::now(); gate.arrive_and_wait();
    for (auto& thread:workers) thread.join();
    auto elapsed=std::chrono::duration<double>(Clock::now()-start).count();
    std::vector<long long> combined;
    for (auto& sample:samples) combined.insert(combined.end(),sample.begin(),sample.end());
    std::sort(combined.begin(),combined.end());
    auto quantile=[&](double q) { return combined[static_cast<std::size_t>(q*(combined.size()-1))]; };
    std::size_t checksum=0; for (auto sum:sums) checksum+=sum;
    std::cout<<mode<<','<<threads<<','<<distribution<<','<<(threads*iterations/elapsed)<<','
             <<quantile(.5)<<','<<quantile(.99)<<','<<quantile(.999)<<','<<checksum<<'\n';
}
