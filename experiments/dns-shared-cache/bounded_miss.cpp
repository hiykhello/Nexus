#include "bounded_table.hpp"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

using namespace dns_hp_experiment;
using Clock=std::chrono::steady_clock;
auto make_answer(Key const& key,std::uint64_t revision) -> Answer {
    return {key.name,{key.name},{},100000,revision};
}
int main() {
    HazardTable table(1);
    auto reader=table.reader(0);
    std::vector<Key> keys;
    for (int i=0;i<256;++i) {
        keys.push_back({1,"host-"+std::to_string(i)+".example.test",1});
        if (!table.put(keys.back(),make_answer(keys.back(),1))) std::abort();
    }
    auto measure=[&](char const* stage) {
        Key absent{1,"never-present.example.test",1};
        std::vector<long long> samples;
        constexpr int iterations=100000;
        samples.reserve(iterations/100);
        auto begin=Clock::now();
        for (int i=0;i<iterations;++i) {
            auto start=i%100==0 ? Clock::now() : Clock::time_point{};
            if (reader.get(absent)) std::abort();
            if (i%100==0) samples.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now()-start).count());
        }
        auto elapsed=std::chrono::duration<double>(Clock::now()-begin).count();
        std::sort(samples.begin(),samples.end());
        std::cout<<stage<<','<<iterations/elapsed<<','<<samples[samples.size()/2]<<','<<samples[(samples.size()-1)*99/100]<<'\n';
    };
    std::cout<<"stage,misses_per_second,p50_ns,p99_ns\n";
    measure("initial");
    for (int i=0;i<10000;++i) {
        auto index=i%keys.size();
        if (!table.erase(keys[index])) std::abort();
        keys[index]={1,"churn-"+std::to_string(i)+".example.test",1};
        if (!table.put(keys[index],make_answer(keys[index],i+2))) std::abort();
    }
    for (auto const& key:keys) if (!reader.get(key)) std::abort();
    measure("after-churn");
}
