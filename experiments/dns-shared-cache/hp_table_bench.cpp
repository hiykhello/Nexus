#ifdef DNS_HP_BOUNDED
#include "bounded_table.hpp"
#else
#include "hp_table.hpp"
#endif
#include <algorithm>
#include <barrier>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <shared_mutex>
#include <thread>
#include <unordered_map>

using namespace dns_hp_experiment;
using Clock=std::chrono::steady_clock;
struct LockedTable {
    std::shared_mutex mutex;
    std::unordered_map<Key,Answer,KeyHash> entries;
    auto get(Key const& key) -> std::optional<Answer> {
        std::shared_lock lock(mutex);
        auto it=entries.find(key);
        if (it==entries.end()) return {};
        return it->second;
    }
    void put(Key const& key,Answer value) {
        std::unique_lock lock(mutex);
        entries.insert_or_assign(key,std::move(value));
    }
};
auto make_answer(Key const& key,std::uint64_t revision) -> Answer {
    Answer result{key.name,{key.name},{},100000,revision};
    result.address[0]=static_cast<std::uint8_t>(revision);
    return result;
}
int main(int argc,char** argv) {
    if (argc!=5) { std::cerr<<"usage: hp_table_bench local|mutex|hazard threads hot|uniform read|update\n"; return 2; }
    std::string mode=argv[1],distribution=argv[3],load=argv[4];
    int count=std::atoi(argv[2]);
    if ((mode!="local" && mode!="mutex" && mode!="hazard") || count<1 || count>64 ||
        (distribution!="hot" && distribution!="uniform") || (load!="read" && load!="update")) return 2;
    if (mode=="local" && load=="update") return 2;
    constexpr std::size_t iterations=100000,sample_every=100,update_count=20000;
    std::vector<Key> keys;
    for (int i=0;i<256;++i) keys.push_back({1,"host-"+std::to_string(i)+".example.test",1});
#ifdef DNS_HP_BOUNDED
    HazardTable hazard(count);
#else
    HazardTable hazard;
#endif
    LockedTable shared;
    std::vector<std::unordered_map<Key,Answer,KeyHash>> local(mode=="local" ? count : 0);
    for (auto const& key:keys) {
        if (mode=="local") for (auto& table:local) table.emplace(key,make_answer(key,1));
        else if (mode=="mutex") shared.put(key,make_answer(key,1));
        else if (!hazard.put(key,make_answer(key,1))) std::abort();
    }
    bool writer=load=="update";
    std::barrier gate(count+1+(writer ? 1 : 0));
    std::vector<std::thread> readers;
    std::vector<std::vector<long long>> samples(count);
    std::vector<std::uint64_t> checksums(count);
    std::vector<long long> write_samples;
    Clock::time_point writer_finished;
    for (int t=0;t<count;++t) readers.emplace_back([&,t] {
#ifdef DNS_HP_BOUNDED
        auto reader=hazard.reader(t);
#endif
        auto& timings=samples[t]; timings.reserve(iterations/sample_every);
        std::uint64_t rng=0x9e3779b97f4a7c15ULL+t,sum=0;
        gate.arrive_and_wait();
        for (std::size_t i=0;i<iterations;++i) {
            rng^=rng<<13; rng^=rng>>7; rng^=rng<<17;
            auto const& key=keys[distribution=="hot" ? 0 : rng%keys.size()];
            auto start=i%sample_every==0 ? Clock::now() : Clock::time_point{};
            std::optional<Answer> result;
            if (mode=="local") {
                auto it=local[t].find(key);
                if (it!=local[t].end()) result=it->second;
            } else if (mode=="mutex") result=shared.get(key);
            else {
#ifdef DNS_HP_BOUNDED
                result=reader.get(key);
#else
                result=hazard.get(key);
#endif
            }
            if (!result || result->canonical_name!=key.name || result->chain.size()!=1 ||
                result->address[0]!=static_cast<std::uint8_t>(result->revision)) std::abort();
            sum+=result->canonical_name.size();
            if (i%sample_every==0) timings.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now()-start).count());
        }
        checksums[t]=sum;
    });
    std::thread updater;
    if (writer) updater=std::thread([&] {
        write_samples.reserve(update_count);
        gate.arrive_and_wait();
        for (std::size_t i=0;i<update_count;++i) {
            auto const& key=keys[distribution=="hot" ? 0 : i%keys.size()];
            auto value=make_answer(key,i+2);
            auto start=Clock::now();
            if (mode=="mutex") shared.put(key,std::move(value));
            else if (!hazard.put(key,std::move(value))) std::abort();
            write_samples.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now()-start).count());
        }
        writer_finished=Clock::now();
    });
    auto start=Clock::now(); gate.arrive_and_wait();
    for (auto& thread:readers) thread.join();
    auto readers_finished=Clock::now();
    if (writer) updater.join();
    auto elapsed=std::chrono::duration<double>(readers_finished-start).count();
    std::vector<long long> combined;
    for (auto& s:samples) combined.insert(combined.end(),s.begin(),s.end());
    std::sort(combined.begin(),combined.end()); std::sort(write_samples.begin(),write_samples.end());
    auto q=[](auto const& data,double value) { return data.empty() ? 0LL : data[static_cast<std::size_t>(value*(data.size()-1))]; };
    std::uint64_t checksum=0; for (auto v:checksums) checksum+=v;
    std::cout<<mode<<','<<count<<','<<distribution<<','<<load<<','<<(count*iterations/elapsed)<<','
             <<q(combined,.5)<<','<<q(combined,.99)<<','<<q(combined,.999)<<','<<q(write_samples,.99)<<','<<q(write_samples,.999)<<','
             <<(writer ? std::chrono::duration<double>(writer_finished-start).count()/elapsed : 0.0)<<','
             <<(mode=="hazard" ? HazardTable::live_nodes() : 0)<<','<<(mode=="hazard" ? HazardTable::peak_nodes() : 0)<<','<<checksum<<'\n';
}
