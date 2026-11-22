#ifdef DNS_HP_BOUNDED
#include "bounded_table.hpp"
#else
#include "hp_table.hpp"
#endif
#include <barrier>
#include <cstdlib>
#include <iostream>
#include <thread>

using namespace dns_hp_experiment;
auto make_answer(Key const& key,std::uint64_t revision) -> Answer {
    Answer result{key.name,{key.name}, {},10000,revision};
    result.address[0]=static_cast<std::uint8_t>(revision);
    return result;
}
int main() {
#ifdef DNS_HP_BOUNDED
    HazardTable table(9);
    auto main_reader=table.reader(8);
    auto get=[&](Key const& key) { return main_reader.get(key); };
#else
    HazardTable table;
    auto get=[&](Key const& key) { return table.get(key); };
#endif
    std::vector<Key> keys;
    for (int i=0;i<256;++i) keys.push_back({1,"host-"+std::to_string(i)+".test",1});
    for (auto const& key:keys) if (!table.put(key,make_answer(key,1))) return 1;
    Key extra{2,"host-0.test",1};
    if (table.put(extra,make_answer(extra,1)) || get(extra)) return 2;
    if (!table.erase(keys[0]) || get(keys[0]) || !table.put(extra,make_answer(extra,1))) return 3;
    if (!get(extra) || !table.erase(extra) || !table.put(keys[0],make_answer(keys[0],1))) return 4;
    for (auto const& key:keys) if (!get(key)) return 5;
    std::atomic<bool> failed=false;
    std::barrier gate(9);
    std::vector<std::thread> threads;
    for (unsigned t=0;t<8;++t) threads.emplace_back([&,t] {
#ifdef DNS_HP_BOUNDED
        auto reader=table.reader(t);
#endif
        std::uint64_t rng=12345+t;
        gate.arrive_and_wait();
        for (int i=0;i<100000;++i) {
            rng^=rng<<13; rng^=rng>>7; rng^=rng<<17;
            auto const& key=keys[rng%keys.size()];
#ifdef DNS_HP_BOUNDED
            auto value=reader.get(key);
#else
            auto value=table.get(key);
#endif
            // Deletions are concurrent, so a miss is allowed; partial values are not.
            if (value && (value->canonical_name!=key.name || value->chain.size()!=1 ||
                value->chain[0]!=key.name || value->address[0]!=static_cast<std::uint8_t>(value->revision))) failed=true;
        }
    });
    gate.arrive_and_wait();
    for (int i=0;i<20000;++i) {
        auto const& key=keys[i%keys.size()];
        if (i%4==0 && !table.erase(key)) return 6;
        if (!table.put(key,make_answer(key,i+2))) return 7;
    }
    for (auto& thread:threads) thread.join();
    if (failed) return 8;
    for (auto const& key:keys) if (!get(key)) return 9;
#ifdef DNS_HP_BOUNDED
    std::atomic<bool> paused=false,release=false;
    std::thread slow([&] {
        auto reader=table.reader(0);
        if (!reader.visit(keys[0],[&](Answer const& old) {
            paused=true;
            while (!release.load()) std::this_thread::yield();
            if (old.canonical_name!=keys[0].name) failed=true;
        })) failed=true;
    });
    while (!paused.load()) std::this_thread::yield();
    for (int i=0;i<10000;++i) if (!table.put(keys[0],make_answer(keys[0],i+1))) std::abort();
    if (HazardTable::live_nodes()!=257) failed=true;
    release=true; slow.join();
    if (!table.put(keys[0],make_answer(keys[0],1)) || HazardTable::live_nodes()!=256 || failed) return 10;

    // Each reader pins a different historical version of the same key.
    std::array<std::atomic<bool>,8> pinned{};
    std::atomic<bool> unpin=false;
    threads.clear();
    for (unsigned t=0;t<8;++t) {
        threads.emplace_back([&,t] {
            auto reader=table.reader(t);
            if (!reader.visit(keys[0],[&](Answer const& value) {
                auto revision=value.revision;
                pinned[t]=true;
                while (!unpin.load()) std::this_thread::yield();
                if (value.revision!=revision || value.canonical_name!=keys[0].name) failed=true;
            })) failed=true;
        });
        while (!pinned[t].load()) std::this_thread::yield();
        if (!table.put(keys[0],make_answer(keys[0],t+2))) std::abort();
    }
    if (HazardTable::live_nodes()!=264) failed=true;
    unpin=true;
    for (auto& thread:threads) thread.join();
    if (!table.put(keys[0],make_answer(keys[0],1)) || HazardTable::live_nodes()!=256 || failed) return 11;

    // Repeatedly replace distinct keys while a disjoint set stays live. These
    // lookups must never miss, even when vacated slots are reused.
    std::atomic<bool> finished=false;
    std::barrier churn_gate(9);
    threads.clear();
    for (unsigned t=0;t<8;++t) threads.emplace_back([&,t] {
        auto reader=table.reader(t);
        std::uint64_t rng=34567+t;
        churn_gate.arrive_and_wait();
        while (!finished.load()) {
            rng^=rng<<13; rng^=rng>>7; rng^=rng<<17;
            auto const& key=keys[rng%128];
            auto value=reader.get(key);
            if (!value || value->canonical_name!=key.name || value->address[0]!=static_cast<std::uint8_t>(value->revision)) failed=true;
        }
    });
    churn_gate.arrive_and_wait();
    for (int i=0;i<10000;++i) {
        auto index=128+i%128;
        if (!table.erase(keys[index])) std::abort();
        keys[index]={1,"churn-"+std::to_string(i)+".test",1};
        if (!table.put(keys[index],make_answer(keys[index],i+1))) std::abort();
    }
    finished=true;
    for (auto& thread:threads) thread.join();
    for (auto const& key:keys) if (!get(key)) failed=true;
    if (get({1,"absent.test",1}) || failed) return 12;
#endif
    std::cout<<"concurrent replacement, delete, capacity and view isolation passed; live="
             <<HazardTable::live_nodes()<<", peak="<<HazardTable::peak_nodes()<<'\n';
}
