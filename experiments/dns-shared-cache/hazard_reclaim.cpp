// Exercise the pinned Xenium revision; not a production cache implementation.
#include <xenium/harris_michael_hash_map.hpp>
#include <xenium/reclamation/hazard_pointer.hpp>
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <thread>

struct Value {
    std::atomic<unsigned>* destroyed;
    explicit Value(std::atomic<unsigned>* counter) : destroyed(counter) {}
    Value(Value const&)=delete;
    Value& operator=(Value const&)=delete;
    ~Value() { if (destroyed) destroyed->fetch_add(1,std::memory_order_relaxed); }
};
using Map=xenium::harris_michael_hash_map<int,Value,
    xenium::policy::reclaimer<xenium::reclamation::hazard_pointer<>>>;

int main() {
    std::atomic<unsigned> destroyed=0;
    bool slots_exhausted=false;
    Map map;
    if (!map.get_or_emplace(1,&destroyed).second) std::abort();
    {
        auto reader=map.find(1);
        if (reader==map.end() || reader->second.destroyed!=&destroyed) std::abort();
        std::thread writer([&] {
            if (!map.erase(1)) std::abort();
            for (int i=2;i<1002;++i) {
                if (!map.get_or_emplace(i,nullptr).second) std::abort();
                if (!map.erase(i)) std::abort();
            }
        });
        writer.join(); // Writer exits while the original reader still protects the node.
        if (destroyed.load(std::memory_order_relaxed)!=0 || reader->second.destroyed!=&destroyed) std::abort();
    }
    // Releasing a guard alone need not scan an abandoned retire list.
    auto after_release=destroyed.load(std::memory_order_relaxed);
    for (int i=1002;i<2002;++i) {
        if (!map.get_or_emplace(i,nullptr).second) std::abort();
        if (!map.erase(i)) std::abort();
    }
    if (destroyed.load(std::memory_order_relaxed)!=1) std::abort();
    try { (void)(map.get_or_emplace(3000,nullptr).second && map.erase(3000)); }
    catch (xenium::reclamation::bad_hazard_pointer_alloc const&) { slots_exhausted=true; }
    if (!slots_exhausted || !map.erase(3000) || map.contains(1)) std::abort();
    std::cout<<"temporary insert iterator plus erase exhausted default slots; protected until release; destroyed immediately after release="<<after_release
             <<"; reclaimed after later retire scans=1\n";
}
