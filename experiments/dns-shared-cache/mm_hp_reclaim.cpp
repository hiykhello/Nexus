// Probe the pinned mm_hp implementation; this is not a DNS cache.
#include "mm_hp.hpp"
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <thread>

struct Node : std::hazard_pointer_obj_base<Node> {
    std::atomic<unsigned>* destroyed;
    explicit Node(std::atomic<unsigned>* counter) : destroyed(counter) {}
    ~Node() { if (destroyed) destroyed->fetch_add(1,std::memory_order_relaxed); }
};
int main() {
    std::atomic<unsigned> destroyed=0;
    std::atomic<Node*> current=new Node(&destroyed);
    {
        auto guard=std::make_hazard_pointer();
        auto* held=guard.protect(current);
        if (!held || held->destroyed!=&destroyed) std::abort();
        std::thread writer([&] {
            current.exchange(nullptr,std::memory_order_acq_rel)->retire();
            for (int i=0;i<2000;++i) (new Node(nullptr))->retire();
        });
        writer.join();
        if (destroyed.load(std::memory_order_relaxed)!=0 || held->destroyed!=&destroyed) std::abort();
    }
    auto after_release=destroyed.load(std::memory_order_relaxed);
    for (int i=0;i<2000;++i) (new Node(nullptr))->retire();
    if (destroyed.load(std::memory_order_relaxed)!=1) std::abort();
    std::cout<<"protected until release; destroyed immediately after release="<<after_release
             <<"; reclaimed after later retire scans=1\n";
}
