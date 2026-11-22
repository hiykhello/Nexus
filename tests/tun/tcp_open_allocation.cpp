#include <cstdlib>
#include <new>
import std;
import tcp.stack;
namespace p = ::packet;
namespace t=tcp;
namespace r = ::rules;
namespace { int remaining=-1; }
void* operator new(std::size_t n) {
    if (remaining>0 && --remaining==0) { remaining=-1; throw std::bad_alloc(); }
    if (auto* memory=std::malloc(n ? n : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory,std::size_t) noexcept { std::free(memory); }
int main() {
    p::Tcp4View syn{.source={10,0,0,1},.destination={127,0,0,1},.source_port=1234,
                    .destination_port=4321,.sequence=99,.flags=2,.window=64};
    auto bytes=p::make_tcp4(syn); if (!bytes) return 1;
    int dispatch_faults=0, stack_faults=0, dispatch_success=0, stack_success=0;
    for (int position=1;position<=40;++position) {
        auto table=t::ConnectionTable::create(1,64);
        remaining=position;
        try {
            auto result=t::dispatch(*table,*bytes,50,0);
            remaining=-1;
            if (!result || !result->opened || table->size()!=1) return 2;
            ++dispatch_success;
        } catch (std::bad_alloc const&) {
            remaining=-1; ++dispatch_faults;
            if (table->size()) return 3;
        }
    }
    for (int position=1;position<=40;++position) {
        p::MemoryLink link;
        auto table=t::ConnectionTable::create(1,64);
        if (!link.send(p::Side::first,*bytes)) return 4;
        {
            t::MemoryDirect4 stack(link,*table,r::Matcher{},1);
            remaining=position;
            try {
                auto result=stack.step(0,50);
                remaining=-1;
                if (!result || !result->input.opened || table->size()!=1) return 5;
                ++stack_success;
            } catch (std::bad_alloc const&) { remaining=-1; ++stack_faults; }
        }
        if (table->size()) return 6;
    }
    if (!dispatch_faults || !stack_faults || !dispatch_success || !stack_success) return 7;
    std::println("TCP open allocation faults: dispatch {}, stack {}; no orphaned flows",dispatch_faults,stack_faults);
}
