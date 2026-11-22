#include <cstdlib>
#include <new>
import std;
import tcp.table;

namespace p = ::packet;
namespace t=tcp;
bool fail_allocation=false;
void* operator new(std::size_t size) {
    if (fail_allocation) throw std::bad_alloc{};
    if (auto* result=std::malloc(size ? size : 1)) return result;
    throw std::bad_alloc{};
}
void operator delete(void* ptr) noexcept { std::free(ptr); }
void operator delete(void* ptr,std::size_t) noexcept { std::free(ptr); }

template<class Table, class View>
auto check(View syn) -> bool {
    auto table=Table::create(2,8); if (!table) return false;
    auto old=table->watch(syn);
    fail_allocation=true;
    try {
        auto same=table->watch(syn);
        if (same!=old) { fail_allocation=false; return false; }
        auto other=syn; ++other.source_port;
        bool failed=false;
        try { (void)table->watch(other); } catch (std::bad_alloc const&) { failed=true; }
        if (!failed || !old->valid) { fail_allocation=false; return false; }
    } catch (...) { fail_allocation=false; return false; }
    fail_allocation=false;
    auto opened=table->open(syn,50,0);
    if (!opened || old->valid || !table->abort(*opened)) return false;
    fail_allocation=true; bool failed=false;
    try { (void)table->watch(syn); } catch (std::bad_alloc const&) { failed=true; }
    fail_allocation=false;
    if (!failed || old->valid) return false;
    auto fresh=table->watch(syn);
    return fresh!=old && fresh->valid && table->watched_generations()==1;
}
int main() {
    p::Tcp4View v4{.source={10,0,0,1},.destination={10,0,0,2},.source_port=1234,.destination_port=80,.flags=2};
    p::Tcp6View v6{.source={0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                   .destination={0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,2},.source_port=1234,.destination_port=80,.flags=2};
    if (!check<t::ConnectionTable>(v4) || !check<t::ConnectionTable6>(v6)) return 1;
    std::println("TCP generation sharing and allocation recovery passed");
}
