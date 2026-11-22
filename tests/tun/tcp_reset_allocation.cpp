#include <cstdlib>
#include <new>
import std;
import tcp.engine;
namespace p = ::packet;
namespace t=tcp;
namespace { int remaining=-1; }
void* operator new(std::size_t n) {
    if (remaining>0 && --remaining==0) { remaining=-1; throw std::bad_alloc(); }
    if (auto* memory=std::malloc(n ? n : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory,std::size_t) noexcept { std::free(memory); }
template<class Table, class Engine, class View, class Parse>
auto scenario(View syn, Parse parse) -> int {
  for (int position=1;position<=4;++position) {
    p::MemoryLink link;
    auto table=Table::create(1,8);
    auto id=table->open(syn,50,0); if (!id) return 1;
    auto* flow=table->get(*id);
    auto ack=syn; ack.sequence=100; ack.acknowledgement=51; ack.flags=0x10; ack.window=8;
    if (!flow->input(ack,0)) return 2;
    Engine engine(link,*table);
    remaining=position; bool caught=false;
    std::optional<t::ReadResult> result;
    try { auto reset=engine.reset(*id,1); if (reset) result=std::move(*reset); } catch (std::bad_alloc const&) { caught=true; }
    remaining=-1;
    if (position==1) {
        if (!caught || flow->state()!=t::ConnectionState::established) return 3;
        auto reset=engine.reset(*id,1);
        if (!reset || !reset->notification.delivered) return 4;
        auto packet=link.receive_packet(p::Side::first);
        if (!packet || !*packet || !(**packet).generation) return 4;
        continue;
    }
    if (caught || !result || !result->notification.backpressured || result->notification.delivered ||
        flow->state()!=t::ConnectionState::reset || table->reclaim(*id,1)!=false) return 4;
    for (std::uint64_t now=2;now<5;++now) {
        remaining=1; auto retry=engine.step(now,0); remaining=-1;
        if (!retry || !retry->backpressured || retry->delivered || table->reclaim(*id,now)!=false) return 5;
    }
    auto retry=engine.step(5,0);
    if (!retry || !retry->delivered || table->reclaim(*id,5)!=true) return 6;
    auto packet=link.receive_packet(p::Side::first); if (!packet || !*packet || !(**packet).generation) return 7;
    auto view=parse((**packet).bytes);
    if (!view || view->flags!=0x14 || view->sequence!=51 || view->acknowledgement!=100) return 8;
    auto empty=link.receive(p::Side::first); if (!empty || *empty) return 9;
  }
    return 0;
}
int main() {
    p::Tcp4View v4{.source={10,0,0,1},.destination={10,0,0,2},.source_port=1234,.destination_port=80,.sequence=99,.flags=2};
    p::Tcp6View v6{.source={0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                   .destination={0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,2},
                   .source_port=1234,.destination_port=80,.sequence=99,.flags=2};
    auto a=scenario<t::ConnectionTable,t::MemoryEngine>(v4,[](auto const& bytes) { return p::parse_tcp4(bytes); });
    auto b=scenario<t::ConnectionTable6,t::MemoryEngine6>(v6,[](auto const& bytes) { return p::parse_tcp6(bytes); });
    if (a || b) return a ? a : b;
    std::println("IPv4 and IPv6 TCP resets survive repeated output allocation failures");
}
