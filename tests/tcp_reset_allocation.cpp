#include <cstdlib>
#include <new>
import std;
import nexus.tcp.engine;
namespace p=nexus::packet;
namespace t=nexus::tcp;
namespace { int remaining=-1; }
void* operator new(std::size_t n) {
    if (remaining>0 && --remaining==0) { remaining=-1; throw std::bad_alloc(); }
    if (auto* memory=std::malloc(n ? n : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete(void* memory,std::size_t) noexcept { std::free(memory); }
int main() {
    p::MemoryLink link;
    auto table=t::ConnectionTable::create(1,8);
    p::Tcp4View syn{.source={10,0,0,1},.destination={10,0,0,2},.source_port=1234,
                    .destination_port=80,.sequence=99,.flags=2};
    auto id=table->open(syn,50,0); if (!id) return 1;
    auto* flow=table->get(*id);
    p::Tcp4View ack{.source=syn.source,.destination=syn.destination,.source_port=syn.source_port,
                    .destination_port=syn.destination_port,.sequence=100,.acknowledgement=51,
                    .flags=0x10,.window=8};
    if (!flow->input(ack,0)) return 2;
    t::MemoryEngine engine(link,*table);
    remaining=1; bool caught=false;
    try { (void)engine.reset(*id,1); } catch (std::bad_alloc const&) { caught=true; }
    remaining=-1;
    if (!caught || flow->state()!=t::ConnectionState::established) return 3;
    remaining=2;
    auto reset=engine.reset(*id,1); remaining=-1;
    if (!reset || !reset->notification.backpressured || reset->notification.delivered ||
        flow->state()!=t::ConnectionState::reset || table->reclaim(*id,1)!=false) return 4;
    for (std::uint64_t now=2;now<5;++now) {
        remaining=1; auto retry=engine.step(now,0); remaining=-1;
        if (!retry || !retry->backpressured || retry->delivered || table->reclaim(*id,now)!=false) return 5;
    }
    auto retry=engine.step(5,0);
    if (!retry || !retry->delivered || table->reclaim(*id,5)!=true) return 6;
    auto packet=link.receive(p::Side::first); if (!packet || !*packet) return 7;
    auto view=p::parse_tcp4(**packet);
    if (!view || view->flags!=0x14 || view->sequence!=51 || view->acknowledgement!=100) return 8;
    auto empty=link.receive(p::Side::first); if (!empty || *empty) return 9;
    std::println("TCP reset survives repeated output allocation failures");
}
