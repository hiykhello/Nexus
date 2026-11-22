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
int main() {
    for (int position=1;position<=2;++position) {
        p::MemoryLink link;
        auto table=t::ConnectionTable::create(1,2);
        p::Tcp4View syn{.source={10,0,0,1},.destination={10,0,0,2},.source_port=1234,
                        .destination_port=80,.sequence=99,.flags=2};
        auto id=table->open(syn,50,0); if (!id) return 1;
        auto* flow=table->get(*id);
        std::array<std::uint8_t,2> data{'a','b'}, output{};
        p::Tcp4View ack{.source=syn.source,.destination=syn.destination,.source_port=syn.source_port,
                        .destination_port=syn.destination_port,.sequence=100,.acknowledgement=51,
                        .flags=0x18,.window=8,.payload=data};
        if (!flow->input(ack,0) || flow->ack().window) return 2;
        t::MemoryEngine engine(link,*table);
        remaining=position;
        if (position==1) {
            bool caught=false;
            try { (void)engine.read(*id,output,1); } catch (std::bad_alloc const&) { caught=true; }
            remaining=-1;
            if (!caught || flow->ack().window || output!=std::array<std::uint8_t,2>{}) return 3;
            auto retry=engine.read(*id,output,1);
            if (!retry || retry->bytes!=2 || !retry->notification.delivered) return 4;
        } else {
            auto read=engine.read(*id,output,1); remaining=-1;
            if (!read || read->bytes!=2 || !read->notification.backpressured || read->notification.delivered) return 5;
            auto retry=engine.step(2,0);
            if (!retry || !retry->delivered) return 6;
        }
        if (output!=data) return 7;
        auto packet=link.receive(p::Side::first);
        if (!packet || !*packet) return 8;
        auto view=p::parse_tcp4(**packet);
        if (!view || view->window!=2 || view->acknowledgement!=102) return 9;
        auto empty=link.receive(p::Side::first); if (!empty || *empty) return 10;
    }
    std::println("TCP reads retain data and window updates across allocation faults");
}
