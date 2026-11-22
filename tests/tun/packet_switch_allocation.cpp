#include <cstdlib>
#include <new>
import std;
import packet.mux;
namespace p = ::packet;
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
        p::MemoryLink external,tcp,udp;
        p::MemorySwitch sw(external,tcp,udp);
        p::Bytes inbound(40),outbound{1,2,3}; inbound[0]=0x45; inbound[9]=6;
        if (!external.send(p::Side::first,inbound) || !udp.send(p::Side::second,outbound)) return 1;
        remaining=position; auto first=sw.step(); remaining=-1;
        if (!first) return 2;
        if (position==1 && (!first->input_backpressured || !first->output_delivered)) return 3;
        if (position==2 && (!first->input_delivered || !first->output_backpressured)) return 4;
        for (int i=0;i<3;++i) {
            remaining=1; auto retry=sw.step(); remaining=-1;
            if (!retry || (position==1 ? !retry->input_backpressured : !retry->output_backpressured)) return 5;
        }
        auto retry=sw.step();
        if (!retry || (position==1 ? !retry->input_delivered : !retry->output_delivered)) return 6;
        auto got_input=tcp.receive(p::Side::second), got_output=external.receive(p::Side::first);
        if (!got_input || !*got_input || **got_input!=inbound || !got_output || !*got_output || **got_output!=outbound) return 7;
        auto empty_input=tcp.receive(p::Side::second), empty_output=external.receive(p::Side::first);
        if (!empty_input || *empty_input || !empty_output || *empty_output) return 8;
    }
    std::println("packet switch retains both directions through repeated allocation failures");
}
