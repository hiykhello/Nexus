#include <cstdlib>
#include <new>
import std;
import nexus.tcp.send;
namespace t=nexus::tcp;
namespace { int remaining=-1; std::size_t allocations=0; bool counting=false; }
void* operator new(std::size_t n) {
    if (counting) ++allocations;
    if (remaining>0 && --remaining==0) { remaining=-1; throw std::bad_alloc(); }
    if (auto* p=std::malloc(n ? n : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
int main() {
    std::array<std::uint8_t,8000> initial{};
    std::array<std::uint8_t,12000> extra{};
    for (std::size_t i=0;i<initial.size();++i) initial[i]=static_cast<std::uint8_t>(i);
    for (std::size_t i=0;i<extra.size();++i) extra[i]=static_cast<std::uint8_t>(i+17);
    bool reached_success=false; int failures=0;
    for (int position=1;position<100;++position) {
        auto buffer=t::SendBuffer::create(0xfffffff0u,20000);
        if (!buffer || !buffer->enqueue(initial) || !buffer->mark_sent(3000)) return 1;
        remaining=position; bool failed=false;
        try { if (!buffer->enqueue(extra)) return 2; }
        catch (std::bad_alloc const&) { failed=true; }
        remaining=-1;
        if (failed) {
            ++failures;
            auto sent=buffer->retransmit(initial.size()), unsent=buffer->unsent(initial.size());
            if (buffer->queued()!=initial.size() || buffer->in_flight()!=3000 || sent.sequence!=0xfffffff0u ||
                !std::ranges::equal(sent.bytes,std::span{initial}.first(3000)) ||
                !std::ranges::equal(unsent.bytes,std::span{initial}.subspan(3000)) || !buffer->enqueue(extra)) return 3;
        } else reached_success=true;
        auto all=buffer->unsent(20000);
        if (buffer->queued()!=20000 || all.bytes.size()!=17000 ||
            !std::ranges::equal(std::span{all.bytes}.first(5000),std::span{initial}.subspan(3000)) ||
            !std::ranges::equal(std::span{all.bytes}.subspan(5000),extra)) return 4;
        if (!failed) break;
    }
    if (!reached_success || !failures) return 5;
    auto buffer=t::SendBuffer::create(0,20000);
    if (!buffer || !buffer->enqueue(initial)) return 6;
    std::array<std::uint8_t,1> byte{1}; allocations=0; counting=true;
    auto appended=buffer->enqueue(byte); counting=false;
    if (!appended) return 7;
    auto direct_allocations=allocations;
    std::deque<std::uint8_t> previous(initial.begin(),initial.end());
    allocations=0; counting=true;
    auto staged=previous; staged.insert(staged.end(),byte.begin(),byte.end()); previous.swap(staged);
    counting=false;
    std::println("TCP send append preserves data on {} allocation failures; small append allocations: direct {}, staged {}",
                 failures,direct_allocations,allocations);
}
