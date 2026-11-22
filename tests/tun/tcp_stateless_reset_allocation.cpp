import std;
import tcp.dispatch;
namespace p = ::packet; namespace t=tcp;
std::size_t fail_size=0;
void* operator new(std::size_t size) {
    if (fail_size && size==fail_size) throw std::bad_alloc{};
    if (auto ptr=std::malloc(size ? size : 1)) return ptr;
    throw std::bad_alloc{};
}
void operator delete(void* ptr) noexcept { std::free(ptr); }
void operator delete(void* ptr,std::size_t) noexcept { std::free(ptr); }

template<class Table, class View, class Make>
auto scenario(View segment, Make make, std::size_t size) -> bool {
    auto table=Table::create(1,8,{1,10}); if (!table) return false;
    auto wire=make(segment); if (!wire) return false;
    fail_size=size; bool threw=false;
    try { (void)t::dispatch(*table,*wire,0,100); } catch (std::bad_alloc const&) { threw=true; }
    fail_size=0;
    if (!threw || !table->stateless_reset_available(100)) return false;
    auto sent=t::dispatch(*table,*wire,0,100);
    if (!sent || !sent->reply || table->stateless_reset_available(100)) return false;
    fail_size=size;
    try {
        auto suppressed=t::dispatch(*table,*wire,0,100);
        fail_size=0;
        if (!suppressed || suppressed->reply || !suppressed->reset_suppressed) return false;
    } catch (...) { fail_size=0; return false; }
    auto renewed=t::dispatch(*table,*wire,0,110);
    if (!renewed || !renewed->reply || renewed->reset_suppressed || table->stateless_reset_available(109)) return false;
    auto disabled=Table::create(1,8,{0,10}); if (!disabled) return false;
    fail_size=size;
    try {
        auto suppressed=t::dispatch(*disabled,*wire,0,0);
        fail_size=0;
        return suppressed && !suppressed->reply && suppressed->reset_suppressed;
    } catch (...) { fail_size=0; return false; }
}
int main() {
    p::Tcp4View v4{.source={10,0,0,1},.destination={10,0,0,2},.source_port=1234,.destination_port=80,.flags=0x10};
    p::Tcp6View v6{.source={0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1},
                   .destination={0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,2},
                   .source_port=1234,.destination_port=80,.flags=0x10};
    if (!scenario<t::ConnectionTable>(v4,[](auto v) { return p::make_tcp4(v); },40) ||
        !scenario<t::ConnectionTable6>(v6,[](auto v) { return p::make_tcp6(v); },60)) return 1;
    std::println("stateless reset limits avoid allocation and preserve quota on failure");
}
