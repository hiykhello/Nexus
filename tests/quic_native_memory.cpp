import std;
import quic.native_memory;
struct Heap {
    static inline bool fail=false;static inline std::size_t blocks=0;
    static auto allocate(std::size_t bytes) noexcept -> void* {if(fail)return nullptr;auto* p=std::malloc(bytes);if(p)++blocks;return p;}
    static auto release(void* p) noexcept -> void {--blocks;std::free(p);}
};
auto main()->int {
    using Memory=quic::NativeMemory<Heap>;Memory memory(4096);auto transport=memory.transport();auto h3=memory.http3();
    auto* first=transport.malloc(64,transport.user_data);if(!first || reinterpret_cast<std::uintptr_t>(first)%alignof(std::max_align_t))return 1;
    auto old=memory.used();std::memset(first,0x5a,64);
    if(h3.malloc(4096,h3.user_data) || memory.used()!=old)return 2;
    if(h3.calloc(std::numeric_limits<std::size_t>::max(),2,h3.user_data) || transport.malloc(std::numeric_limits<std::size_t>::max(),transport.user_data))return 3;
    Heap::fail=true;if(transport.realloc(first,128,transport.user_data) || memory.used()!=old || *static_cast<unsigned char*>(first)!=0x5a)return 4;Heap::fail=false;
    auto* second=h3.realloc(first,128,h3.user_data);if(!second || memory.used()<=old || Heap::blocks!=1)return 5;
    for(std::size_t i=0;i<64;++i)if(static_cast<unsigned char*>(second)[i]!=0x5a)return 6;
    if(transport.realloc(second,0,transport.user_data) || memory.used() || Heap::blocks)return 7;
    auto* zero=h3.calloc(16,8,h3.user_data);if(!zero)return 8;
    for(std::size_t i=0;i<128;++i)if(static_cast<unsigned char*>(zero)[i])return 9;
    h3.free(zero,h3.user_data);transport.free(nullptr,transport.user_data);
    auto* empty=transport.malloc(0,transport.user_data);if(!empty || !memory.used())return 10;transport.free(empty,transport.user_data);
    if(memory.used() || Heap::blocks)return 11;
    std::println("Production shared native memory={} alignment/overflow/calloc/realloc-denial-preserve/overlap-budget/empty/null-free/pass, outstanding0",sizeof(Memory));
}
