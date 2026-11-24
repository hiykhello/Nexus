import std;
import crypto.ecdh;
namespace native {
    struct alignas(std::max_align_t) Header { std::size_t size; };
    bool enabled=false,denied=false;
    std::ptrdiff_t allowance=-1;
    std::size_t calls=0,live=0,bytes=0;
}
// Fixed BoringSSL mem.cc's native allocator hook, not a C++ allocation shim.
extern "C" auto OPENSSL_memory_alloc(std::size_t size) noexcept -> void* {
    if (native::enabled) { ++native::calls; if (!native::allowance) {native::denied=true;return nullptr;} if(native::allowance>0)--native::allowance; }
    if(size>std::numeric_limits<std::size_t>::max()-sizeof(native::Header))return nullptr;
    auto* block=static_cast<native::Header*>(std::malloc(sizeof(native::Header)+size));if(!block)return nullptr;
    block->size=size;++native::live;native::bytes+=size;return block+1;
}
extern "C" auto OPENSSL_memory_free(void* pointer) noexcept -> void {
    if(!pointer)return;
    auto* block=static_cast<native::Header*>(pointer)-1;auto size=block->size;
    native::bytes-=size;--native::live;
    auto* byte=reinterpret_cast<volatile unsigned char*>(block);
    for(std::size_t i=0;i<sizeof(native::Header)+size;++i)byte[i]=0;
    std::free(block);
}
extern "C" auto OPENSSL_memory_get_size(void* pointer) noexcept -> std::size_t {
    return (static_cast<native::Header*>(pointer)-1)->size;
}
namespace c = ::crypto;
auto attempt(std::uint16_t group) -> bool {
    auto a=c::EcPrivate::generate(group),b=c::EcPrivate::generate(group);if(!a||!b)return false;
    auto ap=a->public_key(),bp=b->public_key();if(!ap||!bp)return false;
    auto ab=a->agree(bp->view()),ba=b->agree(ap->view());
    return ab&&ba&&c::constant_time_equal(ab->view(),ba->view());
}
int main() {
    std::size_t failures=0;
    for(auto group:{23,24,25}) {
        if(!attempt(group))return 1;
        auto before=native::live,bytes=native::bytes;
        native::calls=0;native::allowance=-1;native::enabled=true;
        if(!attempt(group))return 2;
        native::enabled=false;auto count=native::calls;
        if(!count||native::live!=before||native::bytes!=bytes)return 3;
        for(std::size_t failure=0;failure<=count;++failure) {
            native::calls=0;native::denied=false;native::allowance=failure;native::enabled=true;
            bool complete=attempt(group);native::enabled=false;
            boringssl::ERR_clear_error();
            if(native::live!=before||native::bytes!=bytes||(failure<count&&(!native::denied||complete))||(failure==count&&(!complete||native::denied)))return 4;
            if(!attempt(group)||native::live!=before||native::bytes!=bytes)return 5;
            if(failure<count)++failures;
        }
        std::println("NIST group={} native allocation failures={} owner cleanup/livebytes and recovery passed",group,count);
    }
    std::println("BoringSSL native failures={} passed",failures);
}
