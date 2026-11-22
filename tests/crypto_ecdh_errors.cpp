import std;
import crypto.ecdh;
namespace native {
    struct alignas(std::max_align_t) Header { std::size_t size; };
    bool enabled=false,denied=false,single=false;
    std::ptrdiff_t allowance=-1;
    std::size_t calls=0,live=0,bytes=0;
}
// Fixed BoringSSL mem.cc's native allocator hook, not a C++ allocation shim.
extern "C" auto OPENSSL_memory_alloc(std::size_t size) noexcept -> void* {
    if (native::enabled) { ++native::calls; if (!native::allowance) {native::denied=true;if(native::single)native::allowance=-1;return nullptr;} if(native::allowance>0)--native::allowance; }
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
int main() {
    std::size_t failures=0;
    for(auto group:{23,24,25}) {
        auto a=c::EcPrivate::generate(group),b=c::EcPrivate::generate(group);if(!a||!b)return 1;
        auto ap=a->public_key(),bp=b->public_key();if(!ap||!bp)return 2;
        auto before=native::live,bytes=native::bytes;
        native::calls=0;native::allowance=-1;native::enabled=true;
        { auto secret=a->agree(bp->view());if(!secret)return 3; }
        native::enabled=false;auto count=native::calls;
        if(!count||native::live!=before||native::bytes!=bytes)return 4;
        for(bool single:{false,true})for(std::size_t failure=0;failure<=count;++failure) {
            native::calls=0;native::denied=false;native::allowance=failure;native::single=single;native::enabled=true;
            { auto secret=a->agree(bp->view());native::enabled=false;
              if(native::denied) {++failures;if(!secret&&secret.error()!=c::Error::backend_failure){std::println("group={} single={} point={}/{} error={}",group,single,failure,count,int(secret.error()));return 5;}}
              else if(!secret)return 6;
            }
            if(native::live!=before||native::bytes!=bytes)return 7;
            { auto recovered=a->agree(bp->view());if(!recovered)return 8; }
            if(native::live!=before||native::bytes!=bytes)return 9;
        }
        // Correct width and uncompressed tag but off-curve input stays peer error.
        auto invalid=*bp;std::fill(invalid.bytes.begin()+1,invalid.bytes.end(),0);
        auto bad=a->agree(invalid.view());if(bad||bad.error()!=c::Error::invalid_peer)return 10;
        auto short_peer=a->agree(bp->view().subspan(1));if(short_peer||short_peer.error()!=c::Error::invalid_peer)return 11;
        std::println("NIST group={} agree native count={} single+persistent local errors and malformed peer negatives passed",group,count);
    }
    std::println("NIST agree native injected={} passed",failures);
}
