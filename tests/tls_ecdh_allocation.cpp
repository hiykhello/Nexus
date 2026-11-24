import std;
import tls.fingerprint;
import tls.client_hello_exchange;
import tls.server_keys;

namespace allocation {
    struct Header { void* base; };
    bool enabled=false,denied=false;
    std::ptrdiff_t allowance=-1;
    std::size_t live=0,calls=0;
    auto get(std::size_t size,std::size_t alignment=alignof(std::max_align_t)) -> void* {
        if (enabled) {
            ++calls;
            if (!allowance) {denied=true;throw std::bad_alloc();}
            if (allowance>0) --allowance;
        }
        alignment=std::max(alignment,alignof(Header));size=std::max<std::size_t>(size,1);
        if (size>std::numeric_limits<std::size_t>::max()-2*alignment) throw std::bad_alloc();
        auto* base=static_cast<std::byte*>(std::aligned_alloc(alignment,(size+2*alignment-1)/alignment*alignment));
        if (!base) throw std::bad_alloc();
        auto* pointer=base+alignment;
        std::construct_at(reinterpret_cast<Header*>(pointer)-1,Header{base});
        ++live;return pointer;
    }
    auto release(void* pointer) noexcept -> void {
        if (!pointer) return;
        auto* header=static_cast<Header*>(pointer)-1;auto* base=header->base;
        --live;std::free(base);
    }
}
auto operator new(std::size_t n) -> void* {return allocation::get(n);}
auto operator new[](std::size_t n) -> void* {return allocation::get(n);}
auto operator new(std::size_t n,std::align_val_t a) -> void* {return allocation::get(n,static_cast<std::size_t>(a));}
auto operator new[](std::size_t n,std::align_val_t a) -> void* {return allocation::get(n,static_cast<std::size_t>(a));}
auto operator delete(void* p) noexcept -> void {allocation::release(p);}
auto operator delete[](void* p) noexcept -> void {allocation::release(p);}
auto operator delete(void* p,std::size_t) noexcept -> void {allocation::release(p);}
auto operator delete[](void* p,std::size_t) noexcept -> void {allocation::release(p);}
auto operator delete(void* p,std::align_val_t) noexcept -> void {allocation::release(p);}
auto operator delete[](void* p,std::align_val_t) noexcept -> void {allocation::release(p);}
auto operator delete(void* p,std::size_t,std::align_val_t) noexcept -> void {allocation::release(p);}
auto operator delete[](void* p,std::size_t,std::align_val_t) noexcept -> void {allocation::release(p);}

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

namespace t=tls;
using Bytes=std::vector<std::uint8_t>;
auto attempt(t::Fingerprint profile,bool retry,t::HandshakeTransport transport,std::uint16_t group) -> bool {
    t::FingerprintConfig config;config.profile=profile;config.pad_to=1600;
    config.group_count=1;config.group_order[0]=group;config.key_share_count=retry ? 0 : 1;config.key_share_groups[0]=group;
    if (transport==t::HandshakeTransport::quic) config.cipher_count=2;
    std::array<std::string_view,1> alpn{"h3"};std::array<std::uint8_t,2> parameters{15,0};
    auto draft=t::make_fingerprint_hello("localhost",alpn,config,transport,transport==t::HandshakeTransport::quic ? std::optional<std::span<std::uint8_t const>>(parameters) : std::nullopt);
    if (!draft) return false;
    auto exchange=t::ClientHelloExchange::create(std::move(draft->hello),draft->initial_groups(),transport);if (!exchange) return false;
    Bytes first(exchange->initial().begin(),exchange->initial().end());if(!exchange->initial_sent())return false;
    std::array<std::uint16_t,1> schemes{0x0807},ciphers{0x1302};
    auto server=t::server_handshake_secrets(first,schemes,t::PeerSignaturePolicy::require_offered,ciphers,transport);
    if (retry) {
        auto retry=t::server_retry_hello(first,schemes,ciphers,transport);if(!retry)return false;
        auto received=exchange->receive(*retry);if(!received||received->outbound.empty())return false;
        Bytes second(received->outbound.begin(),received->outbound.end());if(!exchange->retry_sent())return false;
        server=t::server_handshake_secrets_retry(first,*retry,second,schemes,ciphers,transport);
    }
    if(!server||!exchange->receive(server->server_hello))return false;
    auto flight=exchange->take_flight();if(!flight)return false;
    auto keys=flight->handshake_secrets();
    return keys&&std::ranges::equal(keys->client,server->secrets.client_traffic.view())&&std::ranges::equal(keys->server,server->secrets.server_traffic.view());
}
int main() {
    std::size_t failures[2]{};
    for(auto transport:{t::HandshakeTransport::tcp,t::HandshakeTransport::quic})
     for(auto profile:{t::Fingerprint::tls13_grease,t::Fingerprint::tls13_randomized})
      for(bool retry:{false,true}) for(auto group:{23,24,25}) {
        if(!attempt(profile,retry,transport,group))return 1;
        for(unsigned kind:{0u,1u}) {
            auto before=allocation::live,native_before=native::live,native_bytes=native::bytes;
            allocation::allowance=-1;allocation::calls=0;allocation::enabled=kind==0;
            native::allowance=-1;native::calls=0;native::enabled=kind==1;
            if(!attempt(profile,retry,transport,group))return 2;
            allocation::enabled=false;native::enabled=false;
            auto count=kind==0 ? allocation::calls : native::calls;
            if(!count||allocation::live!=before||native::live!=native_before||native::bytes!=native_bytes)return 3;
            for(std::size_t fail=0;fail<=count;++fail) {
                bool complete=false,threw=false;allocation::allowance=fail;native::allowance=fail;
                allocation::calls=0;allocation::denied=false;allocation::enabled=kind==0;
                native::calls=0;native::denied=false;native::enabled=kind==1;
                try {complete=attempt(profile,retry,transport,group);}catch(std::bad_alloc const&){threw=true;}
                allocation::enabled=false;native::enabled=false;boringssl::ERR_clear_error();
                bool denied=kind==0 ? allocation::denied : native::denied;
                if(allocation::live!=before||native::live!=native_before||native::bytes!=native_bytes||(fail<count&&(!denied||complete))||(fail==count&&(!complete||threw||denied))) {
                    std::println("fault error kind={} group={} retry={} fail={}/{} complete={} threw={} denied={} C++live={}/{} native={}/{} nativebytes={}/{}",kind,group,retry,fail,count,complete,threw,denied,allocation::live,before,native::live,native_before,native::bytes,native_bytes);return 4;
                }
                if(fail<count)++failures[kind];
                if(!attempt(profile,retry,transport,group)||allocation::live!=before||native::live!=native_before||native::bytes!=native_bytes)return 5;
            }
            std::println("transport={} profile={} retry={} group={} kind={} allocation failures={} fresh-owner recovery/live balance passed",static_cast<int>(transport),static_cast<int>(profile),retry,group,kind,count);
        }
      }
    std::println("NIST fingerprint C++allocation failures={} BoringSSLnative failures={} passed",failures[0],failures[1]);
}
