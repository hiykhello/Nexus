import std;
import quic.packet_keys;
import quic.packet_protection;
import crypto;

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


namespace q=quic;
namespace c = ::crypto;
auto hex(std::string_view input) -> c::Bytes {
    auto nib=[](char ch) {return ch<='9' ? ch-'0' : ch-'a'+10;};
    c::Bytes bytes;for(std::size_t i=0;i<input.size();i+=2)bytes.push_back(nib(input[i])*16+nib(input[i+1]));return bytes;
}
// RFC9001 Appendix A.5. Code components under Simplified BSD License, IETF Trust 2021.
int main() {
    auto secret=hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b");
    q::PacketKeys keys;
    if(!keys.reset(q::PacketSuite::chacha20_poly1305_sha256,secret))return 1;
    if(!std::ranges::equal(keys.iv(),hex("e0459b3474bdd0e44a41c144")))return 2;
    auto nonce=q::packet_nonce(keys.iv(),654360564);if(!nonce||!std::ranges::equal(*nonce,hex("e0459b3474bdd0e46d417eb0")))return 3;
    auto header=hex("4200bff4"),payload=hex("01"),expected=hex("655e5cd55c41f69080575d7999c25a5bfb");
    std::array<std::uint8_t,17> encrypted{};
    auto sealed=keys.seal_to(encrypted,*nonce,payload,header);if(!sealed||*sealed!=17||!std::ranges::equal(encrypted,expected))return 4;
    std::array<std::uint8_t,16> sample{},mask{};
    std::copy_n(encrypted.begin()+1,16,sample.begin());
    if(!keys.mask_to(mask,sample)||!std::ranges::equal(std::span(mask).first(5),hex("aefefe7d03")))return 5;
    auto protected_header=header;protected_header[0]^=mask[0]&31;
    for(std::size_t index=1;index<4;++index)protected_header[index]^=mask[index];
    if(protected_header!=hex("4cfe4189"))return 6;
    std::array<std::uint8_t,1> opened{};
    auto plain=keys.open_to(opened,*nonce,encrypted,header);if(!plain||*plain!=1||opened[0]!=1)return 7;
    // A partial overlap must not change the sample before its counter/nonce
    // are consumed; the mask API allows sample/output sharing.
    std::array<std::uint8_t,17> overlap{};std::ranges::copy(sample,overlap.begin());
    if(!keys.mask_to(std::span(overlap).subspan<1,16>(),std::span(overlap).first<16>())||!std::ranges::equal(std::span(overlap).subspan(1),mask))return 8;
    for(auto index:{0u,8u,16u}) {
        auto bad=encrypted;bad[index]^=1;opened[0]=0xff;
        auto failure=keys.open_to(opened,*nonce,bad,header);
        if(failure||failure.error()!=c::Error::authentication_failed||opened[0])return 9;
    }
    auto update=q::packet_key_detail::expand(c::Hash::sha256,secret,"quic ku",32);
    if(!update||*update!=hex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9"))return 10;
    allocation::calls=0;allocation::allowance=-1;allocation::enabled=true;
    for (unsigned trial=0;trial<256;++trial) {
        if (!keys.seal_to(encrypted,*nonce,payload,header) || !keys.open_to(opened,*nonce,encrypted,header) || !keys.mask_to(mask,sample)) return 14;
    }
    allocation::enabled=false;
    if (allocation::calls) return 15;
    auto before=allocation::live;std::size_t failures=0;
    for (std::ptrdiff_t fail=0;fail<16;++fail) {
        bool complete=false,threw=false;
        {
            q::PacketKeys fresh;allocation::allowance=fail;allocation::calls=0;allocation::denied=false;allocation::enabled=true;
            try {complete=fresh.reset(q::PacketSuite::chacha20_poly1305_sha256,secret).has_value();} catch (std::bad_alloc const&) {threw=true;}
            allocation::enabled=false;
            if (allocation::denied && (complete || !threw || fresh.ready())) return 16;
            if (allocation::denied) {
                ++failures;
                if (!fresh.reset(q::PacketSuite::chacha20_poly1305_sha256,secret)) return 17;
            }
        }
        if (allocation::live!=before) return 18;
        if (complete) break;
    }
    if (failures!=3) return 19;
    // Explicit lifetime switching repeatedly reuses the same direct header state.
    for(unsigned round=0;round<32;++round) {
        keys.clear();if(keys.ready()||keys.mask_to(mask,sample))return 11;
        auto suite=round%2 ? q::PacketSuite::chacha20_poly1305_sha256 : q::PacketSuite::aes128_gcm_sha256;
        if(!keys.reset(suite,secret)||!keys.mask_to(mask,sample))return 12;
    }
    keys.clear();if(keys.reset(q::PacketSuite::chacha20_poly1305_sha256,std::array<std::uint8_t,48>{}))return 13;
    std::println("RFC9001A5 ChaCha packet/HP/nonce/KU, tamper erasure, overlap, AES/ChaCha typed-state reuse, 3 cold C++failures and 768 per-packet operations C++new0 passed; PacketKeys={} Protection={}",sizeof(q::PacketKeys),sizeof(q::PacketProtection<>));
}
