import std;
import crypto;
import tls.fingerprint;

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


namespace c = ::crypto;
namespace t=tls;
namespace {
    enum class Mode { collision,repeated,initial_failure,block_failure,refill_failure,sid_failure,permutation_failure } mode;
    unsigned random32=0,random64=0;
    bool enabled=false;
}
auto controlled_random(std::span<std::uint8_t>) -> std::expected<void,c::Error>
    asm("__wrap__ZN5nexus6cryptoW5nexusW6crypto12random_bytesESt4spanIhLm18446744073709551615EE");
auto controlled_random(std::span<std::uint8_t> output) -> std::expected<void,c::Error> {
    if (!enabled) return std::unexpected(c::Error::backend_failure);
    std::ranges::fill(output,std::uint8_t{0x42});
    if (output.size()==32) {
        ++random32;
        if ((mode==Mode::initial_failure && random32==1) || (mode==Mode::sid_failure && random32==2)) return std::unexpected(c::Error::backend_failure);
        return {};
    }
    if (output.size()!=64) return std::unexpected(c::Error::backend_failure);
    ++random64;
    if (random64>3) return std::unexpected(c::Error::backend_failure);
    if ((mode==Mode::block_failure && random64==1) ||
        (mode==Mode::refill_failure && random64==2) ||
        (mode==Mode::permutation_failure && random64==3)) return std::unexpected(c::Error::backend_failure);
    // Each 16-bit sample first starts with zero. Six independent samples
    // deliberately collide in the two extension positions (index4/index5).
    for (std::size_t index=0;index<32;++index) { output[2*index]=0;output[2*index+1]=5; }
    if (random64==1) {
        for (unsigned index=0;index<4;++index)output[2*index+1]=index+1;
        if (mode==Mode::collision || mode==Mode::sid_failure)output[13]=12;
        if (mode==Mode::repeated)output[17]=12;
    } else if (mode==Mode::permutation_failure) {
        // First value resolves the collision, then every shuffle sample is
        // rejected above its exact bound until a third entropy block fails.
        std::ranges::fill(output,std::uint8_t{255});output[0]=0;output[1]=12;
    }
    return {};
}
int main() {
    // Calibration: an unwrapped binary fails here instead of accepting real
    // random data as a deterministic collision-path test.
    std::array<std::uint8_t,1> calibration{};if (c::random_bytes(calibration)) return 1;
    for (auto selected:{Mode::collision,Mode::repeated,Mode::initial_failure,Mode::block_failure,Mode::refill_failure,Mode::sid_failure,Mode::permutation_failure}) {
        auto before=allocation::live;
        {
        mode=selected;random32=random64=0;enabled=true;
        t::FingerprintConfig policy;
        policy.profile=mode==Mode::permutation_failure ? t::Fingerprint::tls13_randomized : t::Fingerprint::tls13_grease;
        auto hello=t::make_fingerprint_hello("localhost",{},policy);
        enabled=false;
        if (mode==Mode::collision || mode==Mode::repeated) {
            if (!hello || hello->hello.extensions.front().type!=0x5a5a || hello->hello.extensions.back().type!=0xcaca || random64!=1 || random32!=2) return 2;
            auto* groups=hello->hello.extension(10);auto* versions=hello->hello.extension(43);auto* signatures=hello->hello.extension(13);
            if (hello->hello.cipher_suites.front()!=0x1a1a || !groups || groups->data[2]!=0x2a || groups->data[3]!=0x2a ||
                !versions || versions->data[1]!=0x3a || versions->data[2]!=0x3a ||
                !signatures || signatures->data[2]!=0x4a || signatures->data[3]!=0x4a) return 3;
        } else if (hello || hello.error()!=t::FingerprintError::random_error) return 4;
        // A failed sample does not poison the next independent construction.
        mode=Mode::collision;random32=random64=0;enabled=true;
        auto recovered=t::make_fingerprint_hello("localhost",{},policy);enabled=false;
        if (!recovered) return 5;
        }
        if (allocation::live!=before) return 6;
    }
    std::println("calibrated CSPRNG wrapper: distinct GREASE rejection-resampling, repeated collision, exact independent slots, all five entropy failure stages and next-owner recovery passed");
}
