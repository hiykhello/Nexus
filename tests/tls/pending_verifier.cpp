import std;
import functional;
import tls.client_hello_driver;

static volatile bool deny_allocations=false;
static volatile std::size_t allocations=0;
void* operator new(std::size_t size) {
    if (deny_allocations) throw std::bad_alloc{};
    if (auto p=std::malloc(size ? size : 1)) { allocations = allocations + 1; return p; }
    throw std::bad_alloc{};
}
void* operator new(std::size_t size,std::align_val_t alignment) {
    if (deny_allocations) throw std::bad_alloc{};
    auto a=static_cast<std::size_t>(alignment);
    if (auto p=std::aligned_alloc(a,((size ? size : 1)+a-1)/a*a)) { allocations = allocations + 1; return p; }
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
void operator delete(void* p,std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p,std::size_t,std::align_val_t) noexcept { std::free(p); }

namespace t=tls;
using Chain=std::span<std::span<std::uint8_t const> const>;
struct Counts { int live=0; int destroyed=0; };
struct Policy {
    std::array<std::uint8_t,40> bytes{};
    Counts* counts;
    explicit Policy(Counts& c) noexcept : counts(&c) { ++counts->live; }
    Policy(Policy const&)=delete;
    Policy(Policy&& other) noexcept : bytes(other.bytes),counts(std::exchange(other.counts,nullptr)) {}
    ~Policy() { if (counts) { --counts->live; ++counts->destroyed; } }
    auto operator()(Chain chain) const -> bool { return !chain.empty() && counts && bytes[0]==0; }
};
struct Large {
    std::array<std::byte,128> bytes{};
    auto operator()(Chain) const -> bool { return true; }
};
struct alignas(64) Aligned {
    auto operator()(Chain) const -> bool { return reinterpret_cast<std::uintptr_t>(this)%alignof(Aligned)==0; }
};
struct ThrowMove {
    ThrowMove()=default;
    ThrowMove(ThrowMove const&)=default;
    ThrowMove(ThrowMove&&) noexcept(false) {}
    auto operator()(Chain) const -> bool { return true; }
};
static_assert(t::PendingCertificateVerifier::stores_inline<Policy>);
static_assert(!t::PendingCertificateVerifier::stores_inline<Large>);
static_assert(!t::PendingCertificateVerifier::stores_inline<Aligned>);
static_assert(!t::PendingCertificateVerifier::stores_inline<ThrowMove>);
static_assert(std::is_nothrow_move_constructible_v<t::PendingCertificateVerifier>);

[[gnu::noinline]] static auto observe_verifier(t::CertificateVerifier const& v, Chain chain) -> bool {
    static t::CertificateVerifier const* volatile sink = nullptr;
    sink = &v;
    return static_cast<bool>(v) && v(chain);
}

[[gnu::noinline]] static auto observe_pending(t::PendingCertificateVerifier const& p) -> bool {
    static t::PendingCertificateVerifier const* volatile sink = nullptr;
    sink = &p;
    return static_cast<bool>(p);
}

int main() {
    std::array<std::uint8_t,1> data{1};
    std::array<std::span<std::uint8_t const>,1> chain{data};
    Counts counts;
    auto before=allocations;
    {
        t::PendingCertificateVerifier first{Policy{counts}};
        t::PendingCertificateVerifier second{std::move(first)};
        t::PendingCertificateVerifier third;
        third=std::move(second);
        third=std::move(third);
        if (first || second || !third || allocations!=before || counts.live!=1) return 1;
        auto verifier=third.release();
        if (third || !verifier || !verifier(chain) || counts.live!=1 || allocations!=before+1) return 2;
    }
    if (counts.live || counts.destroyed!=1) return 3;

    Counts failed;
    {
        t::PendingCertificateVerifier pending{Policy{failed}};
        deny_allocations=true;
        try { (void)pending.release(); deny_allocations=false; return 4; }
        catch (std::bad_alloc const&) { deny_allocations=false; }
        if (!pending || failed.live!=1) return 5;
        pending=nullptr;
    }
    if (failed.live || failed.destroyed!=1) return 6;

    before=allocations;
    {
        t::CertificateVerifier baseline{Large{}};
        if (!observe_verifier(baseline,chain)) return 7;
    }
    auto large_allocations=allocations-before;
    if (!large_allocations) return 15;
    before=allocations;
    {
        t::PendingCertificateVerifier pending{Large{}};
        if (!observe_pending(pending) || allocations-before!=large_allocations) return 8;
        auto verifier=pending.release();
        if (pending || !observe_verifier(verifier,chain) || allocations-before!=large_allocations) return 9;
    }
    before=allocations;
    {
        t::PendingCertificateVerifier pending{Aligned{}};
        auto verifier=pending.release();
        if (!observe_verifier(verifier,chain) || allocations!=before+1) return 10;
    }
    ThrowMove throwing_move;
    before=allocations;
    {
        t::PendingCertificateVerifier pending{throwing_move};
        auto verifier=pending.release();
        if (!observe_verifier(verifier,chain) || allocations!=before+1) return 11;
    }
    {
        Counts stable;
        t::PendingCertificateVerifier pending{Policy{stable}};
        deny_allocations=true;
        try { pending=Large{}; deny_allocations=false; return 12; }
        catch (std::bad_alloc const&) { deny_allocations=false; }
        if (!pending || stable.live!=1) return 13;
        pending=nullptr;
        if (stable.live || stable.destroyed!=1) return 14;
    }
    using Function=bool (*)(Chain);
    Function null_function=nullptr;
    t::CertificateVerifier empty;
    functional::copyable_function<bool(Chain) const> empty_copy;
    functional::move_only_function<int(Chain) const> empty_other;
    t::PendingCertificateVerifier a{null_function},b{std::move(empty)},c{nullptr},d{empty_copy},e{std::move(empty_other)};
    if (a || b || c || d || e || a.release() || b.release() || c.release() || d.release() || e.release()) return 15;
    return 0;
}
