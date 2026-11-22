import std;
import dns.message;
import dns.reverse;

namespace {
    std::atomic<bool> fail{false};
    std::atomic<std::size_t> attempts{0};
    std::atomic<std::size_t> fail_at{std::numeric_limits<std::size_t>::max()};
}
void* operator new(std::size_t size) {
    auto attempt=attempts.fetch_add(1,std::memory_order_relaxed);
    if (fail.load(std::memory_order_relaxed) || attempt==fail_at.load(std::memory_order_relaxed)) throw std::bad_alloc{};
    if (auto* p=std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc{};
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
void operator delete[](void* p,std::size_t) noexcept { std::free(p); }

int main() {
    using namespace dns;
    for (std::size_t offset=0;offset<3;++offset) {
        bool failed=false;
        fail_at.store(attempts.load()+offset);
        try { ReverseCache cannot_allocate(8,1,{1,2}); }
        catch (std::bad_alloc const&) { failed=true; }
        fail_at.store(std::numeric_limits<std::size_t>::max());
        if (!failed) return 1;
    }
    ReverseCache cache(8,2,{3,4});
    auto token=cache.token();
    Address a{{192,0,2,1},4};
    AddressAnswer answer{"example.test",{"example.test"},{a},20};
    auto before=attempts.load();
    fail.store(true);
    bool ok=true;
    try {
        for (unsigned i=0;i<2000;++i) {
            Address current{{10,0,static_cast<std::uint8_t>(i>>8),static_cast<std::uint8_t>(i)},4};
            auto now=std::uint64_t(i)*2000;
            ok &= cache.record(1,"example.test",std::span(&current,1),1,now,token)==ReverseRecord::stored;
            ok &= cache.lookup(1,current,now).has_value();
        }
        ok &= cache.clear(); token=cache.token();
        ReverseTransaction transaction(cache,token,1,"example.test");
        ok &= transaction.stage(answer,true,4'000'000);
        ok &= transaction.finish(true,4'000'000)==ReverseCommit::published;
        ok &= cache.lookup(1,a,4'000'000).has_value();
    } catch (...) { ok=false; }
    fail.store(false);
    auto after=attempts.load();
    if (!ok || before!=after) {
        std::cerr << "reverse operations allocated or failed: " << before << " -> " << after << '\n';
        return 2;
    }
    std::cout << "reverse construction failure and allocation-free operations passed\n";
}
