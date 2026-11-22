#include <cstdlib>
#include <new>
import std;
import dns.message;
import dns.cache;
#include "paged_snapshot.hpp"

namespace { thread_local int fail_after=-1; }
auto operator new(std::size_t size) -> void* {
    if (fail_after>=0 && fail_after--==0) { fail_after=-1; throw std::bad_alloc(); }
    if (auto* result=std::malloc(size ? size : 1)) return result;
    throw std::bad_alloc();
}
auto operator new(std::size_t size,std::align_val_t alignment) -> void* {
    if (fail_after>=0 && fail_after--==0) { fail_after=-1; throw std::bad_alloc(); }
    void* result=nullptr;
    if (posix_memalign(&result,static_cast<std::size_t>(alignment),size ? size : 1)==0) return result;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p,std::size_t) noexcept { std::free(p); }
void operator delete(void* p,std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p,std::size_t,std::align_val_t) noexcept { std::free(p); }

namespace d=dns;
using Cache=dns_hp_experiment::PagedSnapshotPrototype;
auto answer(d::CacheKey const& key,std::uint32_t ttl) -> d::AddressAnswer {
    d::Address address{}; address.size=4; address.bytes[0]=42;
    return {key.name,{key.name},{address},ttl};
}
auto scenario(unsigned kind) -> int {
    unsigned faults=0;
    for (int position=0;position<64;++position) {
        auto count=kind==1 ? 512U : kind==3 ? 33U : 32U;
        Cache cache(512,0,1); auto reader=cache.reader(0);
        std::vector<d::CacheKey> keys;
        for (unsigned i=0;i<count;++i) keys.push_back({1,std::format("fault-long-key-{:04}.test",i),1});
        for (unsigned i=0;i<keys.size();++i) {
            auto const& key=keys[i];
            auto token=cache.begin_query(key);
            auto ttl=kind==2 || (kind==3 && i>=17) ? 1 : 60;
            if (!token || !cache.publish(key,answer(key,ttl),1000,*token)) return -1;
        }
        if (kind==3 && cache.shape().pages!=2) return -7;
        d::CacheKey fresh{1,"fault-long-key-new.test",1};
        auto token=cache.begin_query(fresh); if (!token) return -2;
        bool caught=false,completed=false;
        auto now=kind>=2 ? 3000 : 1000;
        fail_after=position;
        try { completed=cache.publish(fresh,answer(fresh,60),now,*token).has_value(); }
        catch (std::bad_alloc const&) { caught=true; }
        fail_after=-1;
        if (!caught && !completed) return -3;
        if (caught) {
            ++faults;
            if (kind==3 && (cache.shape().pages!=2 || cache.shape().entries!=33)) return -9;
            for (auto const& key:keys) {
                auto old=cache.lookup(key,1000,reader);
                if (!old || !*old || (**old).addresses[0].bytes[0]!=42) return -4;
            }
            auto missing=cache.lookup(fresh,1000,reader);
            if (!missing || *missing || !cache.publish(fresh,answer(fresh,60),now,*token)) return -5;
        }
        auto added=cache.lookup(fresh,now,reader);
        auto old=cache.lookup(keys.front(),now,reader);
        if (!added || !*added || !old || ((kind==0 || kind==3) ? !*old : old->has_value())) return -6;
        if (kind==3 && (cache.shape().pages!=1 || cache.shape().entries!=18)) return -8;
        if (!caught) break;
    }
    return static_cast<int>(faults);
}
int main() {
    for (unsigned kind=0;kind<4;++kind) {
        auto faults=scenario(kind);
        if (faults<2) { std::cerr<<"paged fault "<<kind<<": "<<faults<<'\n'; return 1; }
        std::println("paged {}: {} allocation failures recovered",kind==0 ? "split" : kind==1 ? "eviction" : kind==2 ? "expiry" : "merge",faults);
    }
}
