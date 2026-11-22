#include <cstdlib>
#include <new>
#include "bounded_table.hpp"
import std;
import dns.cache;
import dns.message;
#if defined(DNS_MODULE_SNAPSHOT_EXPERIMENT)
class FaultCache : public dns::AddressCache {
public:
    FaultCache(std::size_t capacity,std::uint64_t stale,std::size_t readers)
        : AddressCache(capacity,stale,true,readers) {}
};
#elif defined(DNS_PAGED_SEMANTIC_EXPERIMENT)
#include "paged_semantic.hpp"
using FaultCache=dns_hp_experiment::PagedSemanticCache;
#elif defined(DNS_SNAPSHOT_EXPERIMENT)
#include "snapshot_cache.hpp"
#ifdef DNS_ORDERED_SNAPSHOT_EXPERIMENT
#ifdef DNS_ORDERED_SCALED_EXPERIMENT
using FaultCache=dns_hp_experiment::OrderedSnapshotCache512;
#else
using FaultCache=dns_hp_experiment::OrderedSnapshotCache;
#endif
#else
using FaultCache=dns_hp_experiment::SnapshotCache;
#endif
#else
#include "semantic_cache.hpp"
using FaultCache=dns_hp_experiment::SemanticCache;
#endif

namespace {
    thread_local int fail_after=-1;
    thread_local std::array<void*,4> watched{};
    thread_local std::array<bool,4> freed{};
    void record_free(void* pointer) noexcept {
        for (std::size_t i=0;i<watched.size();++i) if (pointer && pointer==watched[i]) freed[i]=true;
    }
}
auto operator new(std::size_t size) -> void* {
    if (fail_after>=0 && fail_after--==0) throw std::bad_alloc();
    if (auto* p=std::malloc(size ? size : 1)) return p;
    throw std::bad_alloc();
}
void operator delete(void* p) noexcept { record_free(p); std::free(p); }
void operator delete(void* p,std::size_t) noexcept { record_free(p); std::free(p); }
auto operator new(std::size_t size,std::align_val_t alignment) -> void* {
    if (fail_after>=0 && fail_after--==0) throw std::bad_alloc();
    void* p=nullptr;
    if (posix_memalign(&p,static_cast<std::size_t>(alignment),size ? size : 1)==0) return p;
    throw std::bad_alloc();
}
void operator delete(void* p,std::align_val_t) noexcept { record_free(p); std::free(p); }
void operator delete(void* p,std::size_t,std::align_val_t) noexcept { record_free(p); std::free(p); }

namespace d=dns;
auto answer(d::CacheKey const& key,unsigned ttl) -> d::AddressAnswer {
    d::Address address{}; address.size=4; address.bytes[0]=42;
    return {key.name,{key.name},{address},ttl};
}
auto fault_scenario(bool negative) -> int {
    int failures=0;
    for (int index=0;index<64;++index) {
        FaultCache cache(2,5000,1);
        auto reader=cache.reader(0);
        d::CacheKey first{1,"first-long.example.test",1},second{1,"second-long.example.test",1},fresh{1,"fresh-long.example.test",1};
        auto a=cache.begin_query(first),b=cache.begin_query(second);
        if (!a || !b || !cache.publish(first,answer(first,50),1000,*a) || !cache.publish(second,answer(second,60),1000,*b)) return -1;
        auto token=cache.begin_query(fresh); if (!token) return -2;
        auto input=fresh; auto value=answer(fresh,30);
        bool threw=false,success=false;
        fail_after=index;
        try {
            if (negative) success=cache.publish_negative(std::move(input),d::NegativeKind::no_data,30,1000,*token).has_value();
            else success=cache.publish(std::move(input),std::move(value),1000,*token).has_value();
        } catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) {
            ++failures;
            auto x=cache.lookup(first,1000,reader),y=cache.lookup(second,1000,reader),z=cache.lookup(fresh,1000,reader);
            if (!x || !*x || !y || !*y || !z || *z || cache.size()!=2) return -3;
            if (negative) success=cache.publish_negative(fresh,d::NegativeKind::no_data,30,1000,*token).has_value();
            else success=cache.publish(fresh,answer(fresh,30),1000,*token).has_value();
        }
        if (!success) return -4;
        auto x=cache.lookup(first,1000,reader),y=cache.lookup(second,1000,reader),z=cache.lookup(fresh,1000,reader);
        auto n=cache.lookup_negative(fresh,1000,reader);
        if (!x || *x || !y || !*y || !z || z->has_value()==negative || !n || n->has_value()!=negative || cache.size()!=2) return -5;
        fail_after=0;
        auto cleared=cache.clear(1000);
        auto untouched=fail_after==0;
        fail_after=-1;
        if (!cleared || !untouched || cache.size()!=0) return -6;
        if (!threw) return failures;
    }
    return -7;
}
#if defined(DNS_MODULE_SNAPSHOT_EXPERIMENT) || defined(DNS_PAGED_SEMANTIC_EXPERIMENT)
template<class Cache,class Lookup>
auto oversized_storage(Cache& cache,Lookup&& lookup) -> int {
    for (int variant=0;variant<2;++variant) {
        d::CacheKey key{1,variant ? "large-chain.example.test" : "large-item.example.test",1};
        auto oversized=key;
        oversized.name.reserve(1024*1024);
        watched={oversized.name.data(),nullptr,nullptr,nullptr}; freed={};
        auto token=cache.begin_query(std::move(oversized));
        if (!token || !freed[0]) return 1;
        auto value=answer(key,60);
        value.canonical_name.reserve(1024*1024);
        if (variant) value.chain.reserve(65536);
        value.chain[0].reserve(1024*1024);
        value.addresses.reserve(65536);
        watched={value.canonical_name.data(),variant ? static_cast<void*>(value.chain.data()) : nullptr,
                 value.chain[0].data(),value.addresses.data()};
        freed={};
        if (!cache.publish(key,std::move(value),1000,*token) || !freed[0] ||
            (variant && !freed[1]) || !freed[2] || !freed[3]) return 2;
        watched={};
        auto stored=lookup(key);
        if (!stored || !*stored || (**stored).canonical_name!=key.name || (**stored).chain.size()!=1 ||
            (**stored).chain[0]!=key.name || (**stored).addresses.size()!=1) return 3;
    }
    d::CacheKey stale{1,"large-item.example.test",1};
    stale.name.reserve(1024*1024);
    watched={stale.name.data(),nullptr,nullptr,nullptr}; freed={};
    auto refresh=cache.begin_refresh(std::move(stale),61001,1);
    if (!refresh || !*refresh || !freed[0]) return 4;
    watched={};
    return cache.cancel_query(**refresh) ? 0 : 5;
}
#endif
#ifdef DNS_MODULE_SNAPSHOT_EXPERIMENT
auto oversized_allocation_faults(bool use_snapshot) -> int {
    int failures=0;
    for (int index=0;index<32;++index) {
        d::AddressCache cache(2,0,true,use_snapshot ? 1 : 0);
        std::optional<d::AddressCache::Reader> reader;
        if (use_snapshot) reader.emplace(cache.reader(0));
        auto lookup=[&](d::CacheKey const& key) {
            return reader ? cache.lookup(key,1000,*reader) : cache.lookup(key,1000);
        };
        d::CacheKey old{1,"previous-long.example.test",1},fresh{1,"oversized-long.example.test",1};
        auto first=cache.begin_query(old);
        if (!first || !cache.publish(old,answer(old,60),1000,*first)) return -1;
        auto token=cache.begin_query(fresh);
        if (!token) return -2;
        auto value=answer(fresh,60);
        value.canonical_name.reserve(1024*1024);
        value.chain.reserve(64);
        value.chain[0].reserve(1024*1024);
        value.addresses.reserve(256);
        bool threw=false,success=false;
        fail_after=index;
        try { success=cache.publish(fresh,std::move(value),1000,*token).has_value(); }
        catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) {
            ++failures;
            auto before=lookup(old),missing=lookup(fresh);
            if (!before || !*before || !missing || *missing) return -3;
            success=cache.publish(fresh,answer(fresh,60),1000,*token).has_value();
        }
        if (!success) return -4;
        auto result=lookup(fresh);
        if (!result || !*result || (**result).canonical_name!=fresh.name) return -5;
        if (!threw) return failures;
    }
    return -6;
}
#endif
#if defined(DNS_MODULE_SNAPSHOT_EXPERIMENT) || defined(DNS_PAGED_SEMANTIC_EXPERIMENT)
auto construction_faults() -> int {
    int failures=0;
    for (int index=0;index<16;++index) {
        bool threw=false;
        fail_after=index;
        try { FaultCache cache(2,0,257); }
        catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) ++failures;
        else return failures;
    }
    return -1;
}
#endif
#ifdef DNS_PAGED_SEMANTIC_EXPERIMENT
auto paged_oversized_faults() -> int {
    int failures=0;
    for (int index=0;index<32;++index) {
        FaultCache cache(2,0,1); auto reader=cache.reader(0);
        d::CacheKey old{1,"previous-long.example.test",1},fresh{1,"oversized-long.example.test",1};
        auto first=cache.begin_query(old),token=cache.begin_query(fresh);
        if (!first || !token || !cache.publish(old,answer(old,60),1000,*first)) return -1;
        auto value=answer(fresh,60);
        value.canonical_name.reserve(1024*1024); value.chain.reserve(64);
        value.chain[0].reserve(1024*1024); value.addresses.reserve(256);
        bool threw=false,success=false;
        fail_after=index;
        try { success=cache.publish(fresh,std::move(value),1000,*token).has_value(); }
        catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) {
            ++failures;
            auto before=cache.lookup(old,1000,reader),missing=cache.lookup(fresh,1000,reader);
            if (!before || !*before || !missing || *missing) return -2;
            success=cache.publish(fresh,answer(fresh,60),1000,*token).has_value();
        }
        if (!success) return -3;
        auto result=cache.lookup(fresh,1000,reader);
        if (!result || !*result || (**result).canonical_name!=fresh.name) return -4;
        if (!threw) return failures;
    }
    return -5;
}
auto paged_expiry_merge_faults() -> int {
    int failures=0;
    for (int position=0;position<32;++position) {
        FaultCache cache(512,5000,1); auto reader=cache.reader(0);
        std::vector<d::CacheKey> keys;
        for (unsigned i=0;i<33;++i) {
            keys.push_back({1,std::format("merge-fault-{:04}.test",i),1});
            auto token=cache.begin_query(keys.back());
            if (!token) return -1;
            auto result=i<17 ? cache.publish(keys.back(),answer(keys.back(),60),1000,*token)
                             : cache.publish_negative(keys.back(),d::NegativeKind::no_data,1,1000,*token);
            if (!result) return -2;
        }
        if (cache.shape().pages!=2) return -3;
        d::CacheKey missing{1,"missing-long.example.test",1};
        bool threw=false,success=false;
        fail_after=position;
        try { auto result=cache.begin_refresh(missing,3000,1); success=result && !*result; }
        catch (std::bad_alloc const&) { threw=true; }
        fail_after=-1;
        if (threw) {
            ++failures;
            if (cache.shape().pages!=2 || cache.size()!=33) return -4;
            for (unsigned i=0;i<keys.size();++i) {
                auto positive=cache.lookup(keys[i],1000,reader);
                auto negative=cache.lookup_negative(keys[i],1000,reader);
                if (!positive || !negative || positive->has_value()!=(i<17) || negative->has_value()!=(i>=17)) return -5;
            }
            auto retry=cache.begin_refresh(missing,3000,1); success=retry && !*retry;
        }
        if (!success || cache.shape().pages!=1 || cache.size()!=17) return -6;
        if (!threw) return failures;
    }
    return -7;
}
#endif
int main() {
    auto positive=fault_scenario(false),negative=fault_scenario(true);
    if (positive<1 || negative<1) { std::cerr<<"fault scenario "<<positive<<' '<<negative<<'\n'; return 1; }
#ifdef DNS_MODULE_SNAPSHOT_EXPERIMENT
    auto construction=construction_faults();
    if (construction<3) { std::cerr<<"construction faults "<<construction<<'\n'; return 2; }
    std::cout<<"snapshot construction failures recovered: "<<construction<<'\n';
    d::AddressCache locked(2,5000,true);
    auto locked_result=oversized_storage(locked,[&](auto const& key) { return locked.lookup(key,1000); });
    FaultCache snapshot(2,5000,1);
    auto reader=snapshot.reader(0);
    auto snapshot_result=oversized_storage(snapshot,[&](auto const& key) { return snapshot.lookup(key,1000,reader); });
    if (locked_result || snapshot_result) { std::cerr<<"oversized storage "<<locked_result<<' '<<snapshot_result<<'\n'; return 3; }
    std::cout<<"oversized input storage released for locked and snapshot caches\n";
    auto locked_faults=oversized_allocation_faults(false),snapshot_faults=oversized_allocation_faults(true);
    if (locked_faults<5 || snapshot_faults<5) { std::cerr<<"oversized allocation faults "<<locked_faults<<' '<<snapshot_faults<<'\n'; return 4; }
    std::cout<<"oversized compaction allocation failures recovered: "<<locked_faults<<' '<<snapshot_faults<<'\n';
#endif
#ifdef DNS_PAGED_SEMANTIC_EXPERIMENT
    FaultCache paged(2,5000,1); auto reader=paged.reader(0);
    auto storage=oversized_storage(paged,[&](auto const& key) { return paged.lookup(key,1000,reader); });
    auto oversized=paged_oversized_faults(),merge=paged_expiry_merge_faults(),construction=construction_faults();
    if (storage || oversized<5 || merge<2 || construction<2) {
        std::cerr<<"paged storage/faults "<<storage<<' '<<oversized<<' '<<merge<<' '<<construction<<'\n'; return 5;
    }
    std::cout<<"paged oversized, expiry/merge and construction failures recovered: "<<oversized<<' '<<merge<<' '<<construction<<'\n';
#endif
    std::cout<<"allocation failures recovered: positive="<<positive<<", negative="<<negative<<"; clear allocates nothing\n";
}
