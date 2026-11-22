import std;
import dns.message;
import dns.cache;
#include "paged_semantic.hpp"

namespace d=dns;
using Cache=dns_hp_experiment::FullPagedSemanticCache;
auto answer(d::CacheKey const& key,std::uint32_t ttl,std::uint8_t revision) -> d::AddressAnswer {
    d::Address address{}; address.size=4; address.bytes[0]=revision; address.bytes[1]=static_cast<std::uint8_t>(~revision);
    return {key.name,{key.name},{address},ttl};
}
auto matches(d::AddressCache& reference,Cache& cache,Cache::Reader& reader,d::CacheKey const& key,std::uint64_t now) -> bool {
    auto a=reference.lookup(key,now),b=cache.lookup(key,now,reader);
    if (a.has_value()!=b.has_value() || (!a && a.error()!=b.error())) return false;
    if (a && (a->has_value()!=b->has_value() || (*a && ((**a).canonical_name!=(**b).canonical_name ||
        (**a).ttl!=(**b).ttl || (**a).addresses[0].bytes!=(**b).addresses[0].bytes)))) return false;
    auto an=reference.lookup_negative(key,now),bn=cache.lookup_negative(key,now,reader);
    return an.has_value()==bn.has_value() && (an ? *an==*bn : an.error()==bn.error());
}
auto differential_4096() -> int {
    constexpr unsigned capacity=4096,total=5120;
    d::AddressCache reference(capacity,5000,true); Cache cache(capacity,5000,1); auto reader=cache.reader(0);
    std::vector<d::CacheKey> keys;
    for (unsigned i=0;i<total;++i) keys.push_back({1+i%16,std::format("large-capacity-{:05}.test",i),1});
    auto publish=[&](unsigned i) {
        auto a=reference.begin_query(keys[i]),b=cache.begin_query(keys[i]);
        if (!a || !b || a->generation!=b->generation || a->query!=b->query) return false;
        auto ttl=i<capacity ? 120+i : 7000+i;
        auto first=i%3 ? reference.publish(keys[i],answer(keys[i],ttl,i),1000,*a)
                       : reference.publish_negative(keys[i],d::NegativeKind::no_data,ttl,1000,*a);
        auto second=i%3 ? cache.publish(keys[i],answer(keys[i],ttl,i),1000,*b)
                        : cache.publish_negative(keys[i],d::NegativeKind::no_data,ttl,1000,*b);
        return first && second;
    };
    for (unsigned i=0;i<capacity;++i) if (!publish((i*2053)%capacity)) return 1;
    for (unsigned i=capacity;i<total;++i) if (!publish(i)) return 2;
    if (reference.size()!=capacity || cache.size()!=capacity || cache.shape().min_neighbor_sum<=32 || cache.shape().pages>263) return 3;
    for (auto const& key:keys) if (!matches(reference,cache,reader,key,1000)) return 4;
    constexpr std::uint64_t later=1160000;
    auto first=reference.lookup_stale(keys[1039],later),second=cache.lookup_stale(keys[1039],later);
    if (!first || !second || !*first || !*second || (**first).age_ms!=(**second).age_ms ||
        (**first).answer.ttl!=(**second).answer.ttl || reference.size()!=cache.size()) return 5;
    for (auto const& key:keys) if (!matches(reference,cache,reader,key,later)) return 6;
    return 0;
}
auto capacity_4352() -> int {
    constexpr unsigned capacity=4352,extra=256;
    Cache cache(capacity,0,1); auto reader=cache.reader(0);
    std::vector<d::CacheKey> keys;
    for (unsigned i=0;i<capacity+extra;++i) keys.push_back({1+i%17,std::format("full-capacity-{:05}.test",i),1});
    for (unsigned i=0;i<keys.size();++i) {
        auto token=cache.begin_query(keys[i]);
        auto ttl=i<capacity ? 1000+i : 20000+i;
        if (!token || !cache.publish(keys[i],answer(keys[i],ttl,i),1000,*token)) return 1;
    }
    if (cache.size()!=capacity || cache.shape().pages>263 || cache.shape().min_neighbor_sum<=32) return 2;
    for (unsigned i=0;i<keys.size();++i) {
        auto value=cache.lookup(keys[i],1000,reader);
        if (!value || value->has_value()!=(i>=extra) || (*value && (**value).addresses[0].bytes[0]!=static_cast<std::uint8_t>(i))) return 3;
    }
    return 0;
}
auto readers_257() -> int {
    constexpr std::size_t count=257;
    Cache cache(1,0,count); std::vector<Cache::Reader> readers; readers.reserve(count);
    for (std::size_t i=0;i<count;++i) readers.push_back(cache.reader(i));
    d::CacheKey key{1,"full-reader-pool.test",1};
    auto publish=[&](std::uint8_t value) {
        auto token=cache.begin_query(key);
        return token && cache.publish(key,answer(key,60,value),1000,*token).has_value();
    };
    if (!publish(0)) return 1;
    bool valid=true;
    auto pin=[&](auto&& self,std::size_t i) -> void {
        auto result=cache.lookup_with_hook(key,1000,readers[i],[&] {
            if (!publish(static_cast<std::uint8_t>(i+1))) { valid=false; return; }
            if (i+1<count) self(self,i+1);
            else if (Cache::live_nodes()!=count+1) valid=false;
        });
        if (!result || !*result || (**result).addresses[0].bytes[0]!=static_cast<std::uint8_t>(i)) valid=false;
    };
    pin(pin,0);
    if (!valid || !publish(42) || Cache::live_nodes()!=1) return 2;
    return 0;
}
auto threaded_readers() -> int {
    constexpr unsigned count=32;
    Cache cache(1,0,count);
    d::CacheKey key{1,"full-threaded-readers.test",1};
    auto publish=[&](std::uint8_t value) {
        auto token=cache.begin_query(key);
        return token && cache.publish(key,answer(key,60,value),1000,*token).has_value();
    };
    if (!publish(0)) return 1;
    std::atomic<unsigned> entered=0;
    std::atomic<bool> release=false,failed=false;
    std::vector<std::thread> threads; threads.reserve(count);
    for (unsigned i=0;i<count && !failed.load();++i) {
        try {
            threads.emplace_back([&,i] {
                try {
                    auto reader=cache.reader(i);
                    auto result=cache.lookup_with_hook(key,1000,reader,[&] {
                        entered.fetch_add(1); entered.notify_one(); release.wait(false);
                    });
                    if (!result || !*result || (**result).addresses[0].bytes[0]!=i) failed=true;
                } catch (...) {
                    failed=true; entered.fetch_add(1); entered.notify_one();
                }
            });
        } catch (...) { failed=true; break; }
        auto observed=entered.load();
        while (observed<=i && !failed.load()) { entered.wait(observed); observed=entered.load(); }
        if (!failed.load() && !publish(static_cast<std::uint8_t>(i+1))) failed=true;
    }
    for (unsigned i=0;i<100 && !failed.load();++i) if (!publish(static_cast<std::uint8_t>(i))) failed=true;
    if (threads.size()!=count || Cache::live_nodes()!=count+1) failed=true;
    release=true; release.notify_all();
    for (auto& thread:threads) thread.join();
    if (failed || !publish(99) || Cache::live_nodes()!=1) return 2;
    return 0;
}
auto full_histories() -> int {
    constexpr std::size_t count=2,entries=4352;
    Cache cache(entries,0,count); std::vector<Cache::Reader> readers;
    for (std::size_t i=0;i<count;++i) readers.push_back(cache.reader(i));
    std::vector<d::CacheKey> keys;
    for (std::size_t i=0;i<entries;++i) keys.push_back({1,std::format("full-history-{:05}.test",i),1});
    auto publish=[&](d::CacheKey const& key,std::uint8_t value) {
        auto token=cache.begin_query(key);
        return token && cache.publish(key,answer(key,3600,value),1000,*token).has_value();
    };
    for (auto const& key:keys) if (!publish(key,0)) return 1;
    bool valid=true;
    auto pin=[&](auto&& self,std::size_t i) -> void {
        auto result=cache.lookup_with_hook(keys[0],1000,readers[i],[&] {
            for (auto const& key:keys) if (!publish(key,static_cast<std::uint8_t>(i+1))) { valid=false; return; }
            if (i+1<count) self(self,i+1);
            else if (Cache::live_nodes()!=(count+1)*entries) valid=false;
        });
        if (!result || !*result || (**result).addresses[0].bytes[0]!=i) valid=false;
    };
    pin(pin,0);
    if (!valid || !publish(keys[0],99) || Cache::live_nodes()!=entries) return 2;
    return 0;
}
int main() {
    if (auto result=differential_4096()) { std::cerr<<"paged 4096 differential "<<result<<'\n'; return 1; }
    if (auto result=capacity_4352()) { std::cerr<<"paged 4352 capacity "<<result<<'\n'; return 2; }
    if (auto result=readers_257()) { std::cerr<<"paged 257 readers "<<result<<'\n'; return 3; }
    if (auto result=threaded_readers()) { std::cerr<<"paged threaded readers "<<result<<'\n'; return 4; }
    if (auto result=full_histories()) { std::cerr<<"paged full histories "<<result<<'\n'; return 5; }
    std::puts("paged semantic 4096 differential, 4352 capacity, reader slots and histories passed");
}
