import std;
import dns.message;
import dns.cache;
#include "paged_snapshot.hpp"

namespace d=dns;
using Cache=dns_hp_experiment::PagedSnapshotPrototype;

auto answer(d::CacheKey const& key,std::uint32_t ttl,std::uint8_t value) -> d::AddressAnswer {
    d::Address address{}; address.size=key.type==1 ? 4 : 16;
    address.bytes[0]=value; address.bytes[1]=static_cast<std::uint8_t>(~value);
    return {key.name,{key.name},{address},ttl};
}
template<class A,class B> auto same_status(A const& a,B const& b) -> bool {
    return a.has_value()==b.has_value() && (a.has_value() || a.error()==b.error());
}
auto same_answer(d::AddressAnswer const& a,d::AddressAnswer const& b) -> bool {
    if (a.canonical_name!=b.canonical_name || a.chain!=b.chain || a.ttl!=b.ttl || a.addresses.size()!=b.addresses.size()) return false;
    for (std::size_t i=0;i<a.addresses.size();++i)
        if (a.addresses[i].size!=b.addresses[i].size || a.addresses[i].bytes!=b.addresses[i].bytes) return false;
    return true;
}
auto differential() -> int {
    d::AddressCache reference(512,0,true); Cache candidate(512,0,1); auto reader=candidate.reader(0);
    std::vector<d::CacheKey> keys;
    for (unsigned i=0;i<768;++i) keys.push_back({1+i%2,std::format("domain-{:04}.test",i),static_cast<std::uint16_t>(i%3 ? 1 : 28)});
    struct Pair { d::CacheKey key; d::CacheToken a,b; };
    std::vector<Pair> pending;
    std::uint64_t state=0x8234599811a2b3c4ULL,now=100000;
    auto random=[&] { state^=state<<13; state^=state>>7; state^=state<<17; return state; };
    for (unsigned step=0;step<30000;++step) {
        now+=random()%41;
        auto sampled=random()%5==0 && now>50 ? now-50 : now;
        auto const& key=keys[random()%keys.size()];
        if (random()%100<45) {
            auto a=reference.begin_query(key),b=candidate.begin_query(key);
            if (!same_status(a,b) || (a && (a->generation!=b->generation || a->query!=b->query))) return 1;
            if (a) pending.push_back({key,*a,*b});
        } else if (!pending.empty()) {
            auto const& pair=pending[random()%pending.size()];
            auto value=answer(pair.key,1+random()%120,static_cast<std::uint8_t>(step));
            auto a=reference.publish(pair.key,value,sampled,pair.a),b=candidate.publish(pair.key,std::move(value),sampled,pair.b);
            if (!same_status(a,b)) return 2;
        }
        for (unsigned sample=0;sample<4;++sample) {
            auto const& probe=keys[random()%keys.size()];
            auto a=reference.lookup(probe,sampled),b=candidate.lookup(probe,sampled,reader);
            if (!same_status(a,b) || (a && (a->has_value()!=b->has_value() || (*a && !same_answer(**a,**b))))) return 3;
        }
        auto shape=candidate.shape();
        if (shape.pages>31 || shape.min_neighbor_sum<=32) return 4;
    }
    return 0;
}
auto capacity_and_expiry() -> int {
    d::AddressCache reference(512,0,true); Cache candidate(512,0,1); auto reader=candidate.reader(0);
    std::vector<d::CacheKey> keys;
    for (unsigned i=0;i<768;++i) keys.push_back({1,std::format("capacity-{:04}.test",i),1});
    auto publish=[&](unsigned index,std::uint64_t now) {
        auto const& key=keys[index];
        auto a=reference.begin_query(key),b=candidate.begin_query(key);
        if (!a || !b) return false;
        auto first=reference.publish(key,answer(key,1000+index,index),now,*a);
        auto second=candidate.publish(key,answer(key,1000+index,index),now,*b);
        return first && second;
    };
    for (unsigned i=0;i<512;++i) if (!publish((i*257)%512,1000)) return 1;
    for (unsigned i=512;i<768;++i) if (!publish(i,1000)) return 2;
    auto compare=[&](std::uint64_t now) {
        for (auto const& key:keys) {
            auto a=reference.lookup(key,now),b=candidate.lookup(key,now,reader);
            if (!same_status(a,b) || (a && (a->has_value()!=b->has_value() || (*a && !same_answer(**a,**b))))) return false;
        }
        return true;
    };
    if (!compare(1000) || !publish(0,1500001) || !compare(1500001)) return 3;
    return 0;
}
auto concurrent() -> int {
    Cache cache(512,0,8);
    std::vector<d::CacheKey> keys;
    for (unsigned i=0;i<512;++i) keys.push_back({1,std::format("key-{:04}.test",i),1});
    auto publish=[&](std::size_t index,std::uint8_t value) {
        auto token=cache.begin_query(keys[index]);
        return token && cache.publish(keys[index],answer(keys[index],3600,value),1000,*token).has_value();
    };
    for (std::size_t i=0;i<keys.size();++i) if (!publish(i,0)) return 1;
    std::barrier gate(9);
    std::atomic<bool> stop=false,failed=false;
    std::atomic<std::size_t> count=0;
    std::vector<std::thread> threads;
    for (unsigned id=0;id<8;++id) threads.emplace_back([&,id] {
        auto reader=cache.reader(id); std::uint64_t rng=0x928374abULL+id;
        gate.arrive_and_wait();
        while (!stop.load()) {
            rng^=rng<<13; rng^=rng>>7; rng^=rng<<17;
            auto const& key=keys[rng%keys.size()]; auto result=cache.lookup(key,1000,reader);
            if (!result || !*result || (**result).canonical_name!=key.name || (**result).addresses.size()!=1 ||
                (**result).addresses[0].bytes[1]!=static_cast<std::uint8_t>(~(**result).addresses[0].bytes[0])) failed=true;
            ++count;
        }
    });
    gate.arrive_and_wait();
    for (unsigned i=0;i<10000 && !failed.load();++i) if (!publish(i%512,static_cast<std::uint8_t>(i))) failed=true;
    stop=true; for (auto& thread:threads) thread.join();
    return failed || count==0 ? 2 : 0;
}
auto histories() -> int {
    constexpr std::size_t readers_count=4,entries=512;
    Cache cache(entries,0,readers_count);
    std::vector<Cache::Reader> readers;
    for (std::size_t i=0;i<readers_count;++i) readers.push_back(cache.reader(i));
    std::vector<d::CacheKey> keys;
    for (std::size_t i=0;i<entries;++i) keys.push_back({1,std::format("history-{:04}.test",i),1});
    auto publish=[&](d::CacheKey const& key,unsigned value) {
        auto token=cache.begin_query(key);
        return token && cache.publish(key,answer(key,60,value),1000,*token).has_value();
    };
    for (auto const& key:keys) if (!publish(key,0)) return 1;
    bool valid=true;
    auto pin=[&](auto&& self,std::size_t index) -> void {
        auto result=cache.lookup_with_hook(keys[0],1000,readers[index],[&] {
            for (auto const& key:keys) if (!publish(key,index+1)) { valid=false; return; }
            if (index+1<readers_count) self(self,index+1);
            else if (Cache::live_nodes()!=(readers_count+1)*entries || !publish(keys[0],5) ||
                     Cache::live_nodes()!=(readers_count+1)*entries || Cache::peak_nodes()<(readers_count+1)*entries+1) valid=false;
        });
        if (!result || !*result || (**result).addresses[0].bytes[0]!=index) valid=false;
    };
    pin(pin,0);
    if (!valid || !publish(keys[0],9) || Cache::live_nodes()!=entries) return 2;
    return 0;
}
auto fragmentation() -> int {
    Cache cache(512,0,1); auto reader=cache.reader(0);
    std::vector<d::CacheKey> survivors;
    std::uint64_t now=1000;
    unsigned sequence=0;
    auto next_key=[&] { return d::CacheKey{1,std::format("fragment-{:06}.test",sequence++),1}; };
    auto publish=[&](d::CacheKey const& key,std::uint32_t ttl) {
        auto token=cache.begin_query(key);
        return token && cache.publish(key,answer(key,ttl,42),now,*token).has_value();
    };
    survivors.push_back(next_key());
    if (!publish(survivors.back(),3600)) return 1;
    // Repeatedly insert a batch and expire all but one. Without sparse-page
    // merging this sequence reaches 481 one-node pages.
    for (unsigned round=0;round<480;++round) {
        d::CacheKey next_survivor;
        for (unsigned i=1;i<=32;++i) {
            auto key=next_key();
            if (i==16) next_survivor=key;
            if (!publish(key,i==16 ? 3600 : 1)) return 2;
        }
        now+=2000;
        if (!publish(next_survivor,3600)) return 3;
        survivors.push_back(std::move(next_survivor));
        auto shape=cache.shape();
        if (shape.entries!=survivors.size() || shape.min_neighbor_sum<=32 ||
            shape.pages>2*shape.entries/33+1) return 4;
    }
    for (auto const& key:survivors) {
        auto result=cache.lookup(key,now,reader);
        if (!result || !*result || (**result).addresses[0].bytes[0]!=42) return 5;
    }
    auto shape=cache.shape();
    std::println("paged after churn: {} entries, {} pages, root {} bytes, page {} bytes",
                 shape.entries,shape.pages,shape.root_bytes,shape.page_bytes);
    return 0;
}
auto merge_with_reader() -> int {
    Cache cache(512,0,1); auto reader=cache.reader(0);
    std::vector<d::CacheKey> keys;
    auto publish=[&](d::CacheKey const& key,std::uint32_t ttl,std::uint64_t now) {
        auto token=cache.begin_query(key);
        return token && cache.publish(key,answer(key,ttl,42),now,*token).has_value();
    };
    for (unsigned i=0;i<33;++i) {
        keys.push_back({1,std::format("merge-{:04}.test",i),1});
        if (!publish(keys.back(),i>=17 ? 1 : 60,1000)) return 1;
    }
    if (cache.shape().pages!=2) return 2;
    d::CacheKey fresh{1,"merge-new.test",1};
    bool valid=true;
    auto old=cache.lookup_with_hook(keys.back(),1000,reader,[&] {
        if (!publish(fresh,60,3000) || cache.shape().pages!=1 ||
            cache.shape().entries!=18 || Cache::live_nodes()!=34) valid=false;
    });
    if (!valid || !old || !*old || (**old).addresses[0].bytes[0]!=42) return 3;
    if (!publish(fresh,60,3000) || Cache::live_nodes()!=18) return 4;
    return 0;
}
auto concurrent_merge() -> int {
    constexpr unsigned rounds=64,readers_count=8;
    Cache cache(512,0,readers_count);
    std::vector<d::CacheKey> keys;
    for (unsigned i=0;i<=rounds*32;++i) keys.push_back({1,std::format("merge-race-{:05}.test",i),1});
    std::uint64_t now=1000;
    auto publish=[&](d::CacheKey const& key,std::uint32_t ttl) {
        auto token=cache.begin_query(key);
        return token && cache.publish(key,answer(key,ttl,42),now,*token).has_value();
    };
    if (!publish(keys[0],3600)) return 1;
    std::barrier gate(readers_count+1);
    std::atomic<bool> stop=false,failed=false;
    std::atomic<std::size_t> reads=0,hits=0;
    std::vector<std::thread> threads;
    for (unsigned id=0;id<readers_count;++id) threads.emplace_back([&,id] {
        auto reader=cache.reader(id); std::uint64_t rng=0x65326ba4ULL+id;
        gate.arrive_and_wait();
        while (!stop.load()) {
            rng^=rng<<13; rng^=rng>>7; rng^=rng<<17;
            auto const& key=keys[id%2 ? 0 : rng%keys.size()];
            auto result=cache.lookup(key,1000,reader);
            if (!result || (*result && ((**result).canonical_name!=key.name || (**result).addresses.size()!=1 ||
                (**result).addresses[0].bytes[0]!=42 || (**result).addresses[0].bytes[1]!=static_cast<std::uint8_t>(~42)))) failed=true;
            if (result && *result) ++hits;
            ++reads;
        }
    });
    gate.arrive_and_wait();
    unsigned merges=0;
    for (unsigned round=0;round<rounds && !failed.load();++round) {
        for (unsigned i=1;i<=32;++i)
            if (!publish(keys[round*32+i],i==16 ? 3600 : 1)) { failed=true; break; }
        auto before=cache.shape().pages;
        now+=2000;
        if (!publish(keys[round*32+16],3600)) failed=true;
        if (cache.shape().pages<before) ++merges;
    }
    stop=true;
    for (auto& thread:threads) thread.join();
    return failed || !reads || !hits || !merges ? 2 : 0;
}
int main() {
    if (auto result=differential()) { std::cerr<<"paged differential "<<result<<'\n'; return 1; }
    if (auto result=capacity_and_expiry()) { std::cerr<<"paged capacity "<<result<<'\n'; return 4; }
    if (auto result=concurrent()) { std::cerr<<"paged concurrent "<<result<<'\n'; return 2; }
    if (auto result=histories()) { std::cerr<<"paged histories "<<result<<'\n'; return 3; }
    if (auto result=fragmentation()) { std::cerr<<"paged fragmentation "<<result<<'\n'; return 5; }
    if (auto result=merge_with_reader()) { std::cerr<<"paged merge reader "<<result<<'\n'; return 6; }
    if (auto result=concurrent_merge()) { std::cerr<<"paged concurrent merge "<<result<<'\n'; return 7; }
    std::puts("paged prototype positive cache differential, concurrency and histories passed");
}
