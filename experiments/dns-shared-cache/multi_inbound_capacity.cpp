// Deterministic capacity trace; this is not a latency benchmark.
import std;
import dns.message;
import dns.cache;
#include "paged_semantic.hpp"

namespace d=dns;
enum class Mode { per_inbound,snapshot_256,lock_512 };
struct Counts { unsigned hits=0,misses=0; std::size_t entries=0; };

auto run(Mode mode,bool overlap) -> Counts {
    auto shared=mode!=Mode::per_inbound, snapshot=mode==Mode::snapshot_256;
    d::AddressCache global(snapshot ? 256 : 512,0,true,snapshot ? 2 : 0),first(256,0,true),second(256,0,true);
    std::optional<d::AddressCache::Reader> first_reader,second_reader;
    if (snapshot) { first_reader.emplace(global.reader(0)); second_reader.emplace(global.reader(1)); }
    d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=1;
    std::uint64_t now=1;
    Counts measured;
    for (unsigned round=0;round<3;++round) {
        for (unsigned index=0;index<256;++index) {
            for (unsigned inbound=0;inbound<2;++inbound) {
                auto name=std::format("{}-{:03}.example",overlap ? 0 : inbound,index);
                d::CacheKey key{1,name,1};
                auto& cache=shared ? global : inbound==0 ? first : second;
                auto cached=snapshot ? cache.lookup(key,now,inbound==0 ? *first_reader : *second_reader) : cache.lookup(key,now);
                if (!cached) throw std::runtime_error("lookup failed");
                if (*cached) {
                    if (round) ++measured.hits;
                } else {
                    if (round) ++measured.misses;
                    auto token=cache.begin_query(key);
                    d::AddressAnswer answer{name,{name},{address},3600};
                    if (!token || !cache.publish(key,std::move(answer),now,*token))
                        throw std::runtime_error("publication failed");
                }
                ++now;
            }
        }
    }
    measured.entries=shared ? global.size() : first.size()+second.size();
    return measured;
}

// A and B have one compatible DNS view but disjoint working sets. All TTLs
// remain valid throughout; B's shorter TTL makes it the first global victim.
struct FairnessCounts { unsigned a_old=0,a_new=0,b=0; std::size_t entries=0; };
template<class Publish,class Lookup>
auto fairness_trace(Publish&& publish,Lookup&& lookup) -> FairnessCounts {
    std::array<std::vector<d::CacheKey>,3> keys;
    for (unsigned group=0;group<keys.size();++group)
        for (unsigned index=0;index<256;++index)
            keys[group].push_back({1,std::format("fairness-{}-{:03}.example",group,index),1});
    for (auto const& key:keys[0]) publish(0,key,3600);
    for (auto const& key:keys[1]) publish(1,key,600);
    for (auto const& key:keys[2]) publish(0,key,7200);
    FairnessCounts result;
    for (auto const& key:keys[0]) result.a_old+=lookup(0,key);
    for (auto const& key:keys[1]) result.b+=lookup(1,key);
    for (auto const& key:keys[2]) result.a_new+=lookup(0,key);
    return result;
}

auto fairness(bool shared,bool paged) -> FairnessCounts {
    constexpr std::uint64_t now=1000;
    d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=1;
    auto make_answer=[&](d::CacheKey const& key,std::uint32_t ttl) {
        return d::AddressAnswer{key.name,{key.name},{address},ttl};
    };
    if (paged) {
        dns_hp_experiment::PagedSemanticCache cache(512,0,2);
        auto first=cache.reader(0),second=cache.reader(1);
        auto result=fairness_trace([&](unsigned,d::CacheKey const& key,std::uint32_t ttl) {
            auto token=cache.begin_query(key);
            if (!token || !cache.publish(key,make_answer(key,ttl),now,*token)) throw std::runtime_error("paged publication failed");
        },[&](unsigned inbound,d::CacheKey const& key) {
            auto value=cache.lookup(key,now,inbound==0 ? first : second);
            if (!value) throw std::runtime_error("paged lookup failed");
            return value->has_value();
        });
        result.entries=cache.size();
        return result;
    }
    d::AddressCache global(512,0,true),first(256,0,true),second(256,0,true);
    auto select=[&](unsigned inbound) -> d::AddressCache& { return shared ? global : inbound==0 ? first : second; };
    auto result=fairness_trace([&](unsigned inbound,d::CacheKey const& key,std::uint32_t ttl) {
        auto& cache=select(inbound); auto token=cache.begin_query(key);
        if (!token || !cache.publish(key,make_answer(key,ttl),now,*token)) throw std::runtime_error("publication failed");
    },[&](unsigned inbound,d::CacheKey const& key) {
        auto value=select(inbound).lookup(key,now);
        if (!value) throw std::runtime_error("lookup failed");
        return value->has_value();
    });
    result.entries=shared ? global.size() : first.size()+second.size();
    return result;
}

int main() {
    for (bool overlap:{true,false}) {
        for (auto mode:{Mode::per_inbound,Mode::snapshot_256,Mode::lock_512}) {
            auto result=run(mode,overlap);
            auto label=mode==Mode::per_inbound ? "per-inbound 256" : mode==Mode::snapshot_256 ? "shared snapshot 256" : "shared lock 512";
            std::println("{},{}: {} hits, {} misses, {} entries",overlap ? "overlap" : "disjoint",label,result.hits,result.misses,result.entries);
            auto expected_misses=!overlap && mode==Mode::snapshot_256 ? 1024U : 0U;
            if (result.misses!=expected_misses || result.hits+result.misses!=1024) return 1;
        }
    }
    for (unsigned mode=0;mode<3;++mode) {
        auto result=fairness(mode!=0,mode==2);
        auto label=mode==0 ? "per-inbound 256" : mode==1 ? "shared lock 512" : "shared paged 512";
        std::println("fairness,{}: A old {}, A new {}, B {}, {} entries",label,result.a_old,result.a_new,result.b,result.entries);
        if (result.a_old!=(mode ? 256U : 0U) || result.a_new!=256 || result.b!=(mode ? 0U : 256U) || result.entries!=512) return 2;
    }
}
