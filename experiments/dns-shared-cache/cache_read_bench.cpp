#include "bounded_table.hpp"
import std;
import dns.cache;
import dns.message;
#include "actual_cache_types.hpp"
#include "semantic_cache.hpp"
#include "snapshot_cache.hpp"

namespace d=dns;
using Clock=std::chrono::steady_clock;
struct Shard {
    std::mutex mutex;
    d::AddressCache cache{16};
};
using BoundedTable=dns_hp_experiment::ActualTable;
using CacheValue=dns_hp_experiment::ActualValue;

auto main(int argc,char** argv) -> int {
    if (argc!=4) { std::cerr<<"usage: cache_read_bench per-worker|sharded|shared|bounded|semantic|snapshot|ordered|module threads hot|uniform|miss|collision|collision-miss|prefix|prefix-miss\n"; return 2; }
    std::string mode=argv[1],distribution=argv[3];
    int threads=std::atoi(argv[2]);
    if ((mode!="per-worker" && mode!="sharded" && mode!="shared" && mode!="bounded" && mode!="semantic" && mode!="snapshot" && mode!="ordered" && mode!="module") || threads<1 || threads>128 ||
        (distribution!="hot" && distribution!="uniform" && distribution!="miss" && distribution!="collision" && distribution!="collision-miss" && distribution!="prefix" && distribution!="prefix-miss")) return 2;
    constexpr std::size_t count=256,iterations=50000,sample_every=100;
    std::vector<d::CacheKey> keys;
    d::CacheKey missing{1,"never-present.example.test",1};
    auto miss=distribution=="miss" || distribution=="collision-miss" || distribution=="prefix-miss";
    if (distribution=="collision" || distribution=="collision-miss") {
        // The experimental snapshot uses an unkeyed hash and 512 index slots.
        // Generate one extra same-bucket key for the absent lookup case.
        for (std::size_t i=0;keys.size()<count+1;++i) {
            d::CacheKey key{1,"collision-"+std::to_string(i)+".example.test",1};
            if (dns_hp_experiment::ActualKeyHash{}(key)%512==511) keys.push_back(std::move(key));
        }
        missing=std::move(keys.back()); keys.pop_back();
    } else if (distribution=="prefix" || distribution=="prefix-miss") {
        auto prefix=std::string(63,'a')+"."+std::string(63,'b')+"."+std::string(63,'c')+".";
        for (std::size_t i=0;i<count;++i) keys.push_back({1,prefix+"host-"+std::to_string(i)+".test",1});
        missing.name=prefix+"never-present.test";
    } else for (std::size_t i=0;i<count;++i) keys.push_back({1,"host-"+std::to_string(i)+".example.test",1});
    std::vector<std::unique_ptr<d::AddressCache>> local;
    if (mode=="per-worker") for (int i=0;i<threads;++i) local.push_back(std::make_unique<d::AddressCache>(count));
    std::array<Shard,16> shards;
    d::AddressCache shared(count,0,true);
    std::unique_ptr<BoundedTable> bounded;
    std::unique_ptr<dns_hp_experiment::SemanticCache> semantic;
    std::unique_ptr<dns_hp_experiment::SnapshotCache> snapshot;
    std::unique_ptr<dns_hp_experiment::OrderedSnapshotCache> ordered;
    std::unique_ptr<d::AddressCache> module;
    if (mode=="bounded") bounded=std::make_unique<BoundedTable>(threads);
    if (mode=="semantic") semantic=std::make_unique<dns_hp_experiment::SemanticCache>(count,0,threads);
    if (mode=="snapshot") snapshot=std::make_unique<dns_hp_experiment::SnapshotCache>(count,0,threads);
    if (mode=="ordered") ordered=std::make_unique<dns_hp_experiment::OrderedSnapshotCache>(count,0,threads);
    if (mode=="module") module=std::make_unique<d::AddressCache>(count,0,true,threads);
    auto insert=[](d::AddressCache& cache,d::CacheKey const& key) {
        d::Address address{}; address.size=4; address.bytes[0]=192; address.bytes[3]=10;
        d::AddressAnswer answer{key.name,{key.name},{address},3600};
        auto token=cache.begin_query(key);
        if (!token || !cache.publish(key,std::move(answer),1000,*token)) std::abort();
    };
    for (std::size_t i=0;i<count;++i) {
        if (mode=="per-worker") for (auto& cache:local) insert(*cache,keys[i]);
        else if (mode=="sharded") insert(shards[i%shards.size()].cache,keys[i]);
        else if (mode=="shared") insert(shared,keys[i]);
        else if (mode=="bounded") {
            d::Address address{}; address.size=4; address.bytes[0]=192; address.bytes[3]=10;
            d::AddressAnswer answer{keys[i].name,{keys[i].name},{address},3600};
            if (!bounded->put(keys[i],{std::move(answer),3601000})) std::abort();
        } else if (mode=="semantic") {
            d::Address address{}; address.size=4; address.bytes[0]=192; address.bytes[3]=10;
            d::AddressAnswer answer{keys[i].name,{keys[i].name},{address},3600};
            auto token=semantic->begin_query(keys[i]);
            if (!token || !semantic->publish(keys[i],std::move(answer),1000,*token)) std::abort();
        } else if (snapshot) {
            d::Address address{}; address.size=4; address.bytes[0]=192; address.bytes[3]=10;
            d::AddressAnswer answer{keys[i].name,{keys[i].name},{address},3600};
            auto token=snapshot->begin_query(keys[i]);
            if (!token || !snapshot->publish(keys[i],std::move(answer),1000,*token)) std::abort();
        } else if (ordered) {
            d::Address address{}; address.size=4; address.bytes[0]=192; address.bytes[3]=10;
            d::AddressAnswer answer{keys[i].name,{keys[i].name},{address},3600};
            auto token=ordered->begin_query(keys[i]);
            if (!token || !ordered->publish(keys[i],std::move(answer),1000,*token)) std::abort();
        } else insert(*module,keys[i]);
    }
    std::barrier gate(threads+1);
    std::vector<std::thread> workers;
    std::vector<std::vector<long long>> samples(threads);
    std::vector<std::size_t> sums(threads);
    for (int t=0;t<threads;++t) workers.emplace_back([&,t] {
        std::optional<BoundedTable::Reader> reader;
        std::optional<dns_hp_experiment::SemanticCache::Reader> semantic_reader;
        std::optional<dns_hp_experiment::SnapshotCache::Reader> snapshot_reader;
        std::optional<dns_hp_experiment::OrderedSnapshotCache::Reader> ordered_reader;
        std::optional<d::AddressCache::Reader> module_reader;
        if (bounded) reader.emplace(bounded->reader(t));
        if (semantic) semantic_reader.emplace(semantic->reader(t));
        if (snapshot) snapshot_reader.emplace(snapshot->reader(t));
        if (ordered) ordered_reader.emplace(ordered->reader(t));
        if (module) module_reader.emplace(module->reader(t));
        auto& sample=samples[t]; sample.reserve(iterations/sample_every);
        std::uint64_t rng=0x9e3779b97f4a7c15ULL+static_cast<unsigned>(t);
        std::size_t sum=0;
        gate.arrive_and_wait();
        for (std::size_t i=0;i<iterations;++i) {
            rng^=rng<<13; rng^=rng>>7; rng^=rng<<17;
            auto index=distribution=="hot" ? 0 : rng%count;
            auto const& key=miss ? missing : keys[index];
            auto start=i%sample_every==0 ? Clock::now() : Clock::time_point{};
            auto lookup=[&](d::AddressCache& cache) {
                auto value=cache.lookup(key,1000);
                if (!value || (value->has_value()==miss)) std::abort();
                return *value ? (**value).canonical_name.size() : std::size_t(1);
            };
            if (mode=="per-worker") sum+=lookup(*local[t]);
            else if (mode=="shared") sum+=lookup(shared);
            else if (mode=="bounded") {
                auto normalized=key;
                if (!d::canonicalize_name(normalized.name)) std::abort();
                std::optional<d::AddressAnswer> answer;
                (void)reader->visit(normalized,[&](CacheValue const& value) {
                    if (value.expires<=1000 || (value.expires-1000)/1000==0) return;
                    answer=value.answer;
                    answer->ttl=static_cast<std::uint32_t>((value.expires-1000)/1000);
                });
                if (answer.has_value()==miss) std::abort();
                sum+=answer ? answer->canonical_name.size() : std::size_t(1);
            }
            else if (mode=="semantic") {
                auto value=semantic->lookup(key,1000,*semantic_reader);
                if (!value || (value->has_value()==miss)) std::abort();
                sum+=*value ? (**value).canonical_name.size() : std::size_t(1);
            }
            else if (mode=="snapshot") {
                auto value=snapshot->lookup(key,1000,*snapshot_reader);
                if (!value || (value->has_value()==miss)) std::abort();
                sum+=*value ? (**value).canonical_name.size() : std::size_t(1);
            }
            else if (mode=="ordered") {
                auto value=ordered->lookup(key,1000,*ordered_reader);
                if (!value || (value->has_value()==miss)) std::abort();
                sum+=*value ? (**value).canonical_name.size() : std::size_t(1);
            }
            else if (mode=="module") {
                auto value=module->lookup(key,1000,*module_reader);
                if (!value || (value->has_value()==miss)) std::abort();
                sum+=*value ? (**value).canonical_name.size() : std::size_t(1);
            }
            else {
                auto& shard=shards[index%shards.size()];
                std::lock_guard lock(shard.mutex); sum+=lookup(shard.cache);
            }
            if (i%sample_every==0) sample.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now()-start).count());
        }
        sums[t]=sum;
    });
    auto start=Clock::now(); gate.arrive_and_wait();
    for (auto& thread:workers) thread.join();
    auto elapsed=std::chrono::duration<double>(Clock::now()-start).count();
    std::vector<long long> combined;
    for (auto& sample:samples) combined.insert(combined.end(),sample.begin(),sample.end());
    std::sort(combined.begin(),combined.end());
    auto quantile=[&](double q) { return combined[static_cast<std::size_t>(q*(combined.size()-1))]; };
    std::size_t checksum=0; for (auto sum:sums) checksum+=sum;
    std::cout<<mode<<','<<threads<<','<<distribution<<','<<(threads*iterations/elapsed)<<','
             <<quantile(.5)<<','<<quantile(.99)<<','<<quantile(.999)<<','<<checksum<<'\n';
}
