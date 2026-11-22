#include "bounded_table.hpp"
import std;
import dns.cache;
import dns.message;
#include "semantic_cache.hpp"
#include "snapshot_cache.hpp"

namespace d=dns;
using Clock=std::chrono::steady_clock;
auto answer(d::CacheKey const& key,std::uint64_t revision) -> d::AddressAnswer {
    d::Address address{}; address.size=4; address.bytes[0]=static_cast<std::uint8_t>(revision);
    address.bytes[1]=static_cast<std::uint8_t>(~address.bytes[0]);
    return {key.name,{key.name},{address},3600};
}
auto main(int argc,char** argv) -> int {
    if (argc!=4 && argc!=5) { std::cerr<<"usage: cache_mixed_bench shared|semantic|snapshot threads hot|uniform [writes-per-second]\n"; return 2; }
    std::string mode=argv[1],distribution=argv[3];
    int threads=std::atoi(argv[2]);
    int rate=argc==5 ? std::atoi(argv[4]) : 0;
    if ((mode!="shared" && mode!="semantic" && mode!="snapshot") || threads<1 || threads>16 ||
        (distribution!="hot" && distribution!="uniform") || rate<0 || rate>1000000 || (argc==5 && !rate)) return 2;
    std::size_t iterations=rate ? 200000 : 50000;
    constexpr std::size_t sample_every=100,updates=20000;
    std::vector<d::CacheKey> keys;
    for (unsigned i=0;i<256;++i) keys.push_back({1,"host-"+std::to_string(i)+".example.test",1});
    std::unique_ptr<d::AddressCache> shared;
    std::unique_ptr<dns_hp_experiment::SemanticCache> semantic;
    std::unique_ptr<dns_hp_experiment::SnapshotCache> snapshot;
    if (mode=="shared") shared=std::make_unique<d::AddressCache>(256,0,true);
    else if (mode=="semantic") semantic=std::make_unique<dns_hp_experiment::SemanticCache>(256,0,threads);
    else snapshot=std::make_unique<dns_hp_experiment::SnapshotCache>(256,0,threads);
    auto publish=[&](d::CacheKey const& key,std::uint64_t revision) {
        if (shared) {
            auto token=shared->begin_query(key);
            return token && shared->publish(key,answer(key,revision),1000,*token).has_value();
        }
        if (semantic) {
            auto token=semantic->begin_query(key);
            return token && semantic->publish(key,answer(key,revision),1000,*token).has_value();
        }
        auto token=snapshot->begin_query(key);
        return token && snapshot->publish(key,answer(key,revision),1000,*token).has_value();
    };
    for (auto const& key:keys) if (!publish(key,1)) std::abort();
    std::barrier gate(threads+2);
    std::vector<std::thread> readers;
    std::vector<std::vector<long long>> samples(threads);
    std::vector<std::uint64_t> sums(threads);
    std::vector<long long> writes; writes.reserve(updates);
    Clock::time_point writer_finished;
    std::atomic<bool> readers_done=false;
    for (int t=0;t<threads;++t) readers.emplace_back([&,t] {
        std::optional<dns_hp_experiment::SemanticCache::Reader> reader;
        std::optional<dns_hp_experiment::SnapshotCache::Reader> snapshot_reader;
        if (semantic) reader.emplace(semantic->reader(t));
        if (snapshot) snapshot_reader.emplace(snapshot->reader(t));
        auto& timings=samples[t]; timings.reserve(iterations/sample_every);
        std::uint64_t rng=0x9e3779b97f4a7c15ULL+t,sum=0;
        gate.arrive_and_wait();
        for (std::size_t i=0;i<iterations;++i) {
            rng^=rng<<13; rng^=rng>>7; rng^=rng<<17;
            auto const& key=keys[distribution=="hot" ? 0 : rng%keys.size()];
            auto start=i%sample_every==0 ? Clock::now() : Clock::time_point{};
            auto result=shared ? shared->lookup(key,1000) : semantic ? semantic->lookup(key,1000,*reader) : snapshot->lookup(key,1000,*snapshot_reader);
            if (!result || !*result || (**result).canonical_name!=key.name || (**result).addresses.size()!=1 ||
                (**result).addresses[0].bytes[1]!=static_cast<std::uint8_t>(~(**result).addresses[0].bytes[0])) std::abort();
            sum+=(**result).canonical_name.size();
            if (i%sample_every==0) timings.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now()-start).count());
        }
        sums[t]=sum;
    });
    std::thread writer([&] {
        gate.arrive_and_wait();
        auto next=Clock::now();
        auto interval=std::chrono::nanoseconds(rate ? 1000000000LL/rate : 0);
        for (std::size_t i=0;rate ? !readers_done.load(std::memory_order_relaxed) : i<updates;++i) {
            if (rate) {
                while (!readers_done.load(std::memory_order_relaxed) && Clock::now()<next) std::this_thread::yield();
                if (readers_done.load(std::memory_order_relaxed)) break;
                auto now=Clock::now();
                next=now>next+interval*2 ? now+interval : next+interval;
            }
            auto const& key=keys[distribution=="hot" ? 0 : i%keys.size()];
            auto start=Clock::now();
            if (!publish(key,i+2)) std::abort();
            writes.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now()-start).count());
        }
        writer_finished=Clock::now();
    });
    auto start=Clock::now(); gate.arrive_and_wait();
    for (auto& reader:readers) reader.join();
    auto readers_finished=Clock::now(); readers_done=true; writer.join();
    auto elapsed=std::chrono::duration<double>(readers_finished-start).count();
    std::vector<long long> combined;
    for (auto& sample:samples) combined.insert(combined.end(),sample.begin(),sample.end());
    std::sort(combined.begin(),combined.end()); std::sort(writes.begin(),writes.end());
    auto q=[](auto const& values,double p) { return values.empty() ? 0LL : values[static_cast<std::size_t>(p*(values.size()-1))]; };
    std::uint64_t checksum=0; for (auto value:sums) checksum+=value;
    std::cout<<mode<<','<<threads<<','<<distribution<<','<<threads*iterations/elapsed<<','
             <<q(combined,.5)<<','<<q(combined,.99)<<','<<q(combined,.999)<<','
             <<q(writes,.99)<<','<<q(writes,.999)<<','
             <<std::chrono::duration<double>(writer_finished-start).count()/elapsed<<','<<writes.size()/elapsed<<','<<writes.size()<<','<<checksum<<'\n';
}
