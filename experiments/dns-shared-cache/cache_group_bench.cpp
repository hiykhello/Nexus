#include <pthread.h>
#include <sched.h>
#include "bounded_table.hpp"
import std;
import dns.cache;
import dns.message;
#include "snapshot_cache.hpp"
#include "paged_snapshot.hpp"
#include "paged_semantic.hpp"
#include "../../src/dns-shared/group_snapshot.hpp"

namespace d=dns;
namespace experiment=dns_hp_experiment;
using Clock=std::chrono::steady_clock;
using Ns=std::chrono::nanoseconds;
struct Measurements {
    std::size_t completed=0,hits=0;
    std::uint64_t checksum=0;
    std::vector<long long> service,lag;
};
auto number(std::string_view value,int maximum) -> int {
    int result=0; auto [end,error]=std::from_chars(value.data(),value.data()+value.size(),result);
    if (error!=std::errc{} || end!=value.data()+value.size() || result<=0 || result>maximum)
        throw std::invalid_argument("invalid number");
    return result;
}
auto cpus(std::string_view value,std::size_t count) -> std::vector<int> {
    cpu_set_t available;
    if (sched_getaffinity(0,sizeof(available),&available)) throw std::runtime_error("cannot read affinity");
    std::vector<int> result;
    while (!value.empty()) {
        auto comma=value.find(','); auto part=value.substr(0,comma);
        int cpu=-1; auto [end,error]=std::from_chars(part.data(),part.data()+part.size(),cpu);
        if (error!=std::errc{} || end!=part.data()+part.size() || cpu<0 || cpu>=CPU_SETSIZE ||
            !CPU_ISSET(cpu,&available) || std::ranges::find(result,cpu)!=result.end())
            throw std::invalid_argument("invalid CPU list");
        result.push_back(cpu);
        if (comma==std::string_view::npos) break;
        value.remove_prefix(comma+1);
        if (value.empty()) throw std::invalid_argument("empty CPU");
    }
    if (result.size()!=count) throw std::invalid_argument("one CPU per reader and writer required");
    return result;
}
void pin(int cpu) {
    cpu_set_t set; CPU_ZERO(&set); CPU_SET(cpu,&set);
    if (pthread_setaffinity_np(pthread_self(),sizeof(set),&set)) std::abort();
}
template<class F>
void generate(Clock::time_point start,std::size_t offered,Ns interval,std::size_t sample,Measurements& out,F&& operation) {
    out.service.reserve(offered/sample+1); out.lag.reserve(offered/sample+1);
    std::size_t slot=0;
    while (slot<offered) {
        auto scheduled=start+interval*slot;
        auto now=Clock::now();
        while (now<scheduled) { std::this_thread::yield(); now=Clock::now(); }
        slot+=std::min(static_cast<std::size_t>((now-scheduled)/interval),offered-slot);
        if (slot==offered) break;
        scheduled=start+interval*slot;
        auto before=Clock::now(); out.checksum+=operation(slot); auto after=Clock::now();
        if (slot%sample==0) {
            out.service.push_back(std::chrono::duration_cast<Ns>(after-before).count());
            out.lag.push_back(std::chrono::duration_cast<Ns>(before-scheduled).count());
        }
        ++out.completed; ++slot;
    }
}
auto quantile(std::vector<long long>& values,double p) -> long long {
    if (values.empty()) return 0;
    std::sort(values.begin(),values.end()); return values[static_cast<std::size_t>(p*(values.size()-1))];
}
auto memory_kib(std::string_view field) -> std::size_t {
    std::ifstream status("/proc/self/status"); std::string line;
    while (std::getline(status,line)) if (line.starts_with(field)) {
        auto first=line.find_first_of("0123456789");
        return first==std::string::npos ? 0 : std::stoull(line.substr(first));
    }
    return 0;
}
auto answer(d::CacheKey const& key,std::uint64_t revision) -> d::AddressAnswer {
    d::Address address{}; address.size=4; address.bytes[0]=static_cast<std::uint8_t>(revision);
    address.bytes[1]=static_cast<std::uint8_t>(~address.bytes[0]);
    return {key.name,{key.name},{address},3600};
}
int main(int argc,char** argv) {
    if (argc!=9 && argc!=10) {
        std::cerr<<"usage: cache_group_bench per-inbound|global|paged|paged-semantic|group hot|uniform overlap|disjoint readers read-rate write-rate seconds cpu-list [groups]\n";
        return 2;
    }
    try {
        std::string mode=argv[1],distribution=argv[2],overlap=argv[3];
        auto readers=number(argv[4],16),read_rate=number(argv[5],1000000),write_rate=number(argv[6],1000000),seconds=number(argv[7],60);
        auto group_count=argc==10 ? number(argv[9],17) : 2;
        if ((mode!="per-inbound" && mode!="global" && mode!="paged" && mode!="paged-semantic" && mode!="group") || (distribution!="hot" && distribution!="uniform") ||
            (overlap!="overlap" && overlap!="disjoint") || ((mode=="global" || mode=="paged") && group_count>2))
            throw std::invalid_argument("invalid mode, group count or distribution");
        auto pinned=cpus(argv[8],readers+1);
        auto read_interval=Ns(1000000000LL/read_rate),write_interval=Ns(1000000000LL/write_rate);
        auto read_offered=static_cast<std::size_t>(seconds)*1000000000LL/read_interval.count();
        auto write_offered=static_cast<std::size_t>(seconds)*1000000000LL/write_interval.count();
        std::vector<std::vector<d::CacheKey>> keys(group_count);
        for (int group=0;group<group_count;++group) for (unsigned i=0;i<256;++i)
            keys[group].push_back({1,std::format("host-{}-{:03}.example.test",overlap=="overlap" ? 0 : group,i),1});
        std::vector<std::unique_ptr<experiment::OrderedSnapshotCache>> groups(group_count);
        std::unique_ptr<experiment::OrderedSnapshotCache512> global;
        std::unique_ptr<experiment::PagedSnapshotPrototype> paged;
        std::unique_ptr<experiment::PagedSemanticCache> paged_semantic;
        std::unique_ptr<experiment::FullPagedSemanticCache> full_paged;
        std::unique_ptr<experiment::GroupSnapshot> grouped;
        if (mode=="global") global=std::make_unique<experiment::OrderedSnapshotCache512>(512,0,readers);
        else if (mode=="paged") paged=std::make_unique<experiment::PagedSnapshotPrototype>(512,0,readers);
        else if (mode=="paged-semantic" && group_count<=2) paged_semantic=std::make_unique<experiment::PagedSemanticCache>(group_count*256,0,readers);
        else if (mode=="paged-semantic") full_paged=std::make_unique<experiment::FullPagedSemanticCache>(group_count*256,0,readers);
        else if (mode=="group") { std::vector<std::size_t> capacities(group_count,256); grouped=std::make_unique<experiment::GroupSnapshot>(capacities,readers); }
        else for (int group=0;group<group_count;++group) {
            auto slots=group<readers ? (readers-1-group)/group_count+1 : 0;
            groups[group]=std::make_unique<experiment::OrderedSnapshotCache>(256,0,slots);
        }
        auto publish_one=[](auto& cache,d::CacheKey const& key,std::uint64_t revision) {
            auto token=cache.begin_query(key);
            return token && cache.publish(key,answer(key,revision),1000,*token).has_value();
        };
        auto publish=[&](unsigned group,d::CacheKey const& key,std::uint64_t revision) {
            if (grouped) {
                auto token=grouped->begin_query(group,key);
                return token && grouped->publish(group,key,answer(key,revision),1000,*token).has_value();
            }
            return global ? publish_one(*global,key,revision) : paged ? publish_one(*paged,key,revision) :
                   paged_semantic ? publish_one(*paged_semantic,key,revision) : full_paged ? publish_one(*full_paged,key,revision) :
                   publish_one(*groups[group],key,revision);
        };
        for (int group=0;group<group_count;++group) for (auto const& key:keys[group]) if (!publish(group,key,1)) std::abort();
        auto warm_rss=memory_kib("VmRSS:");
        Clock::time_point start;
        std::barrier gate(readers+2,[&]() noexcept { start=Clock::now()+std::chrono::milliseconds(100); });
        std::vector<Measurements> reads(readers); Measurements writes;
        std::vector<std::thread> threads;
        for (int t=0;t<readers;++t) threads.emplace_back([&,t] {
            pin(pinned[t]); auto group=static_cast<unsigned>(t%group_count);
            auto work=[&](auto& cache,std::size_t slot) {
                auto reader=cache.reader(slot); std::uint64_t rng=0x9e3779b97f4a7c15ULL+t;
                gate.arrive_and_wait();
                generate(start,read_offered,read_interval,100,reads[t],[&](std::size_t) {
                    rng^=rng<<13; rng^=rng>>7; rng^=rng<<17;
                    auto const& key=keys[group][distribution=="hot" ? 0 : rng%256];
                    auto result=cache.lookup(key,1000,reader);
                    if (!result || !*result || (**result).canonical_name!=key.name || (**result).addresses.size()!=1 ||
                        (**result).addresses[0].bytes[1]!=static_cast<std::uint8_t>(~(**result).addresses[0].bytes[0])) std::abort();
                    ++reads[t].hits; return (**result).canonical_name.size();
                });
            };
            if (global) work(*global,t); else if (paged) work(*paged,t); else if (paged_semantic) work(*paged_semantic,t);
            else if (full_paged) work(*full_paged,t); else if (!grouped) work(*groups[group],t/group_count);
            else {
                auto reader=grouped->reader(t); std::uint64_t rng=0x9e3779b97f4a7c15ULL+t; gate.arrive_and_wait();
                generate(start,read_offered,read_interval,100,reads[t],[&](std::size_t) {
                    rng^=rng<<13; rng^=rng>>7; rng^=rng<<17;
                    auto const& key=keys[group][distribution=="hot" ? 0 : rng%256];
                    auto result=grouped->lookup(group,key,1000,reader);
                    if (!result || !*result || (**result).canonical_name!=key.name || (**result).addresses.size()!=1 ||
                        (**result).addresses[0].bytes[1]!=static_cast<std::uint8_t>(~(**result).addresses[0].bytes[0])) std::abort();
                    ++reads[t].hits; return (**result).canonical_name.size();
                });
            }
        });
        std::thread writer([&] {
            pin(pinned[readers]); gate.arrive_and_wait();
            generate(start,write_offered,write_interval,1,writes,[&](std::size_t slot) {
                auto group=static_cast<unsigned>(slot%group_count);
                auto const& key=keys[group][distribution=="hot" ? 0 : (slot/group_count)%256];
                if (!publish(group,key,slot+2)) std::abort(); return std::uint64_t{1};
            });
        });
        gate.arrive_and_wait(); for (auto& thread:threads) thread.join(); writer.join();
        Measurements total;
        for (auto& item:reads) {
            total.completed+=item.completed; total.hits+=item.hits; total.checksum+=item.checksum;
            total.service.insert(total.service.end(),item.service.begin(),item.service.end());
            total.lag.insert(total.lag.end(),item.lag.begin(),item.lag.end());
        }
        auto offered=read_offered*readers;
        std::cout<<mode<<','<<distribution<<','<<overlap<<','<<readers<<','<<read_rate<<','<<write_rate<<','<<seconds<<','
                 <<offered<<','<<total.completed<<','<<offered-total.completed<<','<<quantile(total.service,.5)<<','
                 <<quantile(total.service,.99)<<','<<quantile(total.service,.999)<<','<<quantile(total.lag,.99)<<','
                 <<write_offered<<','<<writes.completed<<','<<write_offered-writes.completed<<','<<quantile(writes.service,.5)<<','
                 <<quantile(writes.service,.99)<<','<<quantile(writes.service,.999)<<','<<quantile(writes.lag,.99)<<','
                 <<warm_rss<<','<<memory_kib("VmHWM:")<<','<<total.hits<<','<<total.checksum<<','<<group_count<<'\n';
    } catch (std::exception const& error) { std::cerr<<error.what()<<'\n'; return 2; }
}
