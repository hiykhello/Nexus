// Service-time microbenchmark, not a production or offered-load benchmark.
#include <cstdio>
import std;
import dns.message;
import dns.cache;
#include "../../src/dns-shared/group_snapshot.hpp"

namespace d=dns;
using Cache=dns_hp_experiment::GroupSnapshot;
using Clock=std::chrono::steady_clock;
auto key(unsigned group,unsigned number) -> d::CacheKey {
    return {1,std::format("churn-{:02}-{:06}.example.test",group,number),1};
}
auto answer(d::CacheKey const& name) -> d::AddressAnswer {
    d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=1;
    return {name.name,{name.name},{address},3600};
}
auto write(Cache& cache,unsigned group,d::CacheKey const& name) -> void {
    auto token=cache.begin_query(group,name);
    if (!token || !cache.publish(group,name,answer(name),1000,*token)) throw std::runtime_error("publication failed");
}
auto percentile(std::vector<std::int64_t>& values,double p) -> std::int64_t {
    std::sort(values.begin(),values.end());
    return values[static_cast<std::size_t>((values.size()-1)*p)];
}
auto main(int argc,char** argv) -> int {
    if (argc!=4) return 2;
    try {
        auto parse=[](char const* text) {
            std::string_view input(text); unsigned value=0;
            auto [end,error]=std::from_chars(input.data(),input.data()+input.size(),value);
            if (error!=std::errc{} || end!=input.data()+input.size()) throw std::invalid_argument("invalid integer");
            return value;
        };
        auto groups=parse(argv[1]),entries=parse(argv[2]),iterations=parse(argv[3]);
        if (!groups || groups>17 || !entries || entries>1024 || groups*entries>8192 || !iterations || iterations>100000)
            throw std::invalid_argument("invalid bounds");
        std::vector<std::size_t> capacities(groups,entries);
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
        capacities.assign(groups,1); Cache cache(capacities,Cache::SharedCapacity{groups*entries},1);
        constexpr std::string_view variant="shared";
#else
        Cache cache(capacities,1);
        constexpr std::string_view variant="fixed";
#endif
        for (unsigned group=0;group<groups;++group)
            for (unsigned i=0;i<entries;++i) write(cache,group,key(group,i));
        std::vector<d::CacheKey> changes; changes.reserve(iterations);
        for (unsigned i=0;i<iterations;++i) changes.push_back(key(groups,i));
        std::vector<std::int64_t> times; times.reserve(iterations);
        auto started=Clock::now();
        for (auto const& name:changes) {
            auto before=Clock::now(); write(cache,0,name); auto after=Clock::now();
            times.push_back(std::chrono::duration_cast<std::chrono::nanoseconds>(after-before).count());
        }
        auto elapsed=std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now()-started).count();
        for (unsigned group=0;group<groups;++group)
            if (cache.size(group)!=entries) throw std::runtime_error("group membership count changed");
        std::cout<<variant<<','<<groups<<','<<entries<<','<<iterations<<','<<elapsed<<','
                 <<percentile(times,.5)<<','<<percentile(times,.99)<<','<<percentile(times,.999)<<','
                 <<cache.charged_bytes()<<','<<cache.peak_charged_bytes()<<'\n';
    } catch (std::exception const& error) { std::fprintf(stderr,"churn: %s\n",error.what()); return 1; }
}
