#include <malloc.h>
import std;
import dns.message;
import dns.cache;
#include "../../src/dns-shared/group_snapshot.hpp"

namespace d=dns;
using GroupCache=dns_hp_experiment::GroupSnapshot;
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
constexpr unsigned group_capacity=8192;
#elif defined(DNS_GROUP_CAPACITY_1024_EXPERIMENT)
constexpr unsigned group_capacity=1024;
#else
constexpr unsigned group_capacity=256;
#endif
struct Memory { std::int64_t allocated=0,rss=0; };
auto memory() -> Memory {
    std::ifstream input("/proc/self/smaps_rollup"); std::string line; std::int64_t rss=-1;
    while (std::getline(input,line)) if (line.starts_with("Rss:")) {
        auto first=line.find_first_of("0123456789");
        if (first==std::string::npos || std::from_chars(line.data()+first,line.data()+line.size(),rss).ec!=std::errc{})
            throw std::runtime_error("invalid RSS");
        rss*=1024; break;
    }
    if (rss<0) throw std::runtime_error("missing RSS");
    auto info=mallinfo2();
    return {static_cast<std::int64_t>(info.uordblks)+static_cast<std::int64_t>(info.hblkhd),rss};
}
auto answer(d::CacheKey const& key) -> d::AddressAnswer {
    d::Address address{}; address.size=4; address.bytes[0]=127; address.bytes[3]=1;
    return {key.name,{key.name},{address},3600};
}
int main(int argc,char** argv) {
    if (argc<5 || argc>8) {
        std::cerr<<"usage: group_memory_bench separate|group overlap|disjoint readers-per-inbound entries-per-group [groups [readers [shared-limit]]]\n";
        return 2;
    }
    try {
        std::string_view mode=argv[1],layout=argv[2];
        auto parse=[](char const* text) {
            auto length=std::char_traits<char>::length(text); unsigned value=0;
            auto [end,error]=std::from_chars(text,text+length,value);
            if (error!=std::errc{} || end!=text+length) throw std::invalid_argument("invalid number");
            return value;
        };
        auto per_inbound=parse(argv[3]),entries=parse(argv[4]);
        auto groups=argc>=6 ? parse(argv[5]) : 17u;
        auto reader_count=argc>=7 ? parse(argv[6]) : argc==6 ? groups*per_inbound : 16*per_inbound+1;
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
        auto shared_limit=argc==8 ? parse(argv[7]) : std::max(entries*groups,groups);
#else
        if (argc==8) throw std::invalid_argument("shared limit requires shared-capacity experiment");
#endif
        if ((mode!="separate" && mode!="group") || (layout!="overlap" && layout!="disjoint") ||
            per_inbound<1 || per_inbound>16 || groups<1 || groups>17 || reader_count<1 || reader_count>257 ||
            entries>group_capacity || (mode=="separate" && (entries>256 || argc>5)))
            throw std::invalid_argument("invalid parameters");
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
        if (mode!="group" || shared_limit>group_capacity || shared_limit<entries*groups || shared_limit<groups)
            throw std::invalid_argument("invalid shared capacity");
#endif
        std::array<std::vector<d::CacheKey>,17> keys;
        for (unsigned group=0;group<groups;++group) for (unsigned i=0;i<entries;++i)
            keys[group].push_back({1,std::format("memory-group-{}-{:04}.example.test",layout=="overlap" ? 0 : group,i),1});
        auto before=memory();
        std::array<std::unique_ptr<d::AddressCache>,17> separate;
        std::unique_ptr<GroupCache> grouped;
        if (mode=="group") {
            std::array<std::size_t,17> capacities; capacities.fill(group_capacity);
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
            capacities.fill(1);
            grouped=std::make_unique<GroupCache>(std::span(capacities).first(groups),GroupCache::SharedCapacity{shared_limit},reader_count);
#else
            grouped=std::make_unique<GroupCache>(std::span(capacities).first(groups),reader_count);
#endif
            auto reader=grouped->reader(0);
            for (unsigned group=0;group<groups;++group) for (auto const& key:keys[group]) {
                if (group && layout=="overlap") {
                    auto cached=grouped->lookup(group,key,1000,reader);
                    if (!cached || !*cached) throw std::runtime_error("group admission miss");
                } else {
                    auto token=grouped->begin_query(group,key);
                    if (!token || !grouped->publish(group,key,answer(key),1000,*token)) throw std::runtime_error("group publication failed");
                }
            }
            for (unsigned group=0;group<groups;++group) for (auto const& key:keys[group]) {
                auto cached=grouped->lookup(group,key,1000,reader);
                if (!cached || !*cached || (**cached).canonical_name!=key.name) throw std::runtime_error("invalid group answer");
            }
        } else {
            for (unsigned group=0;group<groups;++group) {
                separate[group]=std::make_unique<d::AddressCache>(256,0,true,group==16 ? 1 : per_inbound);
                for (auto const& key:keys[group]) {
                    auto token=separate[group]->begin_query(key);
                    if (!token || !separate[group]->publish(key,answer(key),1000,*token)) throw std::runtime_error("separate publication failed");
                }
                auto reader=separate[group]->reader(0);
                for (auto const& key:keys[group]) {
                    auto cached=separate[group]->lookup(key,1000,reader);
                    if (!cached || !*cached || (**cached).canonical_name!=key.name) throw std::runtime_error("invalid separate answer");
                }
            }
        }
        auto after=memory();
        auto charged=grouped ? grouped->charged_bytes() : 0;
        auto nodes=grouped ? GroupCache::live_nodes() : 0;
        auto expected=entries*(layout=="overlap" ? 1U : groups);
        if (grouped && nodes!=expected) throw std::runtime_error("incorrect deduplication");
        std::cout<<mode<<','<<layout<<','<<per_inbound<<','<<reader_count<<','<<entries<<','<<entries*groups<<','
                 <<nodes<<','<<charged<<','<<after.allocated-before.allocated<<','<<after.rss-before.rss;
        if (argc>=6) {
#ifdef DNS_GROUP_SHARED_CAPACITY_EXPERIMENT
            std::cout<<','<<groups<<','<<shared_limit;
#else
            std::cout<<','<<groups<<','<<group_capacity;
#endif
        }
        std::cout<<'\n';
    } catch (std::exception const& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
