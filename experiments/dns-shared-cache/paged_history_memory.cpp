#include <malloc.h>
#include "bounded_table.hpp"
import std;
import dns.cache;
import dns.message;
#include "snapshot_cache.hpp"
#include "paged_snapshot.hpp"

namespace d=dns;
struct Memory { std::int64_t allocated,rss; };
auto memory() -> Memory {
    std::ifstream input("/proc/self/smaps_rollup");
    std::string line;
    std::int64_t rss=-1;
    while (std::getline(input,line)) if (line.starts_with("Rss:")) {
        auto first=line.find_first_of("0123456789");
        if (first==std::string::npos || std::from_chars(line.data()+first,line.data()+line.size(),rss).ec!=std::errc{})
            throw std::runtime_error("invalid smaps RSS");
        rss*=1024; break;
    }
    if (rss<0) throw std::runtime_error("cannot read smaps RSS");
    auto info=mallinfo2();
    return {static_cast<std::int64_t>(info.uordblks)+static_cast<std::int64_t>(info.hblkhd),rss};
}
template<class Cache>
auto measure(std::string_view mode,std::size_t count) -> int {
    constexpr std::size_t entries=512;
    std::vector<d::CacheKey> keys;
    for (std::size_t i=0;i<entries;++i) keys.push_back({1,std::format("history-memory-{:04}.test",i),1});
    auto before=memory();
    Cache cache(entries,0,count);
    std::vector<typename Cache::Reader> readers;
    readers.reserve(count);
    for (std::size_t i=0;i<count;++i) readers.push_back(cache.reader(i));
    auto publish=[&](d::CacheKey const& key,std::uint8_t revision) {
        d::Address address{}; address.size=4; address.bytes[0]=revision;
        d::AddressAnswer answer{key.name,{key.name},{address},3600};
        auto token=cache.begin_query(key);
        return token && cache.publish(key,std::move(answer),1000,*token).has_value();
    };
    for (auto const& key:keys) if (!publish(key,0)) return 1;
    auto warm=memory();
    Memory peak{};
    bool valid=true;
    auto pin=[&](auto&& self,std::size_t index) -> void {
        auto result=cache.lookup_with_hook(keys[0],1000,readers[index],[&] {
            for (auto const& key:keys) if (!publish(key,static_cast<std::uint8_t>(index+1))) { valid=false; return; }
            if (index+1<count) self(self,index+1);
            else {
                if (Cache::live_nodes()!=(count+1)*entries) valid=false;
                peak=memory();
            }
        });
        if (!result || !*result || (**result).addresses[0].bytes[0]!=static_cast<std::uint8_t>(index)) valid=false;
    };
    pin(pin,0);
    if (!valid || !publish(keys[0],99) || Cache::live_nodes()!=entries) return 2;
    auto released=memory();
    std::cout<<mode<<','<<count<<','<<entries<<','
             <<warm.allocated-before.allocated<<','<<peak.allocated-before.allocated<<','<<released.allocated-before.allocated<<','
             <<warm.rss-before.rss<<','<<peak.rss-before.rss<<','<<released.rss-before.rss<<'\n';
    return 0;
}
auto main(int argc,char** argv) -> int {
    if (argc!=3) { std::cerr<<"usage: paged_history_memory ordered512|paged readers\n"; return 2; }
    std::string_view mode=argv[1],text=argv[2];
    std::size_t readers=0;
    auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),readers);
    if (error!=std::errc{} || end!=text.data()+text.size() || !readers || readers>16) return 2;
    if (mode=="ordered512") return measure<dns_hp_experiment::OrderedSnapshotCache512>(mode,readers);
    if (mode=="paged") return measure<dns_hp_experiment::PagedSnapshotPrototype>(mode,readers);
    return 2;
}
