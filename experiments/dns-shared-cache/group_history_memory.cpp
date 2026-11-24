#include <malloc.h>
import std;
import dns.message;
import dns.cache;
import dns.group_snapshot;

namespace d=dns;
using Cache=dns_hp_experiment::GroupSnapshot;
struct Memory { std::int64_t allocated=0,rss=0; };
auto memory() -> Memory {
    std::ifstream input("/proc/self/smaps_rollup"); std::string line; std::int64_t rss=-1;
    while (std::getline(input,line)) if (line.starts_with("Rss:")) {
        auto start=line.find_first_of("0123456789");
        if (start==std::string::npos || std::from_chars(line.data()+start,line.data()+line.size(),rss).ec!=std::errc{})
            throw std::runtime_error("invalid RSS");
        rss*=1024; break;
    }
    if (rss<0) throw std::runtime_error("missing RSS");
    auto info=mallinfo2(); return {static_cast<std::int64_t>(info.uordblks)+static_cast<std::int64_t>(info.hblkhd),rss};
}
int main(int argc,char** argv) {
    if (argc!=4) { std::cerr<<"usage: group-history-memory overlap|disjoint readers budget-bytes\n"; return 2; }
    try {
        std::string_view layout=argv[1];
        auto parse=[](char const* text) {
            auto end=text+std::char_traits<char>::length(text); std::size_t value=0;
            auto [next,error]=std::from_chars(text,end,value);
            if (error!=std::errc{} || next!=end) throw std::invalid_argument("invalid number");
            return value;
        };
        auto count=parse(argv[2]),limit=parse(argv[3]);
        if ((layout!="overlap" && layout!="disjoint") || !count || count>16) throw std::invalid_argument("invalid parameters");
        constexpr std::size_t groups=17,entries=256;
        std::array<std::vector<d::CacheKey>,groups> keys;
        for (std::size_t g=0;g<groups;++g) for (std::size_t i=0;i<entries;++i)
            keys[g].push_back({1,std::format("history-{}-{:04}.test",layout=="overlap" ? 0 : g,i),1});
        auto before=memory();
        std::array<std::size_t,groups> capacities; capacities.fill(entries);
        Cache cache(capacities,count,0,limit);
        std::vector<Cache::Reader> readers; readers.reserve(count);
        for (std::size_t i=0;i<count;++i) readers.push_back(cache.reader(i));
        auto publish=[&](std::size_t group,d::CacheKey const& key,unsigned revision) {
            d::Address address{}; address.size=4; address.bytes[0]=static_cast<std::uint8_t>(revision);
            d::AddressAnswer answer{key.name,{key.name},{address},3600};
            auto token=cache.begin_query(group,key);
            if (!token) throw std::runtime_error("registration failed");
            return cache.publish(group,key,std::move(answer),1000,*token);
        };
        for (std::size_t g=0;g<groups;++g) for (auto const& key:keys[g]) {
            if (layout=="overlap" && g) {
                auto result=cache.lookup(g,key,1000,readers[0]);
                if (!result || !*result) throw std::runtime_error("initial admission failed");
            } else if (!publish(g,key,0)) throw std::runtime_error("initial publication failed");
        }
        auto warm=memory(); auto warm_charge=cache.charged_bytes();
        Memory pinned{}; std::size_t pinned_charge=0,pinned_nodes=0,writes=0;
        bool valid=true,exhausted=false;
        auto pin=[&](auto&& self,std::size_t index) -> void {
            auto result=cache.lookup_with_hook(0,keys[0][0],1000,readers[index],[&] {
                for (std::size_t g=0;g<(layout=="overlap" ? 1U : groups) && !exhausted;++g)
                    for (auto const& key:keys[g]) {
                        auto updated=publish(g,key,static_cast<unsigned>(index+1));
                        if (!updated) {
                            if (updated.error()!=d::CacheError::disabled) valid=false;
                            exhausted=true; break;
                        }
                        ++writes;
                    }
                if (!exhausted && index+1<count) self(self,index+1);
                else {
                    pinned=memory(); pinned_charge=cache.charged_bytes(); pinned_nodes=Cache::live_nodes();
                }
            });
            if (!result || (exhausted ? result->has_value() : !*result || (**result).addresses[0].bytes[0]!=index)) valid=false;
        };
        // Do not enter another lookup with the already active guard in a hook.
        // Disabled state is checked after the pinned calls return.
        pin(pin,0);
        if (cache.peak_charged_bytes()>limit || !valid) throw std::runtime_error("invalid pinned result");
        if (exhausted) {
            auto miss=cache.lookup(0,keys[0][0],1000,readers[0]);
            auto denied=cache.begin_query(0,keys[0][0]);
            if (!miss || *miss || denied || denied.error()!=d::CacheError::disabled || !cache.clear(1000))
                throw std::runtime_error("disabled recovery failed");
            if (!publish(0,keys[0][0],99)) throw std::runtime_error("recovery publication failed");
        } else {
            auto expected=(count+1)*entries*(layout=="overlap" ? 1U : groups);
            if (pinned_nodes!=expected || !publish(0,keys[0][0],99)) throw std::runtime_error("historical count incorrect");
            auto current_nodes=entries*(layout=="overlap" ? 1U : groups);
            if (Cache::live_nodes()!=current_nodes) throw std::runtime_error("history not collected");
        }
        auto recovered=memory(); auto recovered_charge=cache.charged_bytes();
        std::cout<<layout<<','<<count<<','<<limit<<','<<exhausted<<','<<writes<<','<<pinned_nodes<<','
                 <<warm_charge<<','<<pinned_charge<<','<<cache.peak_charged_bytes()<<','<<recovered_charge<<','
                 <<warm.allocated-before.allocated<<','<<pinned.allocated-before.allocated<<','<<recovered.allocated-before.allocated<<','
                 <<warm.rss-before.rss<<','<<pinned.rss-before.rss<<','<<recovered.rss-before.rss<<'\n';
    } catch (std::exception const& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
