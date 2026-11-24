#include <malloc.h>
import std;
import dns.message;
import dns.cache;
import dns.group_snapshot;

namespace d=dns;
using Cache=dns_hp_experiment::GroupSnapshot;
struct Memory { std::int64_t allocated=0,rss=0,high=0; };
auto field(std::string_view path,std::string_view label) -> std::int64_t {
    std::ifstream input{std::string(path)}; std::string line;
    while (std::getline(input,line)) if (line.starts_with(label)) {
        auto first=line.find_first_of("0123456789"); std::int64_t value=0;
        if (first==std::string::npos || std::from_chars(line.data()+first,line.data()+line.size(),value).ec!=std::errc{})
            throw std::runtime_error("invalid memory field");
        return value*1024;
    }
    throw std::runtime_error("missing memory field");
}
auto memory() -> Memory {
    auto rss=field("/proc/self/smaps_rollup","Rss:");
    auto high=field("/proc/self/status","VmHWM:");
    auto info=mallinfo2();
    return {static_cast<std::int64_t>(info.uordblks)+static_cast<std::int64_t>(info.hblkhd),rss,high};
}
int main(int argc,char** argv) {
    if (argc!=4) { std::cerr<<"usage: pending-memory short|long readers count\n"; return 2; }
    try {
        std::string_view name_kind=argv[1];
        auto parse=[](char const* text) {
            auto end=text+std::char_traits<char>::length(text); unsigned value=0;
            auto [next,error]=std::from_chars(text,end,value);
            if (error!=std::errc{} || next!=end) throw std::invalid_argument("invalid number");
            return value;
        };
        auto readers=parse(argv[2]),count=parse(argv[3]);
        if ((name_kind!="short" && name_kind!="long") || readers>257 || count>4096)
            throw std::invalid_argument("invalid parameters");
        std::string long_name=std::string(63,'a')+"."+std::string(63,'b')+"."+std::string(63,'c')+"."+std::string(61,'d');
        d::CacheKey key{1,name_kind=="short" ? "a.test" : long_name,1};
        std::array<std::size_t,17> capacities; capacities.fill(256);
        Cache cache(capacities,readers,0,256*1024);
        auto baseline=memory(); auto charged=cache.charged_bytes();
        for (unsigned i=0;i<count;++i) if (!cache.begin_query(i%17,key)) throw std::runtime_error("registration failed");
        auto full=memory();
        if (cache.charged_bytes()!=charged) throw std::runtime_error("pending unexpectedly charged");
        bool overflow=false;
        if (count==4096) {
            auto denied=cache.begin_query(0,key);
            overflow=!denied && denied.error()==d::CacheError::query_limit;
            if (!overflow) throw std::runtime_error("query limit failed");
        } else if (!cache.clear(1000)) throw std::runtime_error("clear failed");
        auto emptied=memory();
        if (overflow && !cache.clear(1000)) throw std::runtime_error("recovery failed");
        auto again=cache.begin_query(0,key);
        if (!again || !cache.cancel_query(*again)) throw std::runtime_error("recovery query failed");
        std::cout<<name_kind<<','<<readers<<','<<count<<','<<charged<<','
                 <<full.allocated-baseline.allocated<<','<<full.rss-baseline.rss<<','<<full.high-baseline.high<<','
                 <<emptied.allocated-baseline.allocated<<','<<emptied.rss-baseline.rss<<','<<emptied.high-baseline.high<<'\n';
    } catch (std::exception const& error) { std::cerr<<error.what()<<'\n'; return 1; }
}
