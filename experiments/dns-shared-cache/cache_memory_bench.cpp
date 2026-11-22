#include <malloc.h>
#include "bounded_table.hpp"
import std;
import dns.cache;
import dns.message;
#include "actual_cache_types.hpp"
#include "semantic_cache.hpp"
#include "snapshot_cache.hpp"
#include "paged_snapshot.hpp"
#include "paged_semantic.hpp"

namespace d=dns;
auto resident_bytes() -> std::int64_t {
    std::ifstream input("/proc/self/smaps_rollup");
    std::string line;
    while (std::getline(input,line)) if (line.starts_with("Rss:")) {
        auto first=line.find_first_of("0123456789");
        std::int64_t value=0;
        if (first==std::string::npos || std::from_chars(line.data()+first,line.data()+line.size(),value).ec!=std::errc{})
            throw std::runtime_error("invalid smaps RSS");
        return value*1024;
    }
    throw std::runtime_error("cannot read smaps RSS");
}
auto main(int argc,char** argv) -> int {
    if (argc!=3 && argc!=4) { std::cerr<<"usage: cache_memory_bench per-worker|shared|bounded|semantic|snapshot|ordered|ordered512|paged|paged-full-eager|paged-full-lazy|module workers [entries]\n"; return 2; }
    std::string mode=argv[1];
    auto workers=std::atoi(argv[2]);
    auto entries=argc==4 ? std::atoi(argv[3]) : 256;
    auto full=mode=="paged-full-eager" || mode=="paged-full-lazy";
    if ((mode!="per-worker" && mode!="shared" && mode!="bounded" && mode!="semantic" && mode!="snapshot" && mode!="ordered" &&
         mode!="ordered512" && mode!="paged" && mode!="module" && !full) ||
        workers<1 || workers>257 || entries<0 || entries>(full ? 4352 : (mode=="ordered512" || mode=="paged") ? 512 : 256) ||
        (workers>16 && mode!="per-worker" && mode!="snapshot" && mode!="ordered" && mode!="ordered512" && mode!="paged" && mode!="module" && !full)) return 2;
    std::vector<d::CacheKey> keys;
    for (int i=0;i<entries;++i) keys.push_back({1,"host-"+std::to_string(i)+".example.test",1});
    d::Address address{}; address.size=4; address.bytes[0]=192; address.bytes[3]=10;
    auto rss_before=resident_bytes();
    auto before=mallinfo2();
    std::vector<std::unique_ptr<d::AddressCache>> caches;
    std::unique_ptr<dns_hp_experiment::ActualTable> table;
    std::unique_ptr<dns_hp_experiment::SemanticCache> semantic;
    std::unique_ptr<dns_hp_experiment::SnapshotCache> snapshot;
    std::unique_ptr<dns_hp_experiment::OrderedSnapshotCache> ordered;
    std::unique_ptr<dns_hp_experiment::OrderedSnapshotCache512> ordered512;
    std::unique_ptr<dns_hp_experiment::PagedSnapshotPrototype> paged;
    std::unique_ptr<dns_hp_experiment::FullPagedSemanticCache> paged_full_lazy;
    std::unique_ptr<dns_hp_experiment::FullPagedSemanticCacheEager> paged_full_eager;
    std::unique_ptr<d::AddressCache> module;
    if (mode=="bounded") table=std::make_unique<dns_hp_experiment::ActualTable>(workers);
    else if (mode=="semantic") semantic=std::make_unique<dns_hp_experiment::SemanticCache>(256,0,workers);
    else if (mode=="snapshot") snapshot=std::make_unique<dns_hp_experiment::SnapshotCache>(256,0,workers);
    else if (mode=="ordered") ordered=std::make_unique<dns_hp_experiment::OrderedSnapshotCache>(256,0,workers);
    else if (mode=="ordered512") ordered512=std::make_unique<dns_hp_experiment::OrderedSnapshotCache512>(512,0,workers);
    else if (mode=="paged") paged=std::make_unique<dns_hp_experiment::PagedSnapshotPrototype>(512,0,workers);
    else if (mode=="paged-full-lazy") paged_full_lazy=std::make_unique<dns_hp_experiment::FullPagedSemanticCache>(4352,0,workers);
    else if (mode=="paged-full-eager") paged_full_eager=std::make_unique<dns_hp_experiment::FullPagedSemanticCacheEager>(4352,0,workers);
    else if (mode=="module") module=std::make_unique<d::AddressCache>(256,0,true,workers);
    else for (int i=0;i<(mode=="per-worker" ? workers : 1);++i)
        caches.push_back(std::make_unique<d::AddressCache>(256,0,mode=="shared"));
    for (auto const& key:keys) {
        d::AddressAnswer answer{key.name,{key.name},{address},3600};
        if (table) {
            if (!table->put(key,{std::move(answer),3601000})) std::abort();
        } else if (semantic) {
            auto token=semantic->begin_query(key);
            if (!token || !semantic->publish(key,std::move(answer),1000,*token)) std::abort();
        } else if (snapshot) {
            auto token=snapshot->begin_query(key);
            if (!token || !snapshot->publish(key,std::move(answer),1000,*token)) std::abort();
        } else if (ordered) {
            auto token=ordered->begin_query(key);
            if (!token || !ordered->publish(key,std::move(answer),1000,*token)) std::abort();
        } else if (ordered512) {
            auto token=ordered512->begin_query(key);
            if (!token || !ordered512->publish(key,std::move(answer),1000,*token)) std::abort();
        } else if (paged) {
            auto token=paged->begin_query(key);
            if (!token || !paged->publish(key,std::move(answer),1000,*token)) std::abort();
        } else if (paged_full_lazy) {
            auto token=paged_full_lazy->begin_query(key);
            if (!token || !paged_full_lazy->publish(key,std::move(answer),1000,*token)) std::abort();
        } else if (paged_full_eager) {
            auto token=paged_full_eager->begin_query(key);
            if (!token || !paged_full_eager->publish(key,std::move(answer),1000,*token)) std::abort();
        } else if (module) {
            auto token=module->begin_query(key);
            if (!token || !module->publish(key,std::move(answer),1000,*token)) std::abort();
        } else for (auto& cache:caches) {
            auto token=cache->begin_query(key);
            if (!token || !cache->publish(key,answer,1000,*token)) std::abort();
        }
    }
    auto after=mallinfo2();
    auto rss_after=resident_bytes();
    // Large snapshot arrays may be served by mmap and are not in uordblks.
    auto allocated=static_cast<std::int64_t>(after.uordblks)+static_cast<std::int64_t>(after.hblkhd)-
                   static_cast<std::int64_t>(before.uordblks)-static_cast<std::int64_t>(before.hblkhd);
    std::cout<<mode<<','<<workers<<','<<entries<<','<<allocated<<','<<rss_after-rss_before<<'\n';
}
