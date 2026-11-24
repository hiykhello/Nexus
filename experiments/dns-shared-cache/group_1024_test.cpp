// Isolated candidate for 1024 cache memberships per group. It does not set a
// production default or change the existing 256-entry experiment targets.
#include <cstdio>
import std;
import dns.message;
import dns.cache;
import dns.group_snapshot;

namespace d=dns;
using Cache=dns_hp_experiment::GroupSnapshot;
namespace { thread_local int fail_after=-1; thread_local bool injected=false; }
void* operator new(std::size_t size) {
    if (fail_after>=0 && fail_after--==0) { fail_after=-1; injected=true; throw std::bad_alloc(); }
    if (auto* value=std::malloc(size ? size : 1)) return value;
    throw std::bad_alloc();
}
void operator delete(void* value) noexcept { std::free(value); }
void operator delete(void* value,std::size_t) noexcept { std::free(value); }

namespace {
auto require(bool value,char const* reason) -> void { if (!value) throw std::runtime_error(reason); }
auto key(unsigned group,unsigned index,unsigned view=1) -> d::CacheKey {
    return {view,std::format("capacity-{:02}-{:04}.example.test",group,index),1};
}
auto answer(d::CacheKey const& name,unsigned value,unsigned ttl=3600) -> d::AddressAnswer {
    d::Address address{}; address.size=4; address.bytes[0]=static_cast<std::uint8_t>(value);
    address.bytes[1]=static_cast<std::uint8_t>(~address.bytes[0]);
    return {name.name,{name.name},{address},ttl};
}
auto publish(Cache& cache,std::size_t group,d::CacheKey const& name,unsigned value,unsigned ttl=3600) -> void {
    auto token=cache.begin_query(group,name);
    require(token.has_value() && cache.publish(group,name,answer(name,value,ttl),1000,*token).has_value(),"publication failed");
}
auto value(Cache& cache,std::size_t group,d::CacheKey const& name,Cache::Reader& reader) -> std::optional<unsigned> {
    auto result=cache.lookup(group,name,1000,reader);
    require(result.has_value(),"lookup failed");
    if (!*result) return {};
    auto const& found=**result;
    require(found.canonical_name==name.name && found.addresses.size()==1 &&
            found.addresses[0].bytes[1]==static_cast<std::uint8_t>(~found.addresses[0].bytes[0]),"corrupt answer");
    return found.addresses[0].bytes[0];
}
auto ordered_seed(Cache& cache) -> void {
    for (unsigned i=0;i<1024;++i) publish(cache,0,key(0,i),i);
    auto size=cache.size(0),pages=cache.page_count(0);
    if (size!=1024 || pages!=32) throw std::runtime_error(std::format("split seed has {} entries and {} pages",size,pages));
}
auto boundaries_and_faults() -> void {
    {
        std::array<std::size_t,1> invalid{1025}; bool rejected=false;
        try { Cache too_large(invalid,1); } catch (std::invalid_argument const&) { rejected=true; }
        require(rejected,"capacity above 1024 was accepted");
    }
    unsigned failures=0; bool completed=false;
    for (int position=0;position<32 && !completed;++position) {
        std::array<std::size_t,1> capacities{1024}; Cache cache(capacities,1); auto reader=cache.reader(0);
        ordered_seed(cache);
        auto next=key(0,1024); auto result_answer=answer(next,99);
        auto token=cache.begin_query(0,next); require(token.has_value(),"split token failed");
        injected=false; fail_after=position;
        bool failed=false;
        try {
            auto result=cache.publish(0,std::move(next),std::move(result_answer),1000,*token);
            fail_after=-1; require(result.has_value(),"split returned an error"); completed=true;
        } catch (std::bad_alloc const&) {
            fail_after=-1; require(injected,"unexpected allocation failure"); failed=true; ++failures;
        }
        if (failed) {
            require(cache.cancel_query(*token).has_value(),"failed split retained its token");
            require(cache.size(0)==1024 && cache.page_count(0)==32 && value(cache,0,key(0,0),reader)==0 &&
                    value(cache,0,key(0,1023),reader)==255 && !value(cache,0,key(0,1024),reader),
                    "failed split changed the previous version");
            publish(cache,0,key(0,1024),99);
        }
        require(cache.size(0)==1024 && cache.page_count(0)==33 && !value(cache,0,key(0,0),reader) &&
                value(cache,0,key(0,1024),reader)==99,"eviction or page merge failed");
        for (unsigned i=1;i<1024;++i) require(value(cache,0,key(0,i),reader)==i%256,"split lost an existing entry");
    }
    require(completed && failures>0,"split allocation sweep incomplete");
    std::println("1024-entry split allocation faults: {} positions",failures);
}
auto isolation_and_sharing() -> void {
    {
        std::array<std::size_t,2> capacities{1024,1024}; Cache cache(capacities,2);
        auto first=cache.reader(0),second=cache.reader(1);
        for (unsigned i=0;i<1024;++i) publish(cache,0,key(0,i),1,3600);
        for (unsigned i=0;i<1024;++i) publish(cache,1,key(1,i),2,600);
        for (unsigned i=0;i<1024;++i) publish(cache,0,key(2,i),3,7200);
        require(cache.size(0)==1024 && cache.size(1)==1024 && Cache::live_nodes()==2048,"group quota incorrect");
        for (unsigned i=0;i<1024;++i)
            require(!value(cache,0,key(0,i),first) && value(cache,0,key(2,i),first)==3 &&
                    value(cache,1,key(1,i),second)==2,"one group evicted another group's entries");
    }
    require(Cache::live_nodes()==0,"group isolation retained nodes");
    {
        std::array<std::size_t,2> capacities{1024,1024}; Cache cache(capacities,2);
        auto first=cache.reader(0),second=cache.reader(1);
        for (unsigned i=0;i<1024;++i) publish(cache,0,key(0,i),4);
        for (unsigned i=0;i<1024;++i) require(value(cache,1,key(0,i),second)==4,"cross-group admission failed");
        require(cache.size(0)==1024 && cache.size(1)==1024 && Cache::live_nodes()==1024,"identical answers were not shared");
        auto subject=key(0,512); publish(cache,0,subject,8);
        require(value(cache,0,subject,first)==8 && value(cache,1,subject,second)==8,"shared replacement diverged");
        auto token=cache.begin_query(1,subject);
        require(token && cache.publish_negative(1,subject,d::NegativeKind::name_not_found,30,1000,*token),"negative replacement failed");
        auto negative=cache.lookup_negative(0,subject,1000,first);
        require(negative && *negative && **negative==d::NegativeKind::name_not_found && !value(cache,1,subject,second),
                "shared negative replacement diverged");
        auto other_view=key(0,512,2);
        require(!value(cache,1,other_view,second),"different DNS views were merged");
    }
    require(Cache::live_nodes()==0,"group sharing retained nodes");
}
auto variable_group_count() -> void {
    std::size_t one_empty=0,many_empty=0;
    {
        std::array<std::size_t,1> capacities{1024}; Cache cache(capacities,2);
        one_empty=cache.charged_bytes(); auto reader=cache.reader(0);
        require(cache.supports_binding(0,0,2) && !cache.supports_binding(1,0,1),"single group binding count invalid");
        bool rejected=false;
        try { (void)cache.size(1); } catch (std::out_of_range const&) { rejected=true; }
        require(rejected,"single-group cache exposed an unconfigured group");
        publish(cache,0,key(0,0),9);
        require(value(cache,0,key(0,0),reader)==9,"single group did not cache an answer");
    }
    {
        std::array<std::size_t,17> capacities; capacities.fill(1024); Cache cache(capacities,2);
        many_empty=cache.charged_bytes();
    }
    require(one_empty==many_empty,"empty groups unexpectedly allocated membership indexes");
    {
        std::array<std::size_t,3> capacities{1024,5,0}; Cache cache(capacities,2);
        auto first=cache.reader(0),second=cache.reader(1);
        for (unsigned i=0;i<1024;++i) publish(cache,0,key(0,i),1);
        for (unsigned i=0;i<6;++i) publish(cache,1,key(1,i),2);
        require(cache.size(0)==1024 && cache.size(1)==5 && cache.size(2)==0 &&
                value(cache,0,key(0,0),first)==1 && !value(cache,1,key(1,0),second) &&
                !value(cache,2,key(0,0),second),"configured group capacities were not independent");
    }
    require(Cache::live_nodes()==0,"variable groups retained nodes");
}
auto all_groups() -> void {
    std::array<std::size_t,17> capacities; capacities.fill(1024); Cache cache(capacities,1); auto reader=cache.reader(0);
    for (unsigned group=0;group<17;++group) for (unsigned i=0;i<1024;++i) publish(cache,group,key(group,i),group);
    require(Cache::live_nodes()==17408,"17-group capacity was not retained");
    for (unsigned group=0;group<17;++group) for (unsigned i=0;i<1024;++i)
        require(value(cache,group,key(group,i),reader)==group,"17-group initial answer missing");
    for (unsigned i=0;i<1024;++i) publish(cache,0,key(17,i),99,7200);
    for (unsigned group=1;group<17;++group) for (unsigned i=0;i<1024;++i)
        require(value(cache,group,key(group,i),reader)==group,"17-group eviction crossed a quota");
    require(cache.size(0)==1024 && Cache::live_nodes()==17408,"17-group replacement count incorrect");
}
auto history_and_budget() -> void {
    {
        std::array<std::size_t,1> capacities{1024}; Cache cache(capacities,2,0,16*1024*1024);
        auto held=cache.reader(0),current=cache.reader(1);
        for (unsigned i=0;i<1024;++i) publish(cache,0,key(0,i),1);
        auto old=cache.lookup_with_hook(0,key(0,0),1000,held,[&] {
            for (unsigned i=0;i<1024;++i) publish(cache,0,key(0,i),2);
            require(Cache::live_nodes()==2048 && value(cache,0,key(0,0),current)==2,"pinned history was not retained");
        });
        require(old && *old && (**old).addresses[0].bytes[0]==1,"pinned reader did not see its version");
        publish(cache,0,key(0,0),3);
        require(Cache::live_nodes()==1024 && cache.peak_charged_bytes()<=16*1024*1024,"released history was not collected");
    }
    require(Cache::live_nodes()==0,"history retained nodes");
    {
        std::array<std::size_t,1> capacities{1024}; Cache cache(capacities,1,0,128*1024); auto reader=cache.reader(0);
        bool disabled=false;
        for (unsigned i=0;i<1024 && !disabled;++i) {
            auto name=key(0,i); auto token=cache.begin_query(0,name);
            require(token.has_value(),"budget registration failed early");
            auto result=cache.publish(0,name,answer(name,1),1000,*token);
            if (!result) { require(result.error()==d::CacheError::disabled,"unexpected budget error"); disabled=true; }
        }
        auto miss=cache.lookup(0,key(0,0),1000,reader);
        require(disabled && miss && !*miss && cache.peak_charged_bytes()<=128*1024,"budget did not fail closed");
        require(cache.clear(1000).has_value(),"budget recovery clear failed");
        publish(cache,0,key(0,0),7);
        require(value(cache,0,key(0,0),reader)==7,"budget did not recover");
    }
}
auto fragmentation() -> void {
    std::array<std::size_t,1> capacities{1024}; Cache cache(capacities,1); auto reader=cache.reader(0);
    std::uint64_t now=1000; unsigned sequence=0,merges=0;
    std::vector<d::CacheKey> survivors;
    auto next=[&] { return d::CacheKey{1,std::format("fragment-{:06}.example.test",sequence++),1}; };
    auto write=[&](d::CacheKey const& name,unsigned ttl) {
        auto token=cache.begin_query(0,name);
        require(token && cache.publish(0,name,answer(name,42,ttl),now,*token),"fragmentation publication failed");
    };
    survivors.push_back(next()); write(survivors.back(),3600);
    for (unsigned round=0;round<480;++round) {
        d::CacheKey retained;
        for (unsigned i=1;i<=32;++i) {
            auto name=next(); if (i==16) retained=name;
            write(name,i==16 ? 3600 : 1);
        }
        auto before=cache.page_count(0); now+=2000; write(retained,3600);
        survivors.push_back(std::move(retained));
        auto pages=cache.page_count(0);
        merges+=pages<before;
        require(cache.size(0)==survivors.size() && pages<=2*survivors.size()/33+1,
                "sparse pages grew beyond their merged bound");
    }
    require(merges>0,"fragmentation test did not exercise a page merge");
    for (auto const& name:survivors) {
        auto result=cache.lookup(0,name,now,reader);
        require(result && *result && (**result).addresses[0].bytes[0]==42,"fragmentation lost a retained answer");
    }
}
auto differential() -> void {
    std::array<std::size_t,1> capacities{1024}; Cache cache(capacities,1,5000); auto reader=cache.reader(0);
    d::AddressCache reference(1024,5000,true); std::vector<d::CacheKey> keys; keys.reserve(2048);
    for (unsigned i=0;i<2048;++i) keys.push_back(key(0,i,1+i%3));
    std::uint64_t now=1000; std::mt19937 rng(20261030);
    auto write=[&](d::CacheKey const& name,unsigned number,unsigned ttl) {
        auto first=reference.begin_query(name),second=cache.begin_query(0,name);
        require(first && second && reference.publish(name,answer(name,number,ttl),now,*first) &&
                cache.publish(0,name,answer(name,number,ttl),now,*second),"differential seed failed");
    };
    for (unsigned i=0;i<1024;++i) write(keys[i],i,3600);
    auto same=[&](d::CacheKey const& name) {
        auto a=reference.lookup(name,now),b=cache.lookup(0,name,now,reader);
        require(a && b && a->has_value()==b->has_value(),"differential positive presence differs");
        if (*a) require((**a).ttl==(**b).ttl && (**a).canonical_name==(**b).canonical_name &&
                        (**a).addresses[0].bytes==(**b).addresses[0].bytes,"differential positive differs");
        auto an=reference.lookup_negative(name,now),bn=cache.lookup_negative(0,name,now,reader);
        require(an && bn && *an==*bn,"differential negative differs");
        auto as=reference.lookup_stale(name,now),bs=cache.lookup_stale(0,name,now,reader);
        require(as && bs && as->has_value()==bs->has_value(),"differential stale presence differs");
        if (*as) require((**as).age_ms==(**bs).age_ms && (**as).answer.ttl==(**bs).answer.ttl &&
                         (**as).answer.addresses[0].bytes==(**bs).answer.addresses[0].bytes,"differential stale differs");
    };
    for (unsigned step=0;step<20000;++step) {
        auto const& name=keys[rng()%keys.size()]; auto operation=rng()%10;
        if (operation<5) write(name,step,static_cast<unsigned>(rng()%3601));
        else if (operation<7) {
            auto first=reference.begin_query(name),second=cache.begin_query(0,name);
            auto ttl=static_cast<unsigned>(rng()%31);
            auto kind=step%2 ? d::NegativeKind::no_data : d::NegativeKind::name_not_found;
            require(first && second && reference.publish_negative(name,kind,ttl,now,*first) &&
                    cache.publish_negative(0,name,kind,ttl,now,*second),"differential negative publication failed");
        } else if (operation==7) {
            auto first=reference.begin_query(name),second=cache.begin_query(0,name);
            require(first && second && reference.invalidate(name,now,*first) && cache.invalidate(0,name,now,*second),
                    "differential invalidation failed");
        } else if (operation==8) now+=rng()%251;
        same(name); same(keys[rng()%keys.size()]);
        if (step%1000==0) for (auto const& candidate:keys) same(candidate);
        require(cache.page_count(0)<=63,"published index exceeded its page bound");
    }
    std::puts("1024-entry differential: 20000 mixed operations passed");
}
auto concurrent_readers() -> void {
    constexpr unsigned reader_count=4;
    std::array<std::size_t,2> capacities{1024,1024}; Cache cache(capacities,reader_count);
    std::vector<d::CacheKey> keys; keys.reserve(1024);
    for (unsigned i=0;i<1024;++i) { keys.push_back(key(0,i)); publish(cache,0,keys.back(),1); }
    {
        auto reader=cache.reader(0);
        for (auto const& name:keys) require(value(cache,1,name,reader)==1,"concurrent seed admission failed");
    }
    std::atomic<bool> stop=false,failed=false;
    std::array<std::atomic<unsigned>,reader_count> counts{};
    std::barrier gate(reader_count+1);
    std::vector<std::thread> threads;
    for (unsigned i=0;i<reader_count;++i) threads.emplace_back([&,i] {
        auto reader=cache.reader(i); gate.arrive_and_wait(); unsigned iteration=0;
        try {
            while (!stop.load(std::memory_order_relaxed)) {
                auto result=cache.lookup(i%2,keys[(iteration*67+i)%keys.size()],1000,reader);
                if (!result || !*result || (**result).addresses.size()!=1 ||
                    (**result).addresses[0].bytes[1]!=static_cast<std::uint8_t>(~(**result).addresses[0].bytes[0])) {
                    failed=true; break;
                }
                ++iteration;
            }
        } catch (...) { failed=true; }
        counts[i]=iteration;
    });
    gate.arrive_and_wait();
    try { for (unsigned i=0;i<8192;++i) publish(cache,0,keys[(i*73)%keys.size()],i); }
    catch (...) { failed=true; }
    stop=true;
    for (auto& thread:threads) thread.join();
    require(!failed && std::ranges::all_of(counts,[](auto const& count) { return count.load()>0; }),
            "1024-entry concurrent readers failed");
    publish(cache,0,keys[0],9); // trigger collection after the last reader leaves
    require(cache.size(0)==1024 && cache.size(1)==1024 && Cache::live_nodes()==1024,
            "concurrent shared entries were not reclaimed");
    std::puts("1024-entry shared readers and writer passed");
}
}
auto main() -> int {
    try {
        boundaries_and_faults(); isolation_and_sharing(); variable_group_count(); all_groups(); history_and_budget(); fragmentation(); differential(); concurrent_readers();
        require(Cache::live_nodes()==0,"cache nodes survived destruction");
        std::puts("1024 per group: 17 groups, quota isolation, sharing, history and budget passed");
        return 0;
    } catch (std::exception const& error) { std::fprintf(stderr,"1024 group experiment: %s\n",error.what()); return 1; }
}
