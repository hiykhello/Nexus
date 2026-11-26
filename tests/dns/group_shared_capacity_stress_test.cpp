// Shared membership capacity allocation-fault, differential model, and concurrency tests.
import std;
import dns.message;
import dns.cache;
import dns.shared_cache;

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
    return {view,std::format("shared-{:02}-{:05}.example.test",group,index),1};
}
auto answer(d::CacheKey const& name,unsigned value,unsigned ttl=3600) -> d::AddressAnswer {
    d::Address address{}; address.size=4; address.bytes[0]=static_cast<std::uint8_t>(value);
    address.bytes[1]=static_cast<std::uint8_t>(~address.bytes[0]);
    return {name.name,{name.name},{address},ttl};
}
auto write(Cache& cache,std::size_t group,d::CacheKey const& name,unsigned value,
           std::uint64_t now=1000,unsigned ttl=3600) -> void {
    auto token=cache.begin_query(group,name);
    require(token && cache.publish(group,name,answer(name,value,ttl),now,*token),"positive publication failed");
}
auto write_negative(Cache& cache,std::size_t group,d::CacheKey const& name,std::uint64_t now,unsigned ttl) -> void {
    auto token=cache.begin_query(group,name);
    require(token && cache.publish_negative(group,name,d::NegativeKind::name_not_found,ttl,now,*token),"negative publication failed");
}
auto value(Cache& cache,std::size_t group,d::CacheKey const& name,Cache::Reader& reader,
           std::uint64_t now=1000) -> std::optional<unsigned> {
    auto result=cache.lookup(group,name,now,reader);
    require(result.has_value(),"lookup failed");
    if (!*result) return {};
    auto const& found=**result;
    require(found.canonical_name==name.name && found.addresses.size()==1 &&
            found.addresses[0].bytes[1]==static_cast<std::uint8_t>(~found.addresses[0].bytes[0]),"corrupt answer");
    return found.addresses[0].bytes[0];
}
auto borrowed_refresh_faults() -> void {
    auto groups=std::array<std::size_t,2>{1,1}; auto name=key(0,0);
    unsigned failures=0; bool complete=false;
    for (int position=0;position<20 && !complete;++position) {
        Cache cache(groups,Cache::SharedCapacity{8},1,5000); auto reader=cache.reader(0);
        write(cache,0,name,1,1000,1);
        auto held=cache.begin_query(0,key(0,9)); require(held.has_value(),"fault setup failed");
        auto input=name; input.name.reserve(512);
        injected=false; fail_after=position;
        try {
            auto token=cache.begin_refresh(1,std::move(input),2000,1);
            fail_after=-1; require(token && *token && cache.cancel_query(**token),"refresh fault sweep returned error");
            complete=true;
        } catch (std::bad_alloc const&) {
            fail_after=-1; require(injected,"unexpected refresh allocation failure"); ++failures;
            auto stale=cache.lookup_stale(0,name,2000,reader);
            auto retry=cache.begin_refresh(1,name,2000,1);
            require(stale && *stale && retry && *retry && cache.cancel_query(**retry),"refresh did not recover after allocation failure");
        }
        require(cache.cancel_query(*held).has_value(),"fault setup token was lost");
    }
    require(complete && failures>=2,"refresh allocation sweep incomplete");
    {
        Cache cache(groups,Cache::SharedCapacity{8},1,5000,1024*1024); auto reader=cache.reader(0);
        write(cache,0,name,1,1000,1); auto token=cache.begin_refresh(1,name,2000,1);
        require(token && *token,"publication fault setup failed"); auto replacement=answer(name,2);
        for (std::size_t group:{0,1}) {
            injected=false; fail_after=0; bool failed=false;
            try { (void)cache.publish_copy_view(group,name.view,name.name,name.type,replacement,2000,**token); }
            catch (std::bad_alloc const&) { failed=true; }
            fail_after=-1; require(failed && injected,"publication fault was not injected");
            auto stale=cache.lookup_stale(0,name,2000,reader);
            require(stale && static_cast<bool>(*stale)==(group==0),"publication fault disabled the wrong token owner");
        }
        auto disabled=cache.begin_query(0,name);
        require(!disabled && disabled.error()==d::CacheError::disabled && cache.clear(2000),"publication failure did not close and recover cache");
        write(cache,0,name,3,2000,60);
        require(value(cache,0,name,reader,2000)==3,"cache did not recover after borrowed refresh fault");
    }
    for (unsigned scenario=0;scenario<3;++scenario) {
        bool reclaimed=scenario==1;
        auto three=std::array<std::size_t,3>{1,1,1};
        Cache cache(three,Cache::SharedCapacity{3},2,5000,1024*1024); auto reader=cache.reader(0),third=cache.reader(1);
        auto sentinel=key(1,0);
        write(cache,0,name,1,1000,1); write(cache,0,key(0,1),2,1000,60);
        require(value(cache,2,name,third)==1,"stale publication fault setup failed");
        auto token=cache.begin_refresh(1,name,2000,1); require(token && *token,"stale publication token failed");
        if (reclaimed) {
            write(cache,1,sentinel,3,2000,60);
            require(!cache.contains_member(0,name) && cache.contains_member(2,name),"fault refresh source was not reclaimed");
        }
        if (scenario==2) {
            auto expired=cache.lookup_stale(2,name,7000,third);
            require(expired && !*expired,"time watermark setup failed");
        }
        auto replacement=answer(name,4); injected=false; fail_after=0; bool failed=false;
        try { (void)cache.publish_copy_view(1,name.view,name.name,name.type,replacement,scenario==0 ? 7000 : 2000,**token); }
        catch (std::bad_alloc const&) { failed=true; }
        fail_after=-1; require(failed && injected,"obsolete publication fault was not injected");
        auto intact=reclaimed ? value(cache,1,sentinel,reader,2000) : value(cache,0,key(0,1),reader,7000);
        require(intact==(reclaimed ? 3U : 2U) && cache.cancel_query(**token),
                "obsolete refresh allocation failure disabled current cache");
    }
    require(Cache::live_nodes()==0,"borrowed refresh faults retained nodes");
    std::println("borrowed refresh allocation faults: {} positions",failures);
}
auto allocation_faults() -> void {
    unsigned failures=0; bool complete=false;
    for (int position=0;position<50 && !complete;++position) {
        std::array<std::size_t,2> groups{1,1}; Cache cache(groups,Cache::SharedCapacity{12},1);
        for (unsigned i=0;i<12;++i) write(cache,0,key(0,i),i);
        auto name=key(1,0); auto answer_=answer(name,99); auto token=cache.begin_query(1,name);
        require(token.has_value(),"fault token failed");
        injected=false; fail_after=position; bool failed=false;
        try {
            auto result=cache.publish(1,std::move(name),std::move(answer_),1000,*token);
            fail_after=-1; require(result.has_value(),"fault sweep returned error"); complete=true;
        } catch (std::bad_alloc const&) {
            fail_after=-1; require(injected,"unexpected allocation failure"); failed=true; ++failures;
        }
        if (failed) {
            require(cache.cancel_query(*token).has_value(),"failed publication left token invalid");
            require(cache.size(0)==12 && cache.size(1)==0 && cache.contains_member(0,key(0,0)) &&
                    !cache.contains_member(1,key(1,0)),"failed publication changed old root");
            write(cache,1,key(1,0),99);
        }
        require(cache.size(0)==11 && cache.size(1)==1 && !cache.contains_member(0,key(0,0)) &&
                cache.contains_member(1,key(1,0)),"reclaim did not recover after allocation failure");
    }
    require(complete && failures>0,"reclaim allocation sweep incomplete");
    require(Cache::live_nodes()==0,"fault sweep retained nodes");
    std::println("shared-capacity allocation faults: {} positions",failures);
}
auto directory_growth_faults() -> void {
    unsigned failures=0; bool complete=false;
    for (int position=0;position<50 && !complete;++position) {
        std::array<std::size_t,1> groups{1}; Cache cache(groups,Cache::SharedCapacity{1024},1);
        for (unsigned i=0;i<32;++i) write(cache,0,key(0,i),i);
        if (cache.page_count(0)!=1 || cache.directory_slots(0)!=1)
            throw std::runtime_error(std::format("directory growth seed: {} pages, {} slots",cache.page_count(0),cache.directory_slots(0)));
        auto name=key(0,32); auto answer_=answer(name,99); auto token=cache.begin_query(0,name);
        require(token.has_value(),"directory fault token failed");
        injected=false; fail_after=position; bool failed=false;
        try {
            auto result=cache.publish(0,std::move(name),std::move(answer_),1000,*token);
            fail_after=-1; require(result.has_value(),"directory fault returned error"); complete=true;
        } catch (std::bad_alloc const&) {
            fail_after=-1; require(injected,"unexpected directory allocation failure"); failed=true; ++failures;
        }
        if (failed) {
            require(cache.cancel_query(*token).has_value(),"directory failure left token invalid");
            require(cache.size(0)==32 && cache.page_count(0)==1 && cache.directory_slots(0)==1 &&
                    cache.contains_member(0,key(0,0)) && !cache.contains_member(0,key(0,32)),
                    "directory failure changed published snapshot");
            write(cache,0,key(0,32),99);
        }
        require(cache.size(0)==33 && cache.page_count(0)==2 && cache.directory_slots(0)==2 &&
                cache.contains_member(0,key(0,0)) && cache.contains_member(0,key(0,32)),"directory did not grow");
    }
    require(complete && failures>0 && Cache::live_nodes()==0,"directory allocation sweep incomplete");
    std::println("directory growth allocation faults: {} positions",failures);
}
// Deliberately stores independent value copies and no pages or snapshot
// machinery, so mixed operations exercise the policy against another model.
struct Model {
    using Key=std::pair<unsigned,unsigned>; // view, name number
    struct Entry { unsigned value; bool negative; std::uint64_t expiry,discard,order; };
    std::array<std::map<Key,Entry>,4> groups;
    std::array<std::uint64_t,4> orders{};
    std::uint64_t now=1000;
    static constexpr std::size_t capacity=9,share=3;
    auto size() const -> std::size_t {
        std::size_t result=0; for (auto const& group:groups) result+=group.size(); return result;
    }
    auto prune(unsigned group) -> void {
        std::erase_if(groups[group],[&](auto const& item) { return item.second.discard<=now; });
    }
    auto evict(unsigned group) -> std::uint64_t {
        auto& entries=groups[group];
        auto victim=std::ranges::min_element(entries,{},[](auto const& item) {
            return std::pair{item.second.expiry,item.second.order};
        });
        require(victim!=entries.end(),"model attempted to evict empty group");
        auto order=victim->second.order; entries.erase(victim); return order;
    }
    auto admit(unsigned group,Key key,Entry entry) -> void {
        auto& own=groups[group];
        if (auto it=own.find(key);it!=own.end()) { entry.order=it->second.order; it->second=entry; return; }
        if (size()==capacity) {
            for (unsigned i=0;i<4;++i) if (i!=group) prune(i);
        }
        if (size()==capacity) {
            if (own.size()<share) {
                unsigned victim=group; std::size_t excess=0;
                for (unsigned i=0;i<4;++i) {
                    auto candidate=groups[i].size()>share ? groups[i].size()-share : 0;
                    if (candidate>excess) { victim=i; excess=candidate; }
                }
                require(excess>0 && victim!=group,"model found no lender");
                (void)evict(victim); entry.order=++orders[group];
            } else entry.order=evict(group);
        } else entry.order=++orders[group];
        own.emplace(key,entry);
    }
    auto publish(unsigned group,Key key,unsigned value,bool negative,unsigned ttl) -> void {
        if (!ttl) { for (auto& entries:groups) entries.erase(key); return; }
        Entry entry{value,negative,now+ttl*1000,now+ttl*1000+(negative ? 0 : 3000),0};
        prune(group);
        for (auto& entries:groups) if (auto it=entries.find(key);it!=entries.end()) {
            entry.order=it->second.order; it->second=entry;
        }
        if (!groups[group].contains(key)) admit(group,key,entry);
    }
    auto lookup(unsigned group,Key key) -> std::optional<Entry> {
        auto fresh=[&](Entry const& entry) { return now<entry.expiry && (entry.expiry-now)/1000; };
        auto own=groups[group].find(key);
        if (own!=groups[group].end() && fresh(own->second)) return own->second;
        std::optional<Entry> result;
        for (unsigned i=0;i<4;++i) if (i!=group) {
            auto found=groups[i].find(key);
            if (found!=groups[i].end() && fresh(found->second)) { result=found->second; break; }
        }
        if (result) { prune(group); admit(group,key,*result); }
        return result;
    }
    auto clear() -> void { for (auto& entries:groups) entries.clear(); orders.fill(0); }
};
auto differential() -> void {
    std::array<std::size_t,4> groups{1,1,0,1}; Cache cache(groups,Cache::SharedCapacity{Model::capacity},1,3000);
    auto reader=cache.reader(0); Model model; std::mt19937 random(20261030);
    for (unsigned step=0;step<30000;++step) {
        auto group=std::array<unsigned,3>{0,1,3}[random()%3];
        auto name_id=static_cast<unsigned>(random()%16),view=static_cast<unsigned>(1+random()%3);
        Model::Key model_key{view,name_id}; auto name=key(0,name_id,view);
        auto action=random()%100;
        if (action<35) {
            auto ttl=static_cast<unsigned>(1+random()%12); auto number=static_cast<unsigned>(random()%256);
            write(cache,group,name,number,model.now,ttl); model.publish(group,model_key,number,false,ttl);
        } else if (action<50) {
            auto ttl=static_cast<unsigned>(random()%13);
            write_negative(cache,group,name,model.now,ttl); model.publish(group,model_key,0,true,ttl);
        } else if (action<56) {
            auto token=cache.begin_query(group,name);
            require(token && cache.invalidate(group,name,model.now,*token),"model invalidation failed");
            model.publish(group,model_key,0,true,0);
        } else if (action<75 || action>=81) {
            auto expected=model.lookup(group,model_key); auto actual=value(cache,group,name,reader,model.now);
            auto expected_value=expected && !expected->negative ? std::optional<unsigned>{expected->value} : std::nullopt;
            require(actual==expected_value,"model positive lookup differs");
        } else if (action<78) {
            auto expected=model.lookup(group,model_key); auto actual=cache.lookup_negative(group,name,model.now,reader);
            auto expected_value=expected && expected->negative ? std::optional{d::NegativeKind::name_not_found} : std::nullopt;
            require(actual && *actual==expected_value,"model negative lookup differs");
        } else if (action<80) model.now+=random()%2001;
        else { require(cache.clear(model.now).has_value(),"model clear failed"); model.clear(); }
        if (step%13==0) {
            std::size_t count=0;
            for (unsigned i=0;i<4;++i) {
                require(cache.size(i)==model.groups[i].size(),"model group size differs"); count+=cache.size(i);
                for (unsigned v=1;v<=3;++v) for (unsigned id=0;id<16;++id)
                    require(cache.contains_member(i,key(0,id,v))==model.groups[i].contains({v,id}),"model membership differs");
            }
            require(count<=Model::capacity,"shared membership limit exceeded");
        }
    }
    std::puts("shared-capacity differential: 30000 mixed operations passed");
}
auto concurrent_readers() -> void {
    constexpr unsigned reader_count=4;
    std::array<std::size_t,2> groups{1,1}; Cache cache(groups,Cache::SharedCapacity{512},reader_count);
    std::vector<d::CacheKey> keys; keys.reserve(256);
    for (unsigned i=0;i<256;++i) { keys.push_back(key(0,i)); write(cache,0,keys.back(),1); }
    {
        auto reader=cache.reader(0);
        for (auto const& name:keys) require(value(cache,1,name,reader)==1,"concurrent seed failed");
    }
    std::atomic<bool> stop=false,failed=false; std::array<std::atomic<unsigned>,reader_count> counts{};
    std::barrier barrier(reader_count+1); std::vector<std::thread> threads;
    for (unsigned i=0;i<reader_count;++i) threads.emplace_back([&,i] {
        auto reader=cache.reader(i); barrier.arrive_and_wait(); unsigned count=0;
        try {
            while (!stop.load(std::memory_order_relaxed)) {
                if (!value(cache,i%2,keys[(count*67+i)%keys.size()],reader)) { failed=true; break; }
                ++count;
            }
        } catch (...) { failed=true; }
        counts[i]=count;
    });
    barrier.arrive_and_wait();
    try { for (unsigned i=0;i<8192;++i) write(cache,0,keys[(i*73)%keys.size()],i); }
    catch (...) { failed=true; }
    stop=true; for (auto& thread:threads) thread.join();
    require(!failed && std::ranges::all_of(counts,[](auto const& count) { return count.load()>0; }),"concurrent readers failed");
    write(cache,0,keys[0],9);
    require(cache.size(0)==256 && cache.size(1)==256 && Cache::live_nodes()==256,"concurrent history did not drain");
    std::puts("shared-capacity concurrent readers and writer passed");
}
auto concurrent_reclamation() -> void {
    constexpr unsigned reader_count=4;
    std::array<std::size_t,2> groups{1,1}; Cache cache(groups,Cache::SharedCapacity{64},reader_count);
    std::array<std::vector<d::CacheKey>,2> keys;
    for (unsigned group=0;group<2;++group)
        for (unsigned i=0;i<128;++i) keys[group].push_back(key(group,i));
    for (unsigned i=0;i<64;++i) write(cache,0,keys[0][i],i);
    std::atomic<bool> stop=false,failed=false; std::array<std::atomic<unsigned>,reader_count> counts{};
    std::barrier barrier(reader_count+1); std::vector<std::thread> threads;
    for (unsigned i=0;i<reader_count;++i) threads.emplace_back([&,i] {
        auto reader=cache.reader(i); barrier.arrive_and_wait(); unsigned count=0;
        try {
            while (!stop.load(std::memory_order_relaxed)) {
                auto group=i%2;
                (void)value(cache,group,keys[group][(count*31+i)%128],reader);
                if (cache.total_members()>64) { failed=true; break; }
                ++count;
            }
        } catch (...) { failed=true; }
        counts[i]=count;
    });
    barrier.arrive_and_wait();
    try {
        for (unsigned i=0;i<8000;++i) write(cache,1,keys[1][i%128],i);
        for (unsigned i=0;i<8000;++i) write(cache,0,keys[0][i%128],i);
    } catch (...) { failed=true; }
    stop=true; for (auto& thread:threads) thread.join();
    require(!failed && std::ranges::all_of(counts,[](auto const& count) { return count.load()>0; }) &&
            cache.size(0)==32 && cache.size(1)==32 && cache.total_members()==64,"concurrent reclaim failed");
    std::puts("shared-capacity concurrent reclamation passed");
}
}
auto main() -> int {
    try {
        borrowed_refresh_faults(); allocation_faults(); directory_growth_faults();
        differential(); concurrent_readers(); concurrent_reclamation();
        std::puts("shared-capacity faults, differential and concurrency passed"); return 0;
    } catch (std::exception const& error) { std::cerr << "shared capacity stress: " << error.what() << '\n'; return 1; }
}
