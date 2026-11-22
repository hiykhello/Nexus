import std;
import dns.message;
import dns.cache;
#include "../../src/dns-shared/group_snapshot.hpp"
#include "../../src/dns-shared/group_cache_binding.hpp"

namespace d=dns;
using Cache=dns_hp_experiment::GroupSnapshot;
auto key(unsigned group,unsigned index,unsigned view=1) -> d::CacheKey {
    return {view,std::format("group-{}-{:04}.example",group,index),1};
}
auto answer(d::CacheKey const& key,unsigned value,unsigned ttl=60) -> d::AddressAnswer {
    d::Address address{}; address.size=4; address.bytes[0]=static_cast<std::uint8_t>(value);
    address.bytes[1]=static_cast<std::uint8_t>(~address.bytes[0]);
    return {key.name,{key.name},{address},ttl};
}
auto publish(Cache& cache,std::size_t group,d::CacheKey const& key,unsigned value,unsigned ttl=60,std::uint64_t now=1000) -> bool {
    auto token=cache.begin_query(group,key);
    return token && cache.publish(group,key,answer(key,value,ttl),now,*token).has_value();
}
auto value(Cache& cache,std::size_t group,d::CacheKey const& key,Cache::Reader& reader,std::uint64_t now=1000) -> std::optional<unsigned> {
    auto result=cache.lookup(group,key,now,reader);
    if (!result) throw std::runtime_error("lookup error");
    if (!*result) return {};
    auto const& found=**result;
    if (found.canonical_name!=key.name || found.addresses.size()!=1 ||
        found.addresses[0].bytes[1]!=static_cast<std::uint8_t>(~found.addresses[0].bytes[0])) throw std::runtime_error("corrupt answer");
    return found.addresses[0].bytes[0];
}
auto fairness() -> int {
    std::array<std::size_t,2> capacities{256,256}; Cache cache(capacities,2);
    auto first=cache.reader(0),second=cache.reader(1);
    for (unsigned i=0;i<256;++i) if (!publish(cache,0,key(0,i),1,3600)) return 1;
    for (unsigned i=0;i<256;++i) if (!publish(cache,1,key(1,i),2,600)) return 2;
    for (unsigned i=0;i<256;++i) if (!publish(cache,0,key(2,i),3,7200)) return 3;
    if (cache.size(0)!=256 || cache.size(1)!=256 || Cache::live_nodes()!=512) return 4;
    for (unsigned i=0;i<256;++i)
        if (value(cache,0,key(0,i),first) || value(cache,0,key(2,i),first)!=3 || value(cache,1,key(1,i),second)!=2) return 5;
    return 0;
}
auto overlap_and_tokens() -> int {
    std::array<std::size_t,3> capacities{256,256,0}; Cache cache(capacities,2);
    auto first=cache.reader(0),second=cache.reader(1);
    for (unsigned i=0;i<256;++i) if (!publish(cache,0,key(0,i),i)) return 1;
    for (unsigned i=0;i<256;++i) if (value(cache,1,key(0,i),second)!=i) return 2;
    if (cache.size(0)!=256 || cache.size(1)!=256 || Cache::live_nodes()!=256) return 3;
    auto separate=key(0,0,2);
    if (value(cache,1,separate,second) || !publish(cache,1,separate,70)) return 4;
    auto subject=key(0,10);
    auto old=cache.begin_query(0,subject),newer=cache.begin_query(1,subject);
    if (!old || !newer || !cache.publish(1,subject,answer(subject,90),1000,*newer)) return 5;
    auto late=cache.publish(0,subject,answer(subject,80),1000,*old);
    if (late || late.error()!=d::CacheError::stale_query || value(cache,0,subject,first)!=90 || value(cache,1,subject,second)!=90) return 6;
    if (value(cache,1,separate,second)!=70 || value(cache,2,subject,second)) return 7;
    auto wrong=cache.begin_query(0,subject);
    if (!wrong) return 8;
    auto foreign=cache.publish(1,subject,answer(subject,99),1000,*wrong);
    if (foreign || foreign.error()!=d::CacheError::stale_query || !cache.cancel_query(*wrong)) return 9;
    if (!publish(cache,0,subject,7,0) || value(cache,0,subject,first) || value(cache,1,subject,second)) return 10;
    auto before_clear=cache.begin_query(0,separate);
    if (!before_clear || !cache.clear(1000) || cache.size(0) || cache.size(1) || value(cache,1,separate,second)) return 11;
    auto stale=cache.publish(0,separate,answer(separate,1),1000,*before_clear);
    if (stale || stale.error()!=d::CacheError::stale_generation) return 12;
    return 0;
}
auto binding_token_ownership() -> int {
    using Binding=dns_hp_experiment::GroupBinding;
    std::array<std::size_t,2> capacities{8,8};
    // Mirrored operations in two live snapshots intentionally create equal
    // underlying generation/query counters. Only their owners distinguish them.
    Cache a(capacities,1,5000),b(capacities,1,5000);
    Binding a0(a,0),a0_alias(a,0),a1(a,1),b0(b,0),b1(b,1);
    auto ar=a.reader(0),br=b.reader(0);
    auto item=key(0,0);
    auto rejects=[&](Binding& receiver,Binding::Token token) {
        auto rejected=[](auto const& result) { return !result && result.error()==d::CacheError::stale_query; };
        auto copy=answer(item,7),moved=answer(item,8);
        return rejected(receiver.cancel_query(token)) &&
               rejected(receiver.publish(item,copy,1000,token)) &&
               rejected(receiver.publish(item,std::move(moved),1000,token)) && !moved.addresses.empty() &&
               rejected(receiver.publish_negative(item,d::NegativeKind::no_data,30,1000,token)) &&
               rejected(receiver.invalidate(item,1000,token));
    };
    auto first=a0.begin_query(item),second=b0.begin_query(item);
    if (!first || !second || !rejects(b0,*first) || !rejects(a1,*first) ||
        !rejects(a0,*second) || !rejects(b1,*second)) return 1;
    // An equivalent binding of the same group may use a token; failed foreign
    // operations must not consume either snapshot's real registration.
    if (!a0_alias.publish(item,answer(item,1,1),1000,*first) ||
        !b0.publish(item,answer(item,2,1),1000,*second) ||
        value(a,0,item,ar)!=1 || value(b,0,item,br)!=2) return 2;
    auto missing=a0.begin_refresh(key(0,1),2000,2);
    auto bad=a0.begin_query({1,"",1});
    if (!missing || *missing || bad || bad.error()!=d::CacheError::invalid_key) return 3;
    auto refresh_a=a0.begin_refresh(item,2000,2),refresh_b=b0.begin_refresh(item,2000,2);
    if (!refresh_a || !*refresh_a || !refresh_b || !*refresh_b ||
        !rejects(b0,**refresh_a) || !rejects(a1,**refresh_a) ||
        !rejects(a0,**refresh_b) || !rejects(b1,**refresh_b)) return 4;
    if (!a0_alias.publish(item,answer(item,3),2000,**refresh_a) ||
        !b0.cancel_query(**refresh_b)) return 5;
    auto retry=b0.begin_refresh(item,2000,2);
    if (!retry || !*retry || !b0.publish(item,answer(item,4),2000,**retry) ||
        value(a,0,item,ar,2000)!=3 || value(b,0,item,br,2000)!=4) return 6;
    auto stale=a0.begin_query(item);
    if (!stale || !a.clear(2000)) return 7;
    auto cleared=a0.cancel_query(*stale);
    if (cleared || cleared.error()!=d::CacheError::stale_generation) return 8;
    return 0;
}
auto expiry_and_references() -> int {
    std::array<std::size_t,2> capacities{1,1}; Cache cache(capacities,2);
    auto first=cache.reader(0),second=cache.reader(1);
    auto x=key(0,0),y=key(0,1),z=key(0,2);
    if (!publish(cache,0,x,1,2) || value(cache,1,x,second)!=1 || Cache::live_nodes()!=1) return 1;
    auto remaining=cache.lookup(1,x,2000,second);
    if (!remaining || !*remaining || (**remaining).ttl!=1 || value(cache,1,x,second,2001)) return 2;
    if (!publish(cache,0,y,2,20,2001) || Cache::live_nodes()!=2 || value(cache,1,x,second,2001)) return 3;
    if (!publish(cache,1,z,3,30,2001) || Cache::live_nodes()!=2 || value(cache,0,x,first,2001)) return 4;
    if (value(cache,1,y,second,2001)!=2 || Cache::live_nodes()!=1) return 5;
    if (value(cache,0,y,first,22001) || value(cache,1,y,second,22001)) return 6;
    return 0;
}
auto pinned_histories() -> int {
    std::array<std::size_t,2> capacities{4,4}; Cache cache(capacities,3);
    auto first=cache.reader(0),second=cache.reader(1),current=cache.reader(2); auto item=key(0,0);
    if (!publish(cache,0,item,1) || value(cache,1,item,current)!=1) return 1;
    bool valid=true;
    auto result=cache.lookup_with_hook(1,item,1000,first,[&] {
        if (!publish(cache,0,item,2)) { valid=false; return; }
        auto nested=cache.lookup_with_hook(0,item,1000,second,[&] {
            if (!publish(cache,1,item,3) || Cache::live_nodes()!=3 || value(cache,0,item,current)!=3 ||
                value(cache,1,item,current)!=3) valid=false;
        });
        if (!nested || !*nested || (**nested).addresses[0].bytes[0]!=2) valid=false;
        if (!cache.clear(1000) || value(cache,0,item,current)) valid=false;
    });
    if (!result || *result || !valid) return 2;
    if (!publish(cache,0,item,4) || Cache::live_nodes()!=1 || value(cache,1,item,current)!=4) return 3;
    return 0;
}
auto negative_stale_refresh() -> int {
    std::array<std::size_t,2> capacities{4,4}; Cache cache(capacities,2,5000);
    auto first=cache.reader(0),second=cache.reader(1);
    auto positive=key(0,0),negative=key(0,1),other_view=key(0,1,2);
    if (!publish(cache,0,positive,1,2) || value(cache,1,positive,second)!=1) return 1;
    auto n=cache.begin_query(0,negative);
    if (!n || !cache.publish_negative(0,negative,d::NegativeKind::no_data,3,1000,*n)) return 2;
    if (value(cache,1,negative,second) || cache.size(1)!=2) return 3;
    auto cached=cache.lookup_negative(1,negative,1000,second),wrong=cache.lookup_negative(1,other_view,1000,second);
    if (!cached || *cached!=d::NegativeKind::no_data || !wrong || *wrong) return 4;
    auto stale=cache.lookup_stale(0,positive,3000,first),other=cache.lookup_stale(1,positive,3000,second);
    if (!stale || !*stale || (**stale).age_ms || (**stale).answer.ttl!=1 || !other || !*other) return 5;
    auto r=cache.begin_refresh(0,positive,3000,1),duplicate=cache.begin_refresh(1,positive,3000,1);
    if (!r || !*r || !duplicate || *duplicate) return 6;
    auto latest=cache.begin_query(1,positive);
    if (!latest || !cache.publish(1,positive,answer(positive,9),3000,*latest)) return 7;
    auto old=cache.publish(0,positive,answer(positive,2),3000,**r);
    if (old || old.error()!=d::CacheError::stale_query || value(cache,0,positive,first,3000)!=9) return 8;
    auto old_query=cache.begin_query(0,positive),new_negative=cache.begin_query(1,positive);
    if (!old_query || !new_negative || !cache.publish_negative(1,positive,d::NegativeKind::name_not_found,30,3000,*new_negative)) return 9;
    old=cache.publish(0,positive,answer(positive,3),3000,*old_query);
    auto across=cache.lookup_negative(0,positive,3000,first);
    if (old || old.error()!=d::CacheError::stale_query || !across || *across!=d::NegativeKind::name_not_found) return 10;
    if (cache.lookup_stale(0,positive,3000,first)->has_value()) return 11;
    auto before_clear=cache.begin_query(0,positive);
    if (!before_clear || !cache.clear(3000)) return 12;
    old=cache.publish(0,positive,answer(positive,4),3000,*before_clear);
    if (old || old.error()!=d::CacheError::stale_generation) return 13;
    return 0;
}
auto refresh_eviction_and_limits() -> int {
    std::array<std::size_t,2> capacities{1,1}; Cache cache(capacities,2,5000);
    auto first=cache.reader(0),second=cache.reader(1); auto x=key(0,0),y=key(0,1),z=key(0,2);
    if (!publish(cache,0,x,1,1) || value(cache,1,x,second)!=1) return 1;
    auto refresh=cache.begin_refresh(0,x,2000,1);
    if (!refresh || !*refresh) return 2;
    if (!publish(cache,0,y,2,60,2000)) return 3;
    auto late=cache.publish(0,x,answer(x,3),2000,**refresh);
    if (late || late.error()!=d::CacheError::stale_query || value(cache,0,y,first,2000)!=2) return 4;
    if (!cache.cancel_query(**refresh)) return 5;
    if (!publish(cache,0,z,4,1,2000)) return 6;
    auto none=cache.begin_refresh(0,z,3000,0);
    auto one=cache.begin_refresh(0,z,3000,1);
    auto other=cache.begin_refresh(1,x,3000,1);
    if (!none || *none || !one || !*one || !other || *other) return 7;
    if (!cache.cancel_query(**one)) return 8;
    auto deadline=cache.lookup_stale(0,z,7001,first);
    if (!deadline || *deadline) return 9;
    return 0;
}
auto out_of_order_time() -> int {
    std::array<std::size_t,2> capacities{2,2}; Cache cache(capacities,2,5000);
    auto first=cache.reader(0),second=cache.reader(1); auto item=key(0,0);
    if (!publish(cache,0,item,1,1) || value(cache,1,item,second)!=1) return 1;
    auto stale=cache.lookup_stale(0,item,2000,first);
    if (!stale || !*stale || (**stale).age_ms!=0 || value(cache,1,item,second,1000)) return 2;
    auto older=cache.lookup_stale(1,item,1000,second);
    if (!older || !*older || (**older).age_ms!=0) return 3;
    auto expired=cache.lookup_stale(0,item,7000,first);
    if (!expired || *expired || value(cache,1,item,second,1000)) return 4;
    older=cache.lookup_stale(1,item,1000,second);
    if (!older || *older) return 5;
    auto replacement=cache.begin_query(0,item);
    if (!replacement || !cache.publish(0,item,answer(item,2,1),1000,*replacement)) return 6;
    auto now=cache.lookup(1,item,1000,second);
    if (!now || !*now || (**now).ttl!=1 || (**now).addresses[0].bytes[0]!=2) return 7;
    return 0;
}
auto expiry_upper_bound() -> int {
    std::array<std::size_t,1> capacities{1}; Cache cache(capacities,1,5000); auto reader=cache.reader(0);
    auto item=key(0,0); auto max=std::numeric_limits<std::uint64_t>::max();
    if (!publish(cache,0,item,7,1,max-1500)) return 1;
    auto stale=cache.lookup_stale(0,item,max-500,reader);
    if (!stale || !*stale || (**stale).age_ms!=0 || (**stale).answer.ttl!=1) return 2;
    auto overflow=cache.begin_query(0,item);
    if (!overflow) return 3;
    auto failed=cache.publish(0,item,answer(item,8,2),max-500,*overflow);
    if (failed || failed.error()!=d::CacheError::invalid_answer || !cache.cancel_query(*overflow)) return 4;
    return 0;
}
auto budget_exhaustion() -> int {
    std::array<std::size_t,2> capacities{1,1}; auto item=key(0,0);
    std::size_t limit=0,baseline=0;
    {
        Cache measure(capacities,2); baseline=measure.charged_bytes();
        if (!publish(measure,0,item,1)) return 1;
        limit=measure.charged_bytes();
        if (limit<=baseline) return 2;
    }
    Cache cache(capacities,2,5000,limit); auto first=cache.reader(0),second=cache.reader(1);
    // The initial write temporarily needs old and new versions but the empty
    // old root contains no nodes, so its exact retained charge fits.
    if (!publish(cache,0,item,1) || cache.charged_bytes()!=limit) return 3;
    bool disabled=false,recovered=false;
    auto old=cache.lookup_with_hook(0,item,1000,first,[&] {
        auto token=cache.begin_query(0,item);
        if (!token) return;
        auto result=cache.publish_negative(0,item,d::NegativeKind::no_data,30,1000,*token);
        if (result || result.error()!=d::CacheError::disabled) return;
        disabled=true;
        auto denied=cache.begin_query(0,item);
        auto hit=cache.lookup(0,item,1000,second);
        if (denied || denied.error()!=d::CacheError::disabled || !hit || *hit) return;
        if (!cache.clear(1000)) return;
        // Old root remains pinned, so recovery is enabled but cannot reuse the
        // budget until that reader leaves. A publication is not attempted yet.
        auto after=cache.lookup(0,item,1000,second);
        recovered=after && !*after;
    });
    if (!disabled || !recovered || !old || *old || cache.charged_bytes()!=limit || cache.peak_charged_bytes()>limit) return 4;
    // A subsequent publication collects the released historical root.
    if (!publish(cache,0,item,2) || value(cache,0,item,second)!=2 || cache.peak_charged_bytes()>limit) return 5;
    if (!cache.clear(1000) || cache.charged_bytes()!=baseline) return 6;
    try { Cache too_small(capacities,2,0,baseline-1); return 7; }
    catch (Cache::BudgetExceeded const&) {}
    return 0;
}
auto budget_admission_and_clear() -> int {
    std::array<std::size_t,2> capacities{1,1}; auto item=key(0,0);
    std::size_t limit=0;
    {
        Cache measure(capacities,2); if (!publish(measure,0,item,1)) return 1;
        limit=measure.charged_bytes();
    }
    Cache cache(capacities,2,0,limit); auto first=cache.reader(0),second=cache.reader(1);
    if (!publish(cache,0,item,1)) return 2;
    auto shared=cache.lookup(1,item,1000,second);
    if (!shared || !*shared || (**shared).addresses[0].bytes[0]!=1 || cache.size(1)!=0 ||
        value(cache,0,item,first)!=1 || cache.peak_charged_bytes()>limit) return 3;
    bool cleared=false;
    auto old=cache.lookup_with_hook(0,item,1000,first,[&] { cleared=cache.clear(1000).has_value(); });
    if (!cleared || !old || *old) return 4;
    if (!publish(cache,1,item,2) || value(cache,1,item,second)!=2 || cache.peak_charged_bytes()>limit) return 5;
    return 0;
}
auto budget_multiple_histories() -> int {
    std::array<std::size_t,1> capacities{1}; auto item=key(0,0); std::size_t limit=0;
    {
        Cache measure(capacities,2); auto first=measure.reader(0),second=measure.reader(1);
        if (!publish(measure,0,item,0)) return 1;
        bool ok=true;
        auto oldest=measure.lookup_with_hook(0,item,1000,first,[&] {
            if (!publish(measure,0,item,1)) { ok=false; return; }
            auto middle=measure.lookup_with_hook(0,item,1000,second,[&] {
                if (!publish(measure,0,item,2)) ok=false;
                limit=measure.peak_charged_bytes();
            });
            if (!middle || !*middle || (**middle).addresses[0].bytes[0]!=1) ok=false;
        });
        if (!ok || !oldest || !*oldest || (**oldest).addresses[0].bytes[0]!=0) return 2;
    }
    Cache cache(capacities,2,0,limit); auto first=cache.reader(0),second=cache.reader(1);
    if (!publish(cache,0,item,0)) return 3;
    bool failed=false,cleared=false;
    auto oldest=cache.lookup_with_hook(0,item,1000,first,[&] {
        if (!publish(cache,0,item,1)) return;
        auto middle=cache.lookup_with_hook(0,item,1000,second,[&] {
            if (!publish(cache,0,item,2)) return;
            auto token=cache.begin_query(0,item); if (!token) return;
            auto next=cache.publish(0,item,answer(item,3),1000,*token);
            failed=!next && next.error()==d::CacheError::disabled;
            cleared=cache.clear(1000).has_value();
        });
        if (!middle || *middle) failed=false;
    });
    if (!failed || !cleared || !oldest || *oldest || cache.peak_charged_bytes()>limit) return 4;
    if (!publish(cache,0,item,4) || value(cache,0,item,first)!=4 || cache.peak_charged_bytes()>limit) return 5;
    return 0;
}
auto budget_query_limit() -> int {
    std::array<std::size_t,1> capacities{1}; Cache cache(capacities,1,0,1024*1024);
    auto reader=cache.reader(0); auto item=key(0,0);
    if (!publish(cache,0,item,1)) return 1;
    for (unsigned i=0;i<4096;++i) if (!cache.begin_query(0,item)) return 2;
    auto full=cache.begin_query(0,item);
    if (full || full.error()!=d::CacheError::query_limit || value(cache,0,item,reader)) return 3;
    auto denied=cache.begin_query(0,item);
    if (denied || denied.error()!=d::CacheError::disabled || !cache.clear(1000) || !cache.begin_query(0,item)) return 4;
    return 0;
}
auto budget_automatic_recovery() -> int {
    std::array<std::size_t,1> capacities{1}; auto item=key(0,0); std::size_t limit=0;
    {
        Cache measure(capacities,1); if (!publish(measure,0,item,1)) return 1;
        limit=measure.charged_bytes();
    }
    Cache cache(capacities,1,0,limit,10); auto reader=cache.reader(0);
    if (!publish(cache,0,item,1)) return 2;
    d::CacheToken stale{}; bool blocked=false;
    auto old=cache.lookup_with_hook(0,item,1000,reader,[&] {
        auto token=cache.begin_query(0,item); if (!token) return;
        stale=*token;
        auto failed=cache.publish_view(0,item.view,item.name,item.type,answer(item,2),1000,*token);
        if (failed || failed.error()!=d::CacheError::disabled) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        auto denied=cache.begin_query(0,item.view,item.name,item.type);
        blocked=!denied && denied.error()==d::CacheError::disabled;
    });
    if (!old || *old || !blocked) return 3;
    auto fresh=cache.begin_query(0,d::CacheKey(item));
    if (!fresh || fresh->generation==stale.generation ||
        !cache.publish_view(0,item.view,item.name,item.type,answer(item,2),1000,*fresh) || value(cache,0,item,reader)!=2) return 4;
    auto late=cache.publish_view(0,item.view,item.name,item.type,answer(item,3),1000,stale);
    if (late || late.error()!=d::CacheError::stale_generation) return 5;
    auto next=cache.begin_query(0,item); if (!next) return 6;
    auto failure=cache.publish_view(0,item.view,item.name,item.type,answer(item,3),1000,*next);
    auto early=cache.begin_query(0,item);
    if (failure || failure.error()!=d::CacheError::disabled || early || early.error()!=d::CacheError::disabled) return 7;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    auto retry=cache.begin_query(0,item);
    if (!retry || !cache.publish_view(0,item.view,item.name,item.type,answer(item,3),1000,*retry) || value(cache,0,item,reader)!=3 ||
        cache.peak_charged_bytes()>limit) return 8;
    return 0;
}
auto concurrent_automatic_recovery() -> int {
    constexpr unsigned writers=8;
    std::array<std::size_t,1> capacities{1}; auto item=key(0,0); std::size_t limit=0;
    {
        Cache measure(capacities,1); if (!publish(measure,0,item,1)) return 1;
        limit=measure.charged_bytes();
    }
    Cache cache(capacities,1,0,limit,5); auto reader=cache.reader(0);
    if (!publish(cache,0,item,1)) return 2;
    bool disabled=false; d::CacheToken prior{};
    auto old=cache.lookup_with_hook(0,item,1000,reader,[&] {
        auto token=cache.begin_query(0,item); if (!token) return;
        prior=*token;
        auto failed=cache.publish_view(0,item.view,item.name,item.type,answer(item,2),1000,*token);
        disabled=!failed && failed.error()==d::CacheError::disabled;
    });
    if (!old || *old || !disabled) return 3;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    std::barrier start(writers+1); std::array<std::expected<d::CacheToken,d::CacheError>,writers> tokens;
    std::vector<std::thread> threads;
    for (unsigned i=0;i<writers;++i) threads.emplace_back([&,i] {
        start.arrive_and_wait(); tokens[i]=cache.begin_query(0,item.view,item.name,item.type);
    });
    start.arrive_and_wait(); for (auto& thread:threads) thread.join();
    std::set<std::uint64_t> unique;
    for (auto const& token:tokens) {
        if (!token || token->generation!=prior.generation+1 || !unique.insert(token->query).second) return 4;
    }
    auto highest=*std::ranges::max_element(tokens,{},[](auto const& token) { return token->query; });
    if (!cache.publish_view(0,item.view,item.name,item.type,answer(item,3),1000,*highest) || value(cache,0,item,reader)!=3) return 5;
    auto stale=cache.publish_view(0,item.view,item.name,item.type,answer(item,4),1000,prior);
    if (stale || stale.error()!=d::CacheError::stale_generation || cache.peak_charged_bytes()>limit) return 6;
    return 0;
}
auto bounded_input_storage() -> int {
    std::array<std::size_t,1> capacities{1}; Cache cache(capacities,1,0,65536); auto reader=cache.reader(0);
    auto name=std::string(63,'a')+"."+std::string(63,'b')+"."+std::string(63,'c')+"."+std::string(61,'d');
    if (name.size()!=253) return 1;
    d::CacheKey item{1,name,1},query=item; query.name+='.'; query.name.reserve(1<<20);
    auto token=cache.begin_query(0,std::move(query));
    if (!token) return 2;
    d::Address address{}; address.size=4; address.bytes[0]=42;
    d::AddressAnswer input{std::string(254,'z'),{}, {},60};
    input.canonical_name.reserve(1<<20); input.chain.reserve(32); input.addresses.reserve(256);
    for (unsigned i=0;i<16;++i) { input.chain.emplace_back(254,static_cast<char>('a'+i)); input.chain.back().reserve(1<<16); }
    for (unsigned i=0;i<128;++i) input.addresses.push_back(address);
    auto oversized=item; oversized.name.reserve(1<<20);
    if (!cache.publish(0,std::move(oversized),std::move(input),1000,*token)) return 3;
    auto found=cache.lookup(0,item,1000,reader);
    if (!found || !*found || (**found).canonical_name!=std::string(254,'z') || (**found).chain.size()!=16 ||
        (**found).addresses.size()!=128 || (**found).addresses.back().bytes[0]!=42 || cache.peak_charged_bytes()>20000) return 4;
    for (unsigned i=0;i<16;++i) if ((**found).chain[i]!=std::string(254,static_cast<char>('a'+i))) return 5;
    // Invalid inputs do not install truncated records or disable a valid entry.
    for (unsigned invalid=0;invalid<7;++invalid) {
        auto next=cache.begin_query(0,item); if (!next) return 6;
        auto bad=answer(item,1);
        if (invalid==0) bad.addresses.clear();
        if (invalid==1) bad.addresses.resize(129,address);
        if (invalid==2) bad.chain.resize(17,"a");
        if (invalid==3) bad.canonical_name=std::string(255,'a');
        if (invalid==4) bad.chain[0]=std::string(255,'a');
        if (invalid==5) bad.addresses[0].size=16;
        if (invalid==6) bad.ttl.reset();
        auto rejected=cache.publish(0,item,std::move(bad),1000,*next);
        if (rejected || rejected.error()!=d::CacheError::invalid_answer || !cache.cancel_query(*next)) return 7;
        auto still=cache.lookup(0,item,1000,reader);
        if (!still || !*still || (**still).addresses.size()!=128) return 8;
    }
    auto invalid=item; invalid.name+='a';
    auto rejected=cache.begin_query(0,std::move(invalid));
    if (rejected || rejected.error()!=d::CacheError::invalid_key || !cache.clear(1000)) return 9;
    return 0;
}
auto budget_threaded_recovery() -> int {
    std::array<std::size_t,1> capacities{1}; auto item=key(0,0); std::size_t limit=0;
    {
        Cache measure(capacities,2); if (!publish(measure,0,item,1)) return 1;
        limit=measure.charged_bytes();
    }
    Cache cache(capacities,2,0,limit); auto current=cache.reader(1);
    if (!publish(cache,0,item,1)) return 2;
    std::atomic<bool> entered=false,release=false,failed=false;
    std::thread old_reader([&] {
        try {
            auto reader=cache.reader(0);
            auto old=cache.lookup_with_hook(0,item,1000,reader,[&] {
                entered=true; entered.notify_one(); release.wait(false);
            });
            if (!old || *old) failed=true;
        } catch (...) { failed=true; entered=true; entered.notify_one(); }
    });
    while (!entered.load()) entered.wait(false);
    auto token=cache.begin_query(0,item);
    auto rejected=token ? cache.publish_negative(0,item,d::NegativeKind::no_data,30,1000,*token)
                        : std::expected<void,d::CacheError>(std::unexpected(d::CacheError::stale_query));
    auto missing=cache.lookup(0,item,1000,current);
    if (rejected || rejected.error()!=d::CacheError::disabled || !missing || *missing || !cache.clear(1000)) failed=true;
    release=true; release.notify_one(); old_reader.join();
    if (failed || !publish(cache,0,item,2) || value(cache,0,item,current)!=2 || cache.peak_charged_bytes()>limit) return 3;
    return 0;
}
auto single_group_differential() -> int {
    std::array<std::size_t,1> capacities{64}; Cache cache(capacities,1,5000); auto reader=cache.reader(0);
    d::AddressCache reference(64,5000,true); std::vector<d::CacheKey> keys;
    for (unsigned i=0;i<96;++i) keys.push_back(key(0,i,1+i%3));
    std::mt19937 rng(20261030); std::uint64_t now=1000;
    auto same_state=[&](d::CacheKey const& item) {
        auto a=reference.lookup(item,now),b=cache.lookup(0,item,now,reader);
        if (!a || !b || a->has_value()!=b->has_value()) return false;
        if (*a && ((**a).canonical_name!=(**b).canonical_name || (**a).ttl!=(**b).ttl ||
                   (**a).addresses[0].bytes!=(**b).addresses[0].bytes)) return false;
        auto an=reference.lookup_negative(item,now),bn=cache.lookup_negative(0,item,now,reader);
        if (!an || !bn || *an!=*bn) return false;
        auto as=reference.lookup_stale(item,now),bs=cache.lookup_stale(0,item,now,reader);
        if (!as || !bs || as->has_value()!=bs->has_value()) return false;
        return !*as || ((**as).age_ms==(**bs).age_ms && (**as).answer.ttl==(**bs).answer.ttl &&
                        (**as).answer.addresses[0].bytes==(**bs).answer.addresses[0].bytes);
    };
    for (unsigned step=0;step<30000;++step) {
        auto const& item=keys[rng()%keys.size()]; auto operation=rng()%12;
        if (operation<5) {
            auto first=reference.begin_query(item),second=cache.begin_query(0,item);
            auto ttl=static_cast<unsigned>(rng()%16);
            if (!first || !second || first->generation!=second->generation || first->query!=second->query) return 1;
            auto a=reference.publish(item,answer(item,step,ttl),now,*first),b=cache.publish(0,item,answer(item,step,ttl),now,*second);
            if (!a || !b) return 2;
        } else if (operation<7) {
            auto first=reference.begin_query(item),second=cache.begin_query(0,item);
            auto ttl=static_cast<unsigned>(rng()%16);
            auto kind=step%2 ? d::NegativeKind::no_data : d::NegativeKind::name_not_found;
            if (!first || !second || !reference.publish_negative(item,kind,ttl,now,*first) ||
                !cache.publish_negative(0,item,kind,ttl,now,*second)) return 3;
        } else if (operation==7) {
            auto first=reference.begin_query(item),second=cache.begin_query(0,item);
            if (!first || !second || !reference.invalidate(item,now,*first) || !cache.invalidate(0,item,now,*second)) return 4;
        } else if (operation==8) {
            auto first=reference.begin_refresh(item,now,4),second=cache.begin_refresh(0,item,now,4);
            if (!first || !second || first->has_value()!=second->has_value()) return 5;
            if (*first) {
                if ((**first).generation!=(**second).generation || (**first).query!=(**second).query) return 6;
                if (step%2) {
                    if (!reference.cancel_query(**first) || !cache.cancel_query(**second)) return 7;
                } else if (!reference.publish(item,answer(item,step,10),now,**first) ||
                           !cache.publish(0,item,answer(item,step,10),now,**second)) return 8;
            }
        } else if (operation==9) {
            if (!reference.clear(now) || !cache.clear(now)) return 9;
        } else now+=rng()%1501;
        if (!same_state(item) || !same_state(keys[rng()%keys.size()])) return 10;
    }
    for (auto const& item:keys) if (!same_state(item)) return 11;
    return 0;
}
auto capacity_4352() -> int {
    std::array<std::size_t,17> capacities; capacities.fill(256); Cache cache(capacities,1); auto reader=cache.reader(0);
    for (unsigned group=0;group<17;++group) for (unsigned i=0;i<256;++i)
        if (!publish(cache,group,key(group,i),group,60)) return 1;
    if (Cache::live_nodes()!=4352) return 2;
    for (unsigned group=0;group<17;++group) for (unsigned i=0;i<256;++i)
        if (value(cache,group,key(group,i),reader)!=group) return 3;
    for (unsigned i=0;i<256;++i) if (!publish(cache,0,key(17,i),99,120)) return 4;
    for (unsigned group=1;group<17;++group) for (unsigned i=0;i<256;++i)
        if (value(cache,group,key(group,i),reader)!=group) return 5;
    if (cache.size(0)!=256 || Cache::live_nodes()!=4352) return 6;
    return 0;
}
auto concurrent_updates() -> int {
    constexpr unsigned readers=8;
    std::array<std::size_t,2> capacities{16,16}; Cache cache(capacities,readers);
    auto item=key(0,0); if (!publish(cache,0,item,0)) return 1;
    std::atomic<bool> failed=false; std::barrier ready(readers+1); std::vector<std::thread> threads;
    for (unsigned t=0;t<readers;++t) threads.emplace_back([&,t] {
        try {
            auto reader=cache.reader(t); ready.arrive_and_wait();
            for (unsigned i=0;i<10000 && !failed.load();++i) {
                auto result=cache.lookup(t%2,item,1000,reader);
                if (!result) { failed=true; break; }
                if (*result) {
                    auto const& found=**result;
                    if (found.canonical_name!=item.name || found.addresses.size()!=1 ||
                        found.addresses[0].bytes[1]!=static_cast<std::uint8_t>(~found.addresses[0].bytes[0])) failed=true;
                }
            }
        } catch (...) { failed=true; }
    });
    ready.arrive_and_wait();
    for (unsigned i=0;i<5000 && !failed.load();++i) {
        if (i%127==0 && !cache.clear(1000)) { failed=true; break; }
        if (!publish(cache,i%2,item,i)) { failed=true; break; }
    }
    for (auto& thread:threads) thread.join();
    return failed ? 2 : 0;
}
auto concurrent_semantics() -> int {
    constexpr unsigned readers=8;
    std::array<std::size_t,2> capacities{16,16}; Cache cache(capacities,readers,5000);
    auto item=key(0,0); if (!publish(cache,0,item,0,1)) return 1;
    std::atomic<bool> failed=false; std::barrier ready(readers+1); std::vector<std::thread> threads;
    for (unsigned t=0;t<readers;++t) threads.emplace_back([&,t] {
        try {
            auto reader=cache.reader(t); ready.arrive_and_wait();
            for (unsigned i=0;i<8000 && !failed.load();++i) {
                auto now=1000+static_cast<std::uint64_t>(i)*2;
                auto result=cache.lookup(t%2,item,now,reader);
                auto negative=cache.lookup_negative(t%2,item,now,reader);
                auto stale=cache.lookup_stale(t%2,item,now,reader);
                if (!result || !negative || !stale) { failed=true; break; }
                auto valid=[&](d::AddressAnswer const& answer) {
                    return answer.canonical_name==item.name && answer.addresses.size()==1 &&
                        answer.addresses[0].bytes[1]==static_cast<std::uint8_t>(~answer.addresses[0].bytes[0]);
                };
                if ((*result && !valid(**result)) || (*stale && (!valid((**stale).answer) || (**stale).answer.ttl!=1))) failed=true;
            }
        } catch (...) { failed=true; }
    });
    ready.arrive_and_wait();
    for (unsigned i=0;i<5000 && !failed.load();++i) {
        auto now=1000+static_cast<std::uint64_t>(i)*4;
        if (i%127==0 && !cache.clear(now)) { failed=true; break; }
        auto token=cache.begin_query(i%2,item);
        if (!token) { failed=true; break; }
        auto result=i%3 ? cache.publish(i%2,item,answer(item,i,1+i%3),now,*token)
                        : cache.publish_negative(i%2,item,d::NegativeKind::no_data,1+i%3,now,*token);
        if (!result) { failed=true; break; }
        if (i%11==0) {
            auto refresh=cache.begin_refresh(i%2,item,now+4000,8);
            if (!refresh || (*refresh && !cache.cancel_query(**refresh))) { failed=true; break; }
        }
    }
    for (auto& thread:threads) thread.join();
    return failed ? 2 : 0;
}
int main() {
    if (auto result=fairness()) { std::cerr<<"group fairness "<<result<<'\n'; return 1; }
    if (auto result=overlap_and_tokens()) { std::cerr<<"group overlap "<<result<<'\n'; return 2; }
    if (auto result=binding_token_ownership()) { std::cerr<<"group binding ownership "<<result<<'\n'; return 22; }
    if (auto result=expiry_and_references()) { std::cerr<<"group expiry "<<result<<'\n'; return 3; }
    if (auto result=pinned_histories()) { std::cerr<<"group history "<<result<<'\n'; return 4; }
    if (auto result=negative_stale_refresh()) { std::cerr<<"group negative/stale "<<result<<'\n'; return 5; }
    if (auto result=refresh_eviction_and_limits()) { std::cerr<<"group refresh eviction "<<result<<'\n'; return 6; }
    if (auto result=out_of_order_time()) { std::cerr<<"group out-of-order time "<<result<<'\n'; return 7; }
    if (auto result=expiry_upper_bound()) { std::cerr<<"group upper bound "<<result<<'\n'; return 8; }
    if (auto result=budget_exhaustion()) { std::cerr<<"group budget "<<result<<'\n'; return 9; }
    if (auto result=budget_admission_and_clear()) { std::cerr<<"group admission budget "<<result<<'\n'; return 10; }
    if (auto result=budget_multiple_histories()) { std::cerr<<"group history budget "<<result<<'\n'; return 11; }
    if (auto result=budget_query_limit()) { std::cerr<<"group query budget "<<result<<'\n'; return 12; }
    if (auto result=budget_automatic_recovery()) { std::cerr<<"group automatic recovery "<<result<<'\n'; return 20; }
    if (auto result=concurrent_automatic_recovery()) { std::cerr<<"group concurrent recovery "<<result<<'\n'; return 21; }
    if (auto result=bounded_input_storage()) { std::cerr<<"group input bounds "<<result<<'\n'; return 19; }
    if (auto result=budget_threaded_recovery()) { std::cerr<<"group threaded budget "<<result<<'\n'; return 13; }
    if (auto result=single_group_differential()) { std::cerr<<"group differential "<<result<<'\n'; return 14; }
    if (auto result=capacity_4352()) { std::cerr<<"group capacity "<<result<<'\n'; return 15; }
    if (auto result=concurrent_updates()) { std::cerr<<"group concurrency "<<result<<'\n'; return 16; }
    if (auto result=concurrent_semantics()) { std::cerr<<"group concurrent semantics "<<result<<'\n'; return 17; }
    if (Cache::live_nodes()) { std::cerr<<"group nodes leaked\n"; return 18; }
    std::puts("group snapshot: differential, fairness, sharing, negative, stale/refresh, expiry, histories, 4352 capacity and concurrency passed");
}
