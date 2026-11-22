#include "bounded_table.hpp"
import std;
import dns.cache;
import dns.message;
#if defined(DNS_MODULE_SNAPSHOT_EXPERIMENT)
class ModuleSnapshotCache : public dns::AddressCache {
public:
    ModuleSnapshotCache(std::size_t capacity,std::uint64_t stale,std::size_t readers)
        : AddressCache(capacity,stale,true,readers) {}
};
#elif defined(DNS_PAGED_SEMANTIC_EXPERIMENT)
#include "paged_semantic.hpp"
#elif defined(DNS_SNAPSHOT_EXPERIMENT)
#include "snapshot_cache.hpp"
#else
#include "semantic_cache.hpp"
#endif

namespace d=dns;
#ifdef DNS_MODULE_SNAPSHOT_EXPERIMENT
using SemanticCache=ModuleSnapshotCache;
#elif defined(DNS_PAGED_SEMANTIC_EXPERIMENT)
using SemanticCache=dns_hp_experiment::PagedSemanticCache;
#elif defined(DNS_SNAPSHOT_EXPERIMENT)
#ifdef DNS_ORDERED_SNAPSHOT_EXPERIMENT
#ifdef DNS_ORDERED_SCALED_EXPERIMENT
using SemanticCache=dns_hp_experiment::OrderedSnapshotCache512;
#else
using SemanticCache=dns_hp_experiment::OrderedSnapshotCache;
#endif
#else
using SemanticCache=dns_hp_experiment::SnapshotCache;
#endif
#else
using dns_hp_experiment::SemanticCache;
#endif
#ifndef DNS_MODULE_SNAPSHOT_EXPERIMENT
namespace dns_hp_experiment {
thread_local bool pause_advance=false;
std::atomic<bool> advance_ready=false,advance_resume=false;
void after_advance_for_test() {
    if (!pause_advance) return;
    pause_advance=false; advance_ready=true;
    while (!advance_resume.load()) std::this_thread::yield();
}
#ifdef DNS_SNAPSHOT_EXPERIMENT
thread_local bool pause_snapshot_load=false;
std::atomic<void const*> loaded_snapshot=nullptr;
std::atomic<bool> resume_snapshot_load=false;
void after_snapshot_load_for_test(void const* snapshot) {
    if (!pause_snapshot_load) return;
    pause_snapshot_load=false;
    loaded_snapshot=snapshot;
    while (!resume_snapshot_load.load()) std::this_thread::yield();
}
#endif
}
#endif
template<class A,class B> auto same_status(A const& a,B const& b) -> bool {
    return a.has_value()==b.has_value() && (a.has_value() || a.error()==b.error());
}
auto same_token(d::CacheToken a,d::CacheToken b) -> bool { return a.generation==b.generation && a.query==b.query; }
auto same_answer(d::AddressAnswer const& a,d::AddressAnswer const& b) -> bool {
    if (a.canonical_name!=b.canonical_name || a.chain!=b.chain || a.ttl!=b.ttl || a.addresses.size()!=b.addresses.size()) return false;
    for (std::size_t i=0;i<a.addresses.size();++i)
        if (a.addresses[i].size!=b.addresses[i].size || a.addresses[i].bytes!=b.addresses[i].bytes) return false;
    return true;
}
auto answer(d::CacheKey key,std::uint32_t ttl,std::uint8_t value) -> d::AddressAnswer {
    (void)d::canonicalize_name(key.name);
    d::Address address{}; address.size=key.type==1 ? 4 : 16; address.bytes[0]=value;
    address.bytes[1]=static_cast<std::uint8_t>(~value);
    address.bytes[2]=static_cast<std::uint8_t>(key.view);
    address.bytes[3]=static_cast<std::uint8_t>(key.type);
    return {key.name,{key.name},{address},ttl};
}
auto check_lookups(d::AddressCache& reference,SemanticCache& candidate,SemanticCache::Reader& reader,
                   d::CacheKey const& key,std::uint64_t now) -> bool {
    auto a=reference.lookup(key,now),b=candidate.lookup(key,now,reader);
    if (!same_status(a,b) || (a && (a->has_value()!=b->has_value() || (*a && !same_answer(**a,**b))))) return false;
    auto an=reference.lookup_negative(key,now),bn=candidate.lookup_negative(key,now,reader);
    return same_status(an,bn) && (!an || *an==*bn);
}
auto check_stale(d::AddressCache& reference,SemanticCache& candidate,SemanticCache::Reader& reader,d::CacheKey const& key,std::uint64_t now) -> bool {
#ifdef DNS_MODULE_SNAPSHOT_EXPERIMENT
    auto a=reference.lookup_stale(key,now),b=candidate.lookup_stale(key,now,reader);
#else
    (void)reader;
    auto a=reference.lookup_stale(key,now),b=candidate.lookup_stale(key,now);
#endif
    if (!same_status(a,b)) return false;
    if (!a) return true;
    if (a->has_value()!=b->has_value()) return false;
    return !*a || ((**a).age_ms==(**b).age_ms && same_answer((**a).answer,(**b).answer));
}
#ifdef DNS_ORDERED_SCALED_EXPERIMENT
auto scaled_capacity() -> int {
    d::AddressCache reference(512,5000,true);
    SemanticCache candidate(512,5000,1);
    auto reader=candidate.reader(0);
    std::vector<d::CacheKey> keys;
    for (unsigned i=0;i<768;++i) keys.push_back({1,std::format("scaled-{:04}.test",i),1});
    for (unsigned i=0;i<keys.size();++i) {
        auto first=reference.begin_query(keys[i]),second=candidate.begin_query(keys[i]);
        if (!first || !second || !same_token(*first,*second) ||
            !reference.publish(keys[i],answer(keys[i],1000+i,i),1000,*first) ||
            !candidate.publish(keys[i],answer(keys[i],1000+i,i),1000,*second)) return 1;
    }
    if (reference.size()!=512 || candidate.size()!=512) return 2;
    for (auto const& key:keys) if (!check_lookups(reference,candidate,reader,key,1000)) return 3;
    return 0;
}
#endif
auto differential() -> int {
    d::AddressCache reference(8,5000,true);
    SemanticCache candidate(8,5000,1);
    auto reader=candidate.reader(0);
    std::vector<d::CacheKey> keys;
    for (int i=0;i<16;++i) keys.push_back({static_cast<std::uint64_t>(1+i%2),
        "Host-"+std::to_string(i)+".Example.Test.",static_cast<std::uint16_t>(i%3 ? 1 : 28)});
    keys.push_back({1,"bad..test",1}); keys.push_back({1,"bad.test",99});
    struct Pair { d::CacheKey key; d::CacheToken reference,candidate; };
    std::vector<Pair> tokens;
    std::uint64_t state=0x123456789abcdefULL,now=100000;
    auto random=[&] { state^=state<<13; state^=state>>7; state^=state<<17; return state; };
    for (int step=0;step<30000;++step) {
        now+=random()%201;
        auto sampled=random()%5==0 && now>3000 ? now-3000 : now;
        auto key=keys[random()%keys.size()];
        auto operation=random()%100;
        bool equal=true;
        if (operation<20) {
            auto a=reference.begin_query(key),b=candidate.begin_query(key);
            equal=same_status(a,b) && (!a || same_token(*a,*b));
            if (equal && a) tokens.push_back({key,*a,*b});
        } else if (operation<31) {
            auto a=reference.begin_refresh(key,sampled,2),b=candidate.begin_refresh(key,sampled,2);
            equal=same_status(a,b) && (!a || (a->has_value()==b->has_value() && (!*a || same_token(**a,**b))));
            if (equal && a && *a) tokens.push_back({key,**a,**b});
        } else if (operation<69 && !tokens.empty()) {
            auto pair=tokens[random()%tokens.size()];
            if (random()%7) key=pair.key;
            if (operation<51) {
                auto value=answer(key,random()%8,random()%256);
                auto a=reference.publish(key,value,sampled,pair.reference),b=candidate.publish(key,value,sampled,pair.candidate);
                equal=same_status(a,b);
            } else if (operation<60) {
                auto kind=random()%2 ? d::NegativeKind::name_not_found : d::NegativeKind::no_data;
                auto ttl=random()%8;
                auto a=reference.publish_negative(key,kind,ttl,sampled,pair.reference),b=candidate.publish_negative(key,kind,ttl,sampled,pair.candidate);
                equal=same_status(a,b);
            } else if (operation<65) {
                auto a=reference.invalidate(key,sampled,pair.reference),b=candidate.invalidate(key,sampled,pair.candidate);
                equal=same_status(a,b);
            } else {
                auto a=reference.cancel_query(pair.reference),b=candidate.cancel_query(pair.candidate);
                equal=same_status(a,b);
            }
        } else if (operation<71) {
            auto a=reference.clear(sampled),b=candidate.clear(sampled); equal=same_status(a,b);
        } else if (operation<81) equal=check_stale(reference,candidate,reader,key,sampled);
        else equal=check_lookups(reference,candidate,reader,key,sampled);
        if (equal) equal=check_lookups(reference,candidate,reader,keys[random()%keys.size()],sampled);
        if (!equal || reference.size()!=candidate.size()) {
            std::cerr<<"differential mismatch at "<<step<<" operation "<<operation<<'\n'; return 1;
        }
        if (tokens.size()>1000) tokens.erase(tokens.begin(),tokens.begin()+500);
    }
    return 0;
}
#ifndef DNS_MODULE_SNAPSHOT_EXPERIMENT
auto clear_race() -> int {
    SemanticCache cache(8,5000,2);
    d::CacheKey key{1,"clear.test",1};
    auto old=cache.begin_query(key);
    if (!old || !cache.publish(key,answer(key,60,1),1000,*old)) return 1;
    std::atomic<bool> paused=false,resume=false;
    std::optional<std::expected<std::optional<d::AddressAnswer>,d::CacheError>> result;
    std::thread reader([&] {
        auto handle=cache.reader(0); bool first=true;
        result=cache.lookup_with_hook(key,1000,handle,[&] {
            if (!first) return;
            first=false; paused=true;
            while (!resume.load()) std::this_thread::yield();
        });
    });
    while (!paused.load()) std::this_thread::yield();
    if (!cache.clear(2000)) std::abort();
    auto fresh=cache.begin_query(key);
    if (!fresh || !cache.publish(key,answer(key,60,2),2000,*fresh)) std::abort();
    resume=true; reader.join();
    if (!result || !*result || !(**result) || (***result).addresses[0].bytes[0]!=
#ifdef DNS_SNAPSHOT_EXPERIMENT
        1
#else
        2
#endif
    ) return 2;
    return 0;
}
auto clock_race() -> int {
    SemanticCache cache(8,0,1);
    d::CacheKey old_key{1,"old.test",1},new_key{1,"new.test",1};
    auto a=cache.begin_query(old_key),b=cache.begin_query(new_key);
    if (!a || !b || !cache.publish(old_key,answer(old_key,2,1),1000,*a) ||
        !cache.publish(new_key,answer(new_key,30,1),1000,*b)) return 1;
    auto next=cache.begin_query(new_key); if (!next) return 2;
    std::atomic<bool> reader_started=false,reader_done=false;
    std::optional<std::expected<std::optional<d::AddressAnswer>,d::CacheError>> result;
    std::thread writer([&] {
        dns_hp_experiment::pause_advance=true;
        if (!cache.publish(new_key,answer(new_key,30,2),4000,*next)) std::abort();
    });
    while (!dns_hp_experiment::advance_ready.load()) std::this_thread::yield();
    std::thread reader([&] {
        auto handle=cache.reader(0); reader_started=true;
        result=cache.lookup(new_key,1000,handle); reader_done=true;
    });
    while (!reader_started.load()) std::this_thread::yield();
#ifdef DNS_SNAPSHOT_EXPERIMENT
    auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(1);
    while (!reader_done.load() && std::chrono::steady_clock::now()<deadline) std::this_thread::yield();
#else
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
#endif
    auto completed_early=reader_done.load();
    dns_hp_experiment::advance_resume=true; writer.join(); reader.join();
#ifdef DNS_SNAPSHOT_EXPERIMENT
    if (!completed_early || !result || !*result || !(**result) || (***result).addresses[0].bytes[0]!=1) return 3;
#else
    if (completed_early || !result || !*result || !(**result) || (***result).addresses[0].bytes[0]!=2) return 3;
#endif
    auto handle=cache.reader(0);
    auto expired=cache.lookup(old_key,1000,handle);
    if (!expired || *expired) return 4;
    auto fresh=cache.lookup(new_key,1000,handle);
    if (!fresh || !*fresh || (**fresh).addresses[0].bytes[0]!=2) return 5;
    return 0;
}
#endif
auto concurrent_updates() -> int {
    SemanticCache cache(128,5000,8);
    std::vector<d::CacheKey> keys;
    for (unsigned i=0;i<128;++i) keys.push_back({1+i%2,"name-"+std::to_string(i/4)+".test",
        static_cast<std::uint16_t>(i%4<2 ? 1 : 28)});
    for (auto const& key:keys) {
        auto token=cache.begin_query(key);
        if (!token || !cache.publish(key,answer(key,60,1),1000,*token)) return 1;
    }
    std::atomic<bool> failed=false;
    std::barrier gate(9);
    std::vector<std::thread> readers;
    for (unsigned t=0;t<8;++t) readers.emplace_back([&,t] {
        auto handle=cache.reader(t);
        std::uint64_t rng=1234+t;
        gate.arrive_and_wait();
        for (int i=0;i<50000;++i) {
            rng^=rng<<13; rng^=rng>>7; rng^=rng<<17;
            auto const& key=keys[rng%keys.size()];
            auto result=cache.lookup(key,1000,handle);
            if (!result) { failed=true; continue; }
            if (*result) {
                auto const& value=**result;
                if (value.canonical_name!=key.name || value.chain.size()!=1 || value.chain[0]!=key.name ||
                    value.addresses.size()!=1 || value.addresses[0].size!=(key.type==1 ? 4 : 16) ||
                    value.addresses[0].bytes[1]!=static_cast<std::uint8_t>(~value.addresses[0].bytes[0]) ||
                    value.addresses[0].bytes[2]!=key.view || value.addresses[0].bytes[3]!=key.type || !value.ttl || !*value.ttl)
                    failed=true;
            }
        }
    });
    gate.arrive_and_wait();
    for (unsigned i=0;i<6000;++i) {
        if (i%257==0 && !cache.clear(1000+i)) std::abort();
        auto const& key=keys[i%keys.size()];
        auto token=cache.begin_query(key);
        if (!token || !cache.publish(key,answer(key,60,static_cast<std::uint8_t>(i)),1000+i,*token)) std::abort();
    }
    for (auto& reader:readers) reader.join();
    return failed ? 2 : 0;
}
#ifdef DNS_MODULE_SNAPSHOT_EXPERIMENT
auto module_reader_contract() -> int {
    try { d::AddressCache invalid(257,0,true,1); return 1; } catch (std::invalid_argument const&) {}
    try { d::AddressCache invalid(1,0,false,1); return 2; } catch (std::invalid_argument const&) {}
    try { d::AddressCache invalid(1,0,true,258); return 3; } catch (std::out_of_range const&) {}
    d::AddressCache baseline(1);
    try { (void)baseline.reader(0); return 4; } catch (std::logic_error const&) {}
    d::AddressCache cache(2,5000,true,1),other(2,5000,true,1);
    auto reader=cache.reader(0),foreign=other.reader(0);
    try { (void)cache.reader(0); return 5; } catch (std::logic_error const&) {}
    try { (void)cache.reader(1); return 6; } catch (std::out_of_range const&) {}
    d::CacheKey key{1,"module.test",1};
    auto token=cache.begin_query(key);
    if (!token || !cache.publish(key,answer(key,1,42),1000,*token)) return 7;
    auto no_reader=cache.lookup(key,1000);
    if (no_reader || no_reader.error()!=d::CacheError::reader_required) return 8;
    auto no_negative_reader=cache.lookup_negative(key,1000);
    if (no_negative_reader || no_negative_reader.error()!=d::CacheError::reader_required) return 9;
    auto no_stale_reader=cache.lookup_stale(key,2000);
    if (no_stale_reader || no_stale_reader.error()!=d::CacheError::reader_required) return 10;
    try { (void)cache.lookup(key,1000,foreign); return 11; } catch (std::invalid_argument const&) {}
    try { (void)cache.lookup_negative(key,1000,foreign); return 12; } catch (std::invalid_argument const&) {}
    try { (void)cache.lookup_stale(key,2000,foreign); return 13; } catch (std::invalid_argument const&) {}
    auto hit=cache.lookup(key,1000,reader);
    auto stale=cache.lookup_stale(key,2000,reader);
    if (!hit || !*hit || (**hit).addresses[0].bytes[0]!=42 || !stale || !*stale || (**stale).answer.ttl!=1) return 14;
    auto moved=std::move(reader);
    try { (void)cache.lookup(key,1000,reader); return 15; } catch (std::invalid_argument const&) {}
    auto miss=cache.lookup(key,2000,moved);
    if (!miss || *miss) return 16;
    token=cache.begin_query(key);
    if (!token || !cache.publish_negative(key,d::NegativeKind::no_data,10,2000,*token)) return 17;
    auto negative=cache.lookup_negative(key,2000,moved);
    if (!negative || *negative!=d::NegativeKind::no_data) return 18;
    return 0;
}
#endif

#ifdef DNS_MODULE_SNAPSHOT_EXPERIMENT
auto module_oversized_inputs() -> int {
    for (bool snapshot:{false,true}) {
        d::AddressCache cache(2,5000,true,snapshot ? 1 : 0);
        std::optional<d::AddressCache::Reader> reader;
        if (snapshot) reader.emplace(cache.reader(0));
        d::CacheKey key{1,"oversized.example.test",1},pending=key;
        pending.name.reserve(1024*1024);
        auto token=cache.begin_query(std::move(pending));
        if (!token) return 1;
        auto value=answer(key,60,42);
        value.canonical_name.reserve(1024*1024);
        value.chain.reserve(64);
        value.chain[0].reserve(1024*1024);
        value.addresses.reserve(256);
        if (!cache.publish(key,std::move(value),1000,*token)) return 2;
        auto result=reader ? cache.lookup(key,1000,*reader) : cache.lookup(key,1000);
        if (!result || !*result || (**result).canonical_name!=key.name ||
            (**result).chain.size()!=1 || (**result).chain[0]!=key.name ||
            (**result).addresses.size()!=1 || (**result).addresses[0].bytes[0]!=42) return 3;
        key.name.reserve(1024*1024);
        auto refresh=cache.begin_refresh(std::move(key),61001,1);
        if (!refresh || !*refresh || !cache.cancel_query(**refresh)) return 4;
    }
    return 0;
}
auto module_snapshot_pool() -> int {
    using State=d::detail::BasicSnapshotState<true>;
    {
        State large(0,0,257);
        std::vector<State::Reader> readers;
        readers.reserve(257);
        for (std::size_t i=0;i<257;++i) readers.emplace_back(large.reader(i));
    }
    constexpr std::size_t count=32;
    State cache(1,0,count);
    d::CacheKey key{1,"held.example.test",1};
    auto publish=[&](std::uint8_t revision) {
        auto token=cache.begin_query(key);
        return token && cache.publish(key,answer(key,60,revision),1000,*token).has_value();
    };
    if (!publish(0)) return 1;
    std::atomic<std::size_t> entered=0;
    std::atomic<bool> release=false,failed=false;
    std::vector<std::thread> readers;
    readers.reserve(count);
    for (std::size_t i=0;i<count && !failed.load();++i) {
        readers.emplace_back([&,i] {
            try {
                auto reader=cache.reader(i);
                auto result=cache.lookup_with_hook(key,1000,reader,[&] {
                    entered.fetch_add(1);
                    while (!release.load()) std::this_thread::yield();
                });
                if (!result || !*result || (**result).addresses.size()!=1 ||
                    (**result).addresses[0].bytes[0]!=i) failed=true;
            } catch (...) { failed=true; }
        });
        while (entered.load()<=i && !failed.load()) std::this_thread::yield();
        if (!failed.load() && !publish(static_cast<std::uint8_t>(i+1))) failed=true;
    }
    // All held versions, the current version and the writer's candidate must
    // fit in the reserved pool while snapshots repeatedly retire and recycle.
    for (std::uint8_t i=33;i<97 && !failed.load();++i) if (!publish(i)) failed=true;
    release=true;
    for (auto& reader:readers) reader.join();
    if (failed || readers.size()!=count || !publish(99)) return 2;
    auto reader=cache.reader(0);
    auto current=cache.lookup(key,1000,reader);
    return current && *current && (**current).addresses[0].bytes[0]==99 ? 0 : 3;
}
#endif
#include "snapshot_scenarios.hpp"
int main() {
    if (auto result=differential()) return result;
#ifdef DNS_ORDERED_SCALED_EXPERIMENT
    if (auto result=scaled_capacity()) { std::cerr<<"scaled capacity "<<result<<'\n'; return 9; }
#endif
#ifdef DNS_MODULE_SNAPSHOT_EXPERIMENT
    if (auto result=module_reader_contract()) { std::cerr<<"module reader contract "<<result<<'\n'; return 6; }
    if (auto result=module_snapshot_pool()) { std::cerr<<"module snapshot pool "<<result<<'\n'; return 7; }
    if (auto result=module_oversized_inputs()) { std::cerr<<"module oversized inputs "<<result<<'\n'; return 8; }
#endif
#ifndef DNS_MODULE_SNAPSHOT_EXPERIMENT
    if (auto result=clear_race()) { std::cerr<<"clear race "<<result<<'\n'; return 2; }
    if (auto result=clock_race()) { std::cerr<<"clock race "<<result<<'\n'; return 3; }
#endif
    if (auto result=concurrent_updates()) { std::cerr<<"concurrent updates "<<result<<'\n'; return 4; }
#ifdef DNS_SNAPSHOT_EXPERIMENT
    if (auto result=collision_and_compaction()) { std::cerr<<"collision and compaction "<<result<<'\n'; return 5; }
    if (auto result=reader_slot_lifetime()) { std::cerr<<"reader slot lifetime "<<result<<'\n'; return 5; }
#ifdef DNS_ORDERED_SNAPSHOT_EXPERIMENT
    if (auto result=large_reader_pool()) { std::cerr<<"large reader pool "<<result<<'\n'; return 5; }
    if (auto result=full_history_bound()) { std::cerr<<"full history bound "<<result<<'\n'; return 5; }
    if (auto result=ordered_replacement_race()) { std::cerr<<"ordered replacement race "<<result<<'\n'; return 5; }
#endif
    if (auto result=snapshot_protect_retry()) { std::cerr<<"snapshot protect retry "<<result<<'\n'; return 5; }
    if (auto result=reused_snapshot_address()) { std::cerr<<"reused snapshot address "<<result<<'\n'; return 5; }
    if (auto result=retained_snapshots()) { std::cerr<<"retained snapshots "<<result<<'\n'; return 5; }
#endif
    std::cout<<"30,000 differential DNS operations, clear, publication and concurrent updates passed\n";
}
