import std;
import dns.message;
import dns.cache;
#include "paged_semantic.hpp"

namespace d=dns;
using Cache=dns_hp_experiment::PagedSemanticCache;
auto answer(d::CacheKey const& key,std::uint32_t ttl,std::uint8_t value) -> d::AddressAnswer {
    d::Address address{}; address.size=4; address.bytes[0]=value; address.bytes[1]=static_cast<std::uint8_t>(~value);
    return {key.name,{key.name},{address},ttl};
}
template<class A,class B> auto equal_status(A const& a,B const& b) -> bool {
    return a.has_value()==b.has_value() && (a.has_value() || a.error()==b.error());
}
auto equal_token(d::CacheToken a,d::CacheToken b) -> bool { return a.generation==b.generation && a.query==b.query; }
auto equal_stale(std::expected<std::optional<d::StaleAddressAnswer>,d::CacheError> const& a,
                 std::expected<std::optional<d::StaleAddressAnswer>,d::CacheError> const& b) -> bool {
    if (!equal_status(a,b)) return false;
    if (!a) return true;
    if (a->has_value()!=b->has_value()) return false;
    if (!*a) return true;
    return (**a).age_ms==(**b).age_ms && (**a).answer.ttl==(**b).answer.ttl &&
           (**a).answer.canonical_name==(**b).answer.canonical_name &&
           (**a).answer.addresses[0].bytes==(**b).answer.addresses[0].bytes;
}
auto equal_answer(d::AddressAnswer const& a,d::AddressAnswer const& b) -> bool {
    if (a.canonical_name!=b.canonical_name || a.chain!=b.chain || a.ttl!=b.ttl || a.addresses.size()!=b.addresses.size()) return false;
    for (std::size_t i=0;i<a.addresses.size();++i)
        if (a.addresses[i].size!=b.addresses[i].size || a.addresses[i].bytes!=b.addresses[i].bytes) return false;
    return true;
}
auto mixed_capacity() -> int {
    d::AddressCache reference(512,5000,true); Cache cache(512,5000,1); auto reader=cache.reader(0);
    std::vector<d::CacheKey> keys;
    for (unsigned i=0;i<768;++i) keys.push_back({1+i%2,std::format("mixed-capacity-{:04}.test",i),1});
    for (unsigned i=0;i<512;++i) {
        auto a=reference.begin_query(keys[i]),b=cache.begin_query(keys[i]);
        if (!a || !b) return 1;
        auto first=i%2 ? reference.publish(keys[i],answer(keys[i],5+i%20,i),1000,*a)
                       : reference.publish_negative(keys[i],d::NegativeKind::no_data,5+i%20,1000,*a);
        auto second=i%2 ? cache.publish(keys[i],answer(keys[i],5+i%20,i),1000,*b)
                        : cache.publish_negative(keys[i],d::NegativeKind::no_data,5+i%20,1000,*b);
        if (!first || !second) return 2;
    }
    struct Pair { d::CacheKey key; d::CacheToken a,b; };
    std::vector<Pair> pending;
    std::uint64_t now=1000,state=0x384a5fb72ac7e91ULL;
    auto random=[&] { state^=state<<13; state^=state>>7; state^=state<<17; return state; };
    auto compare=[&](d::CacheKey const& key,std::uint64_t sampled) {
        auto a=reference.lookup(key,sampled),b=cache.lookup(key,sampled,reader);
        if (!equal_status(a,b) || (a && (a->has_value()!=b->has_value() || (*a && !equal_answer(**a,**b))))) return false;
        auto an=reference.lookup_negative(key,sampled),bn=cache.lookup_negative(key,sampled,reader);
        return equal_status(an,bn) && (!an || *an==*bn);
    };
    for (unsigned step=0;step<20000;++step) {
        now+=random()%8;
        auto sampled=random()%5==0 && now>100 ? now-100 : now;
        auto key=keys[random()%keys.size()];
        auto operation=random()%100;
        bool equal=true;
        if (step && step%7000==0) {
            auto a=reference.clear(sampled),b=cache.clear(sampled); equal=equal_status(a,b);
        } else if (operation<35) {
            auto a=reference.begin_query(key),b=cache.begin_query(key);
            equal=equal_status(a,b) && (!a || equal_token(*a,*b));
            if (equal && a) pending.push_back({key,*a,*b});
        } else if (operation<47) {
            auto a=reference.begin_refresh(key,sampled,8),b=cache.begin_refresh(key,sampled,8);
            equal=equal_status(a,b) && (!a || (a->has_value()==b->has_value() && (!*a || equal_token(**a,**b))));
            if (equal && a && *a) pending.push_back({key,**a,**b});
        } else if (operation<83 && !pending.empty()) {
            auto const& pair=pending[random()%pending.size()];
            if (random()%8) key=pair.key;
            if (operation<65) {
                auto value=answer(key,random()%30,static_cast<std::uint8_t>(step));
                auto a=reference.publish(key,value,sampled,pair.a),b=cache.publish(key,value,sampled,pair.b);
                equal=equal_status(a,b);
            } else if (operation<74) {
                auto kind=random()%2 ? d::NegativeKind::name_not_found : d::NegativeKind::no_data;
                auto ttl=random()%30;
                auto a=reference.publish_negative(key,kind,ttl,sampled,pair.a),b=cache.publish_negative(key,kind,ttl,sampled,pair.b);
                equal=equal_status(a,b);
            } else if (operation<79) {
                auto a=reference.invalidate(key,sampled,pair.a),b=cache.invalidate(key,sampled,pair.b);
                equal=equal_status(a,b);
            } else {
                auto a=reference.cancel_query(pair.a),b=cache.cancel_query(pair.b);
                equal=equal_status(a,b);
            }
        } else if (operation<91) {
            auto a=reference.lookup_stale(key,sampled),b=cache.lookup_stale(key,sampled);
            equal=equal_stale(a,b);
        } else equal=compare(key,sampled);
        if (equal) equal=compare(keys[random()%keys.size()],sampled);
        auto shape=cache.shape();
        if (!equal || shape.entries!=reference.size() || shape.pages>31 || shape.min_neighbor_sum<=32) {
            std::cerr<<"paged mixed differential step "<<step<<" operation "<<operation<<'\n'; return 3;
        }
        if (pending.size()>1500) pending.erase(pending.begin(),pending.begin()+750);
    }
    return 0;
}
auto cross_page() -> int {
    d::AddressCache reference(512,5000,true); Cache cache(512,5000,2);
    auto reader=cache.reader(0);
    std::vector<d::CacheKey> keys;
    for (unsigned i=0;i<512;++i) keys.push_back({1,std::format("semantic-{:04}.test",i),1});
    for (unsigned i=0;i<keys.size();++i) {
        auto a=reference.begin_query(keys[i]),b=cache.begin_query(keys[i]);
        if (!a || !b || !equal_token(*a,*b)) return 1;
        auto first=i%2 ? reference.publish(keys[i],answer(keys[i],2,42),1000,*a)
                       : reference.publish_negative(keys[i],d::NegativeKind::no_data,2,1000,*a);
        auto second=i%2 ? cache.publish(keys[i],answer(keys[i],2,42),1000,*b)
                        : cache.publish_negative(keys[i],d::NegativeKind::no_data,2,1000,*b);
        if (!first || !second) return 2;
    }
    auto pages_before=cache.shape().pages;
    auto a=reference.begin_refresh(keys[1],4000,2),b=cache.begin_refresh(keys[1],4000,2);
    if (!a || !b || !*a || !*b || !equal_token(**a,**b) || cache.shape().pages>=pages_before ||
        cache.shape().min_neighbor_sum<=32 || cache.size()!=reference.size()) return 3;
    for (unsigned i=0;i<keys.size();++i) {
        auto positive=reference.lookup(keys[i],4000),paged=cache.lookup(keys[i],4000,reader);
        auto negative=reference.lookup_negative(keys[i],4000),paged_negative=cache.lookup_negative(keys[i],4000,reader);
        if (!equal_status(positive,paged) || !positive || positive->has_value()!=paged->has_value() ||
            !equal_status(negative,paged_negative) || !negative || *negative!=*paged_negative) return 4;
        auto stale=reference.lookup_stale(keys[i],4000),paged_stale=cache.lookup_stale(keys[i],4000);
        if (!equal_stale(stale,paged_stale) || !stale || stale->has_value()!=(i%2!=0)) return 5;
    }
    auto foreground_a=reference.begin_query(keys[1]),foreground_b=cache.begin_query(keys[1]);
    if (!foreground_a || !foreground_b || !equal_token(*foreground_a,*foreground_b) ||
        !reference.publish(keys[1],answer(keys[1],60,42),4000,*foreground_a) ||
        !cache.publish(keys[1],answer(keys[1],60,42),4000,*foreground_b)) return 6;
    auto stale_a=reference.publish(keys[1],answer(keys[1],60,1),4000,**a);
    auto stale_b=cache.publish(keys[1],answer(keys[1],60,1),4000,**b);
    if (!equal_status(stale_a,stale_b) || stale_a || stale_a.error()!=d::CacheError::stale_query) return 7;
    auto pending_a=reference.begin_refresh(keys[3],4000,2),pending_b=cache.begin_refresh(keys[3],4000,2);
    if (!pending_a || !pending_b || !*pending_a || !*pending_b || !equal_token(**pending_a,**pending_b)) return 8;
    bool valid=true;
    auto held=cache.lookup_with_hook(keys[1],4000,reader,[&] {
        if (!reference.clear(5000) || !cache.clear(5000)) { valid=false; return; }
        auto old_a=reference.publish(keys[3],answer(keys[3],60,3),5000,**pending_a);
        auto old_b=cache.publish(keys[3],answer(keys[3],60,3),5000,**pending_b);
        if (!equal_status(old_a,old_b) || old_a || old_a.error()!=d::CacheError::stale_generation) { valid=false; return; }
        auto next_a=reference.begin_query(keys[1]),next_b=cache.begin_query(keys[1]);
        if (!next_a || !next_b || !equal_token(*next_a,*next_b) ||
            !reference.publish(keys[1],answer(keys[1],60,99),5000,*next_a) ||
            !cache.publish(keys[1],answer(keys[1],60,99),5000,*next_b)) valid=false;
    });
    auto current_reader=cache.reader(1);
    auto current=cache.lookup(keys[1],5000,current_reader);
    if (!valid || !held || !*held || (**held).addresses[0].bytes[0]!=42 ||
        !current || !*current || (**current).addresses[0].bytes[0]!=99 || cache.size()!=1) return 9;
    return 0;
}
auto overflow() -> int {
    d::AddressCache reference(4,5000,true); Cache cache(4,5000,1);
    auto reader=cache.reader(0);
    d::CacheKey key{1,"overflow.example.test",1};
    auto now=std::numeric_limits<std::uint64_t>::max()-2000;
    auto a=reference.begin_query(key),b=cache.begin_query(key);
    if (!a || !b || !reference.publish(key,answer(key,1,42),now,*a) || !cache.publish(key,answer(key,1,42),now,*b)) return 1;
    now=std::numeric_limits<std::uint64_t>::max();
    auto stale=reference.lookup_stale(key,now),paged=cache.lookup_stale(key,now);
    if (!equal_stale(stale,paged) || !stale || !*stale || (**stale).age_ms!=1000) return 2;
    auto refresh_a=reference.begin_refresh(key,now,1),refresh_b=cache.begin_refresh(key,now,1);
    if (!refresh_a || !refresh_b || !*refresh_a || !*refresh_b || !equal_token(**refresh_a,**refresh_b)) return 3;
    auto erase_a=reference.publish(key,answer(key,0,42),now,**refresh_a);
    auto erase_b=cache.publish(key,answer(key,0,42),now,**refresh_b);
    auto result=cache.lookup(key,now,reader);
    if (!equal_status(erase_a,erase_b) || !erase_a || !result || *result || cache.size()!=0) return 4;
    return 0;
}
auto concurrent_semantics() -> int {
    constexpr unsigned reader_count=8;
    Cache cache(512,5000,reader_count);
    std::vector<d::CacheKey> keys;
    for (unsigned i=0;i<512;++i) {
        keys.push_back({1,std::format("semantic-race-{:04}.test",i),1});
        auto token=cache.begin_query(keys.back());
        if (!token) return 1;
        auto result=i%2 ? cache.publish(keys.back(),answer(keys.back(),2,42),1000,*token)
                        : cache.publish_negative(keys.back(),d::NegativeKind::no_data,2,1000,*token);
        if (!result) return 2;
    }
    auto before=cache.shape().pages;
    std::barrier gate(reader_count+1);
    std::atomic<bool> stop=false,failed=false;
    std::atomic<std::size_t> reads=0,hits=0;
    std::vector<std::thread> threads;
    for (unsigned id=0;id<reader_count;++id) threads.emplace_back([&,id] {
        auto reader=cache.reader(id); std::uint64_t rng=0xd73941aULL+id;
        if (id%2) {
            auto initial=cache.lookup(keys[id],1000,reader);
            if (!initial || !*initial) failed=true; else ++hits;
        } else {
            auto initial=cache.lookup_negative(keys[id],1000,reader);
            if (!initial || !*initial) failed=true; else ++hits;
        }
        gate.arrive_and_wait();
        while (!stop.load()) {
            rng^=rng<<13; rng^=rng>>7; rng^=rng<<17;
            auto const& key=keys[rng%keys.size()];
            auto positive=cache.lookup(key,1000,reader);
            auto negative=cache.lookup_negative(key,1000,reader);
            if (!positive || !negative) failed=true;
            else {
                if (*positive) {
                    auto const& value=**positive;
                    if (value.canonical_name!=key.name || value.addresses.size()!=1 ||
                        value.addresses[0].bytes[1]!=static_cast<std::uint8_t>(~value.addresses[0].bytes[0])) failed=true;
                    ++hits;
                }
                if (*negative) ++hits;
            }
            ++reads;
        }
    });
    gate.arrive_and_wait();
    auto expired=cache.begin_refresh({1,"absent.example.test",1},4000,1);
    if (!expired || *expired || cache.shape().pages>=before) failed=true;
    for (unsigned i=0;i<3000 && !failed.load();++i) {
        auto now=4000+std::uint64_t(i/100)*250;
        auto const& key=keys[(i*257)%keys.size()];
        auto token=cache.begin_query(key);
        if (!token) { failed=true; break; }
        auto ttl=i%11==0 ? 0 : 1+i%8;
        auto result=i%3 ? cache.publish(key,answer(key,ttl,static_cast<std::uint8_t>(i)),now,*token)
                        : cache.publish_negative(key,d::NegativeKind::name_not_found,ttl,now,*token);
        if (!result) { failed=true; break; }
        if (i%73==0) {
            auto refresh=cache.begin_refresh(keys[(i+1)%keys.size()],now,2);
            if (!refresh || (*refresh && !cache.cancel_query(**refresh))) { failed=true; break; }
        }
        if (i%500==499 && !cache.clear(now)) { failed=true; break; }
    }
    stop=true;
    for (auto& thread:threads) thread.join();
    return failed || !reads || !hits ? 3 : 0;
}
int main() {
    if (auto result=mixed_capacity()) { std::cerr<<"paged semantic mixed capacity "<<result<<'\n'; return 4; }
    if (auto result=cross_page()) { std::cerr<<"paged semantic cross-page "<<result<<'\n'; return 1; }
    if (auto result=overflow()) { std::cerr<<"paged semantic overflow "<<result<<'\n'; return 2; }
    if (auto result=concurrent_semantics()) { std::cerr<<"paged semantic concurrency "<<result<<'\n'; return 3; }
    std::puts("paged semantic cross-page expiry, refresh, clear and overflow passed");
}
