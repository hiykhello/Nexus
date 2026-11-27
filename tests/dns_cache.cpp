import std;
import corosio;
import dns.cache;
import dns.message;
import dns.response_cache;
import dns.message_cache;
namespace d=dns;

namespace {
    auto make_a_response(std::string_view domain,std::uint16_t id,std::uint8_t last_octet) -> d::Response {
        auto wire=*d::make_query(id,{std::string(domain),1});
        wire[2]=0x81; wire[3]=0x80; wire[7]=1;
        wire.insert(wire.end(),{0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,192,0,2,last_octet});
        return *d::parse_response(wire,id,{std::string(domain),1});
    }

    auto pending_index_stress() -> int {
        d::Address a{}; a.size=4; a.bytes[0]=192; a.bytes[3]=9;
        d::AddressAnswer ans{"k0.test",{"k0.test"},{a},60};
        // 1. AddressCache: >256 concurrent pending keys (rehashes 64->128->256->512),
        //    same-key superseding, mid-chain cancellation, and O(1) refresh cap.
        d::AddressCache burst(512,5000);
        std::vector<d::CacheToken> tokens;
        tokens.reserve(300);
        for (int i=0;i<300;++i) {
            auto t=burst.begin_query({1,"k"+std::to_string(i)+".test",1});
            if (!t) return 104;
            tokens.push_back(*t);
        }
        auto k0_newer=burst.begin_query({1,"k0.test",1});
        auto k150_newer=burst.begin_query({1,"k150.test",1});
        if (!k0_newer || !k150_newer) return 105;
        if (!burst.publish({1,"k0.test",1},ans,1000,*k0_newer)) return 106;
        if (auto stale=burst.publish({1,"k0.test",1},ans,1000,tokens[0]); stale || stale.error()!=d::CacheError::stale_query) return 107;
        for (int i=2;i<300;i+=2) {
            if (i==150) continue;
            if (!burst.cancel_query(tokens[i])) return 108;
            if (auto dup=burst.cancel_query(tokens[i]); dup || dup.error()!=d::CacheError::stale_query) return 109;
        }
        if (!burst.publish({1,"k150.test",1},ans,1000,*k150_newer)) return 110;
        if (auto stale=burst.publish({1,"k150.test",1},ans,1000,tokens[150]); stale || stale.error()!=d::CacheError::stale_query) return 111;
        for (int i=1;i<300;i+=2) {
            auto name="k"+std::to_string(i)+".test";
            if (!burst.publish({1,name,1},ans,1000,tokens[i])) return 112;
        }
        if (burst.size()!=152) return 113;

        // 2. Snapshot AddressCache pending burst + refresh counter tracking.
        d::AddressCache snap(16,5000,true,2);
        auto reader=snap.reader(0);
        std::vector<d::CacheToken> snap_tokens;
        for (int i=0;i<100;++i) {
            auto t=snap.begin_query({1,"s"+std::to_string(i)+".test",1});
            if (!t) return 114;
            snap_tokens.push_back(*t);
        }
        d::AddressAnswer short_ans{"s0.test",{"s0.test"},{a},1};
        if (!snap.publish({1,"s0.test",1},short_ans,1000,snap_tokens[0]) ||
            !snap.publish({1,"s1.test",1},short_ans,1000,snap_tokens[1])) return 115;
        auto r0=snap.begin_refresh({1,"s0.test",1},2000,1);
        if (!r0 || !*r0) return 116;
        if (auto r1=snap.begin_refresh({1,"s1.test",1},2000,1); !r1 || *r1) return 117;
        if (!snap.cancel_query(**r0)) return 118;
        auto r1=snap.begin_refresh({1,"s1.test",1},2000,1);
        if (!r1 || !*r1 || !snap.publish({1,"s1.test",1},short_ans,2000,**r1)) return 119;
        if (auto hit=snap.lookup({1,"s1.test",1},2000,reader); !hit || !*hit) return 120;
        for (int i=2;i<100;++i) if (!snap.cancel_query(snap_tokens[i])) return 121;

        // 3. ResponseCache pending burst & sent_edns isolation.
        d::ResponseCache rcache(64);
        d::CacheKey rk{1,"rc.test",1};
        auto e0_old=rcache.begin(rk,false), e0_new=rcache.begin(rk,false), e1=rcache.begin(rk,true);
        if (!e0_old || !e0_new || !e1) return 122;
        std::vector<d::CacheToken> extra;
        for (int i=0;i<100;++i) {
            auto t=rcache.begin({1,"rx"+std::to_string(i)+".test",1},false);
            if (!t) return 123;
            extra.push_back(*t);
        }
        auto resp0=make_a_response("rc.test",7,10), resp1=make_a_response("rc.test",8,11);
        if (!rcache.publish(rk,resp0,1000,*e0_new)) return 124;
        if (auto stale=rcache.publish(rk,resp0,1000,*e0_old); stale || stale.error()!=d::CacheError::stale_query) return 125;
        if (!rcache.publish(rk,resp1,1000,*e1)) return 126;
        auto hit0=rcache.lookup(rk,1000,7,false), hit1=rcache.lookup(rk,1000,8,true);
        if (!hit0 || !*hit0 || !hit1 || !*hit1) return 127;
        for (auto t:extra) if (!rcache.cancel(t)) return 128;

        // 4. MessageCache 256-pending cap, rekey_query overwrite, cancel & publish.
        d::MessageCache mcache(std::chrono::seconds(60),256);
        d::MessageCache::View view(0,corosio::endpoint(corosio::ipv4_address::loopback(),53),false,{});
        std::vector<d::MessageCache::Ticket> tickets;
        tickets.reserve(256);
        for (int i=0;i<256;++i) {
            auto qwire=*d::make_query(1,{"m"+std::to_string(i)+".test",1});
            auto q=*d::parse_query(qwire);
            auto t=mcache.begin(view,q);
            if (!t) return 129;
            tickets.push_back(*t);
        }
        auto overflow_q=*d::parse_query(*d::make_query(1,{"overflow.test",1}));
        if (mcache.begin(view,overflow_q).has_value()) return 130;
        auto q0=*d::parse_query(*d::make_query(1,{"m0.test",1}));
        auto rekeyed=mcache.begin(view,q0);
        if (!rekeyed || rekeyed->sequence==tickets[0].sequence) return 131;
        auto now=std::chrono::steady_clock::now();
        mcache.publish(tickets[0],q0,make_a_response("m0.test",1,20),now);
        if (mcache.lookup(view,q0,now).has_value()) return 132;
        mcache.publish(*rekeyed,q0,make_a_response("m0.test",1,21),now);
        if (!mcache.lookup(view,q0,now).has_value()) return 133;
        for (std::size_t i=1;i<tickets.size();++i) mcache.cancel(tickets[i]);
        if (!mcache.begin(view,overflow_q).has_value()) return 134;
        return 0;
    }
}

auto main() -> int {
    d::AddressCache cache(2);
    d::Address a{}; a.size=4; a.bytes[0]=192; a.bytes[3]=1;
    d::AddressAnswer answer{"example.test",{"example.test"},{a},10};
    d::CacheKey key{1,"Example.Test.",1};
    auto token=*cache.begin_query(key);
    if (!cache.publish(key,answer,1000,token)) return 1;
    auto hit=cache.lookup({1,"example.test",1},1000);
    if (!hit || !*hit || (**hit).ttl!=10 || (**hit).addresses[0].bytes[0]!=192) return 2;
    hit=cache.lookup(key,1999);
    if (!hit || !*hit || (**hit).ttl!=9) return 3;
    auto other=cache.lookup({2,"example.test",1},2000);
    if (!other || *other) return 4;
    other=cache.lookup({1,"example.test",28},2000);
    if (!other || *other) return 5;
    auto reverse=cache.lookup(key,1999);
    if (reverse || reverse.error()!=d::CacheError::time_reversed) return 6;
    hit=cache.lookup(key,10999);
    if (!hit || *hit) return 7;
    hit=cache.lookup(key,11000);
    if (!hit || *hit || cache.size()!=0) return 8;
    token=*cache.begin_query(key);
    if (!cache.publish(key,answer,11000,token)) return 9;
    if (!cache.clear(11001)) return 10;
    auto old=cache.publish(key,answer,11002,token);
    if (old || old.error()!=d::CacheError::stale_generation || cache.size()) return 11;
    token=*cache.begin_query(key);
    if (!cache.publish(key,answer,11003,token)) return 12;
    token=*cache.begin_query(key);
    answer.ttl=0;
    if (!cache.publish(key,answer,11004,token) || cache.size()) return 13;
    token=*cache.begin_query({1,"a.test",1});
    answer.ttl=5;
    if (!cache.publish({1,"a.test",1},answer,11005,token)) return 14;
    token=*cache.begin_query({1,"b.test",1});
    answer.ttl=10;
    if (!cache.publish({1,"b.test",1},answer,11005,token) || !cache.publish({1,"c.test",1},answer,11005,*cache.begin_query({1,"c.test",1}))) return 15;
    if (cache.size()!=2 || *cache.lookup({1,"a.test",1},11005)) return 16;
    if (!*cache.lookup({1,"b.test",1},11005) || !*cache.lookup({1,"c.test",1},11005)) return 17;
    token=*cache.begin_query({1,"x.test",28});
    auto invalid=cache.publish({1,"x.test",28},answer,11005,token);
    if (invalid || invalid.error()!=d::CacheError::invalid_answer) return 18;
    d::AddressCache disabled(0);
    auto fail=disabled.publish(key,answer,0,*disabled.begin_query(key));
    if (fail || fail.error()!=d::CacheError::disabled) return 19;
    token=*cache.begin_query(key);
    auto overflow=cache.publish(key,answer,std::numeric_limits<std::uint64_t>::max()-1,token);
    if (overflow || overflow.error()!=d::CacheError::invalid_answer) return 20;
    if (!cache.lookup(key,11005)) return 21;
    auto older=*cache.begin_query(key);
    auto newer=*cache.begin_query(key);
    answer.addresses[0].bytes[3]=2;
    if (!cache.publish(key,answer,11005,newer)) return 22;
    answer.addresses[0].bytes[3]=3;
    auto stale=cache.publish(key,answer,11005,older);
    if (stale || stale.error()!=d::CacheError::stale_query) return 23;
    hit=cache.lookup(key,11005);
    if (!hit || !*hit || (**hit).addresses[0].bytes[3]!=2) return 24;
    auto before_zero=*cache.begin_query(key);
    auto zero=*cache.begin_query(key);
    answer.ttl=0;
    if (!cache.publish(key,answer,11005,zero)) return 25;
    answer.ttl=10;
    stale=cache.publish(key,answer,11005,before_zero);
    if (stale || stale.error()!=d::CacheError::stale_query || *cache.lookup(key,11005)) return 26;
    auto first=*cache.begin_query(key);
    auto second=*cache.begin_query({2,"other.test",1});
    if (!cache.publish({2,"other.test",1},answer,11005,second)) return 27;
    stale=cache.publish(key,answer,11005,first);
    if (!stale) return 28;
    auto duplicate=cache.publish({2,"other.test",1},answer,11005,second);
    if (duplicate || duplicate.error()!=d::CacheError::stale_query) return 29;
    auto canceled=*cache.begin_query(key);
    if (!cache.cancel_query(canceled)) return 30;
    stale=cache.publish(key,answer,11005,canceled);
    if (stale || stale.error()!=d::CacheError::stale_query) return 31;
    auto wrong=*cache.begin_query(key);
    stale=cache.publish({2,"other.test",1},answer,11005,wrong);
    if (stale || stale.error()!=d::CacheError::stale_query || !cache.cancel_query(wrong)) return 32;
    d::AddressCache bounded(1,0,false,0,4096);
    std::vector<d::CacheToken> tokens;
    for (int i=0; i<4096; ++i) {
        auto t=bounded.begin_query(key);
        if (!t) return 33;
        tokens.push_back(*t);
    }
    auto full=bounded.begin_query(key);
    if (full || full.error()!=d::CacheError::query_limit) return 34;
    if (!bounded.cancel_query(tokens.back()) || !bounded.begin_query(key)) return 35;
    d::AddressCache lifecycle(1);
    auto old_pending=*lifecycle.begin_query(key);
    auto fresh=*lifecycle.begin_query(key);
    if (!lifecycle.publish(key,answer,0,fresh)) return 36;
    auto evict=*lifecycle.begin_query({1,"evict.test",1});
    if (!lifecycle.publish({1,"evict.test",1},answer,0,evict)) return 37;
    stale=lifecycle.publish(key,answer,0,old_pending);
    if (stale || stale.error()!=d::CacheError::stale_query) return 38;
    auto can_finish=*lifecycle.begin_query(key);
    auto canceled_later=*lifecycle.begin_query(key);
    if (!lifecycle.cancel_query(canceled_later) || !lifecycle.publish(key,answer,0,can_finish)) return 39;
    auto pending_clear=*lifecycle.begin_query(key);
    if (!lifecycle.clear(0)) return 40;
    stale=lifecycle.publish(key,answer,0,pending_clear);
    if (stale || stale.error()!=d::CacheError::stale_generation) return 41;
    auto old_negative_race=*lifecycle.begin_query(key);
    auto negative=*lifecycle.begin_query(key);
    auto different=*lifecycle.begin_query({2,"example.test",1});
    if (!lifecycle.invalidate(key,0,negative)) return 42;
    stale=lifecycle.publish(key,answer,0,old_negative_race);
    if (stale || stale.error()!=d::CacheError::stale_query) return 43;
    if (!lifecycle.publish({2,"example.test",1},answer,0,different)) return 44;
    if (*lifecycle.lookup(key,0) || !*lifecycle.lookup({2,"example.test",1},0)) return 45;
    auto older_negative=*lifecycle.begin_query(key);
    auto newer_positive=*lifecycle.begin_query(key);
    if (!lifecycle.publish(key,answer,0,newer_positive)) return 46;
    auto invalidation=lifecycle.invalidate(key,0,older_negative);
    if (invalidation || invalidation.error()!=d::CacheError::stale_query || !*lifecycle.lookup(key,0)) return 47;
    d::AddressCache negatives(2);
    auto earlier=*negatives.begin_query(key);
    auto later=*negatives.begin_query(key);
    if (!negatives.publish_negative(key,d::NegativeKind::no_data,3,1000,later)) return 48;
    stale=negatives.publish(key,answer,1000,earlier);
    if (stale || stale.error()!=d::CacheError::stale_query) return 49;
    if (*negatives.lookup(key,1000) || *negatives.lookup_negative(key,1000)!=d::NegativeKind::no_data ||
        *negatives.lookup_negative({2,"example.test",1},1000) || *negatives.lookup_negative({1,"example.test",28},1000)) return 50;
    if (*negatives.lookup_negative(key,3001)) return 51;
    auto new_negative=*negatives.begin_query(key);
    if (!negatives.publish_negative(key,d::NegativeKind::name_not_found,3,4000,new_negative)) return 52;
    auto replace=*negatives.begin_query(key);
    if (!negatives.publish(key,answer,4000,replace) || *negatives.lookup_negative(key,4000) || !*negatives.lookup(key,4000)) return 53;
    auto zero_negative=*negatives.begin_query(key);
    if (!negatives.publish_negative(key,d::NegativeKind::no_data,0,4000,zero_negative) || negatives.size()) return 54;
    auto before_clear=*negatives.begin_query(key);
    if (!negatives.clear(4000)) return 55;
    auto cleared=negatives.publish_negative(key,d::NegativeKind::no_data,3,4000,before_clear);
    if (cleared || cleared.error()!=d::CacheError::stale_generation) return 56;
    d::AddressCache optimistic(2,3000);
    answer.ttl=2; answer.addresses[0].bytes[3]=7;
    if (!optimistic.publish(key,answer,1000,*optimistic.begin_query(key))) return 57;
    if (*optimistic.lookup_stale(key,2999) || *optimistic.lookup(key,2999) || optimistic.size()!=1) return 58;
    auto expired=optimistic.lookup_stale(key,3000);
    if (!expired || !*expired || (**expired).answer.ttl!=1 || (**expired).age_ms!=0 ||
        (**expired).answer.addresses[0].bytes[3]!=7 || *optimistic.lookup(key,3000) || *optimistic.lookup_negative(key,3000)) return 59;
    if (*optimistic.lookup_stale({2,"example.test",1},3000) || *optimistic.lookup_stale({1,"example.test",28},3000)) return 60;
    expired=optimistic.lookup_stale(key,5000);
    if (!expired || !*expired || (**expired).age_ms!=2000) return 61;
    if (*optimistic.lookup_stale(key,5001) || optimistic.size()!=1 || *optimistic.lookup_stale(key,6000) || optimistic.size()) return 62;
    auto negative_token=*optimistic.begin_query(key);
    if (!optimistic.publish_negative(key,d::NegativeKind::no_data,1,6000,negative_token) ||
        *optimistic.lookup_stale(key,7000) || optimistic.size()) return 63;
    answer.ttl=0;
    if (!optimistic.publish(key,answer,7000,*optimistic.begin_query(key)) || *optimistic.lookup_stale(key,7000)) return 64;
    answer.ttl=1;
    if (!optimistic.publish(key,answer,7000,*optimistic.begin_query(key))) return 65;
    auto refresh=*optimistic.begin_query(key);
    if (!*optimistic.lookup_stale(key,8000) || !optimistic.clear(8000)) return 66;
    auto late=optimistic.publish(key,answer,8000,refresh);
    if (late || late.error()!=d::CacheError::stale_generation || *optimistic.lookup_stale(key,8000)) return 67;
    if (!optimistic.publish(key,answer,8000,*optimistic.begin_query(key))) return 68;
    auto negative_refresh=*optimistic.begin_query(key);
    if (!*optimistic.lookup_stale(key,9000) || !optimistic.publish_negative(key,d::NegativeKind::name_not_found,2,9000,negative_refresh) ||
        *optimistic.lookup_stale(key,9000) || *optimistic.lookup_negative(key,9000)!=d::NegativeKind::name_not_found) return 69;
    d::AddressCache near_limit(1,std::numeric_limits<std::uint64_t>::max());
    if (!near_limit.publish(key,answer,0,*near_limit.begin_query(key)) || !*near_limit.lookup_stale(key,1000)) return 70;
    auto bad_key=near_limit.lookup_stale({1,"example.test",15},1000);
    if (bad_key || bad_key.error()!=d::CacheError::invalid_key) return 71;
    auto backwards=near_limit.lookup_stale(key,999);
    if (backwards || backwards.error()!=d::CacheError::time_reversed) return 72;
    d::AddressCache default_policy(1);
    if (!default_policy.publish(key,answer,0,*default_policy.begin_query(key)) || *default_policy.lookup_stale(key,1000) || default_policy.size()) return 73;
    d::AddressCache eviction(1,5000);
    if (!eviction.publish(key,answer,0,*eviction.begin_query(key)) || !*eviction.lookup_stale(key,1000) ||
        !eviction.publish({1,"new.test",1},answer,1000,*eviction.begin_query({1,"new.test",1})) ||
        *eviction.lookup_stale(key,1000) || !*eviction.lookup({1,"new.test",1},1000)) return 74;
    d::AddressCache refreshes(2,5000);
    d::CacheKey another{1,"another.test",1};
    if (!refreshes.publish(key,answer,0,*refreshes.begin_query(key)) || !refreshes.publish(another,answer,0,*refreshes.begin_query(another))) return 75;
    if (*refreshes.begin_refresh(key,999,1) || *refreshes.begin_refresh(key,1000,0)) return 76;
    auto first_refresh=refreshes.begin_refresh(key,1000,1);
    if (!first_refresh || !*first_refresh || *refreshes.begin_refresh(key,1000,2) || *refreshes.begin_refresh(another,1000,1)) return 77;
    if (!refreshes.cancel_query(**first_refresh)) return 78;
    auto foreground=*refreshes.begin_query(key);
    if (*refreshes.begin_refresh(key,1000,1) || !refreshes.cancel_query(foreground)) return 79;
    first_refresh=refreshes.begin_refresh(key,1000,2);
    auto second_refresh=refreshes.begin_refresh(another,1000,2);
    if (!first_refresh || !*first_refresh || !second_refresh || !*second_refresh) return 80;
    if (!refreshes.publish(key,answer,1000,**first_refresh) || !*refreshes.lookup(key,1000) || !refreshes.cancel_query(**second_refresh)) return 81;
    d::AddressCache refresh_evict(1,5000);
    if (!refresh_evict.publish(key,answer,0,*refresh_evict.begin_query(key))) return 82;
    auto lost=*refresh_evict.begin_refresh(key,1000,1); if (!lost) return 83;
    if (!refresh_evict.publish(another,answer,1000,*refresh_evict.begin_query(another))) return 84;
    auto late_positive=refresh_evict.publish(key,answer,1000,*lost);
    if (late_positive || late_positive.error()!=d::CacheError::stale_query || !refresh_evict.cancel_query(*lost) ||
        *refresh_evict.lookup(key,1000) || !*refresh_evict.lookup(another,1000)) return 85;
    if (!refresh_evict.publish(key,answer,1000,*refresh_evict.begin_query(key))) return 86;
    lost=*refresh_evict.begin_refresh(key,2000,1); if (!lost) return 87;
    if (!refresh_evict.publish(another,answer,2000,*refresh_evict.begin_query(another))) return 88;
    auto late_negative=refresh_evict.publish_negative(key,d::NegativeKind::no_data,2,2000,*lost);
    if (late_negative || late_negative.error()!=d::CacheError::stale_query || !refresh_evict.cancel_query(*lost)) return 89;
    if (!refresh_evict.publish(key,answer,2000,*refresh_evict.begin_query(key))) return 90;
    lost=*refresh_evict.begin_refresh(key,3000,1); if (!lost) return 91;
    if (!refresh_evict.publish(another,answer,3000,*refresh_evict.begin_query(another))) return 92;
    auto late_invalidation=refresh_evict.invalidate(key,3000,*lost);
    if (late_invalidation || late_invalidation.error()!=d::CacheError::stale_query || !refresh_evict.cancel_query(*lost)) return 93;
    if (!refresh_evict.publish(key,answer,3000,*refresh_evict.begin_query(key))) return 94;
    lost=*refresh_evict.begin_refresh(key,4000,1); if (!lost || !refresh_evict.clear(4000)) return 95;
    auto cleared_refresh=refresh_evict.publish(key,answer,4000,*lost);
    if (cleared_refresh || cleared_refresh.error()!=d::CacheError::stale_generation) return 96;
    if (!refresh_evict.publish(key,answer,4000,*refresh_evict.begin_query(key))) return 97;
    lost=*refresh_evict.begin_refresh(key,5000,1); if (!lost) return 98;
    late_positive=refresh_evict.publish(key,answer,10000,*lost);
    if (late_positive || late_positive.error()!=d::CacheError::stale_query || !refresh_evict.cancel_query(*lost)) return 99;
    if (!refresh_evict.publish(key,answer,10000,*refresh_evict.begin_query(key))) return 100;
    lost=*refresh_evict.begin_refresh(key,11000,1); if (!lost) return 101;
    if (!refresh_evict.publish(another,answer,11000,*refresh_evict.begin_query(another)) ||
        !refresh_evict.publish(key,answer,11000,*refresh_evict.begin_query(key))) return 102;
    auto old_refresh=refresh_evict.publish(key,answer,11000,*lost);
    if (old_refresh || old_refresh.error()!=d::CacheError::stale_query || !*refresh_evict.lookup(key,11000)) return 103;
    if (auto rc=pending_index_stress()) return rc;
    std::println("DNS positive cache, view isolation, expiry and clear barrier passed");
}
