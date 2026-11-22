import std;
import dns.message;
import dns.reverse;

int main() {
    using namespace dns;
    unsigned failures=0;
    auto check=[&](bool value,std::string_view label) { if (!value) { ++failures; std::cerr << "FAIL: " << label << '\n'; } };
    auto v4=[](std::uint8_t final) { Address address{{192,0,2,final},4}; return address; };
    auto a=v4(1), b=v4(2), c=v4(3);
    ReverseCache cache(2,7,{0x1234,0x5678});
    auto token=cache.token();
    check(cache.record(10,"One.Example",std::span(&a,1),10,1000,token)==ReverseRecord::stored,"store validated answer");
    auto one=cache.lookup(10,a,1001);
    check(one && one->view()=="one.example","lookup normalized name");
    check(!cache.lookup(11,a,1001) && !cache.lookup(10,a,1001,2),"view and scope isolation");
    Address mapped{{0,0,0,0,0,0,0,0,0,0,255,255,192,0,2,1},16};
    check(cache.lookup(10,mapped,1001).has_value(),"mapped address shares canonical key");
    check(cache.record(10,"two.example",std::span(&a,1),2,2000,token)==ReverseRecord::stored,"observe conflicting name");
    check(!cache.lookup(10,a,3000) && !cache.lookup(10,a,10999) && !cache.lookup(10,a,11000),"conflict stays unknown through both TTLs");
    check(cache.record(10,"one.example",std::span(&a,1),100,11000,token)==ReverseRecord::stored &&
          cache.lookup(10,a,11000).has_value(),"expired conflict can be relearned");
    check(cache.record(10,"b.example",std::span(&b,1),1,20000,token)==ReverseRecord::stored,"fill remaining slot");
    check(cache.record(10,"c.example",std::span(&c,1),3,20000,token)==ReverseRecord::unavailable,"full cache fails closed");
    check(!cache.lookup(10,a,22000),"lost observation suspends lookups");
    check(cache.lookup(10,a,23000).has_value() && !cache.lookup(10,c,23000),"lookups resume after lost observation expires");
    check(cache.record(10,"late.example",std::span(&c,1),1,22000,token)==ReverseRecord::ignored,"late observation cannot revive expired result");
    check(cache.clear() && cache.record(10,"old.example",std::span(&a,1),10,23000,token)==ReverseRecord::stale &&
          !cache.lookup(10,a,23000),"clear invalidates in-flight token");
    auto current=cache.token();
    check(cache.record(10,"zero.example",std::span(&a,1),0,23000,current)==ReverseRecord::ignored,"zero TTL not stored");
    check(cache.record(10,"bad..name",std::span(&a,1),10,23000,current)==ReverseRecord::invalid,"invalid name rejected");
    Address invalid{{1,2,3,4,5},4};
    check(cache.record(10,"valid.example",std::span(&invalid,1),10,23000,current)==ReverseRecord::invalid,"invalid address rejected");
    check(cache.record(10,"valid.example",std::span(&a,1),10,23000,{8,current.epoch})==ReverseRecord::stale,"generation mismatch rejected");
    ReverseCache churn(8,11,{3,4}); auto churn_token=churn.token();
    for (unsigned i=0;i<2000;++i) {
        auto address=v4(static_cast<std::uint8_t>(i%200+1)); auto now=std::uint64_t(i)*2000;
        if (churn.record(5,"churn.example",std::span(&address,1),1,now,churn_token)!=ReverseRecord::stored ||
            !churn.lookup(5,address,now)) { check(false,"expired-key churn and probe cleanup"); break; }
    }
    check(churn.storage_bytes()>0 && churn.storage_bytes()<100000,"fixed storage budget reported");
    ReverseCache pooled(8,12,{8,9}); auto pooled_token=pooled.token();
    for (unsigned round=0;round<300;++round) {
        auto now=std::uint64_t(round)*3000;
        std::array<Address,8> addresses;
        for (unsigned i=0;i<addresses.size();++i) addresses[i]=v4(static_cast<std::uint8_t>(i+1));
        check(pooled.record(1,"first.example",addresses,1,now,pooled_token)==ReverseRecord::stored,"fill name pool");
        for (unsigned i=0;i<4;++i)
            check(pooled.record(1,"second.example",std::span(&addresses[i],1),1,now,pooled_token)==ReverseRecord::stored &&
                  !pooled.lookup(1,addresses[i],now),"conflict releases name and remains ambiguous");
        for (unsigned i=4;i<8;++i)
            check(pooled.lookup(1,addresses[i],now).has_value(),"other names survive conflict");
        if (round%7==0) { check(pooled.clear(),"clear pool"); pooled_token=pooled.token(); }
    }
    ReverseCache maximum(ReverseCache::max_capacity,14,{10,11});
    check(maximum.storage_bytes()<2'000'000,"maximum reverse storage budget");
    ReverseCache reused(1,15,{12,13}); auto reused_token=reused.token();
    check(reused.record(1,"longer-name.example",std::span(&a,1),1,0,reused_token)==ReverseRecord::stored &&
          reused.record(1,"x.test",std::span(&b,1),1,1000,reused_token)==ReverseRecord::stored,"reuse expired name slot");
    auto short_name=reused.lookup(1,b,1000);
    check(short_name && short_name->view()=="x.test" &&
          std::all_of(short_name->bytes.begin()+short_name->size,short_name->bytes.end(),[](char c) { return c==0; }),
          "reused name does not expose old trailing bytes");
    ReverseCache staged_cache(16,17,{7,8});
    Address v6{{0x20,0x01,0x0d,0xb8},16};
    AddressAnswer first{"target.example",{"query.example","target.example"},{a},10};
    AddressAnswer second{"target.example",{"query.example","target.example"},{v6},20};
    ReverseTransaction staged(staged_cache,21,"QUERY.example");
    check(staged.stage(first,true,1000) && staged.stage(second,false,1100),"stage fresh and stale families");
    check(!staged_cache.lookup(21,a,4000),"staged result is invisible before acceptance");
    check(staged.finish(true,4500)==ReverseCommit::published,"publish after accepted transaction");
    check(staged_cache.lookup(21,a,10499) && !staged_cache.lookup(21,a,10500),"elapsed TTL rounds down without extension");
    check(!staged_cache.lookup(21,v6,10500) && !staged_cache.lookup(22,a,10500),"stale family and other view stay absent");
    check(staged.finish(true,10500)==ReverseCommit::invalid,"transaction is one-shot");
    ReverseTransaction inconsistent(staged_cache,21,"query.example");
    auto different=second; different.canonical_name="other.example"; different.chain.back()="other.example";
    check(inconsistent.stage(first,true,11000) && !inconsistent.stage(different,true,11000),"reject mismatched family canonical names");
    check(inconsistent.finish(true,11000)==ReverseCommit::invalid && !staged_cache.lookup(21,a,11000),"invalid transaction publishes nothing");
    ReverseTransaction canceled(staged_cache,21,"query.example");
    check(canceled.stage(first,true,12000) && canceled.finish(false,12000)==ReverseCommit::empty &&
          !staged_cache.lookup(21,a,12000),"canceled transaction publishes nothing");
    ReverseTransaction outdated(staged_cache,21,"query.example");
    check(outdated.stage(first,true,13000) && staged_cache.clear() &&
          outdated.finish(true,13000)==ReverseCommit::stale && !staged_cache.lookup(21,a,13000),"clear rejects delayed staged result");
    ReverseTransaction late(staged_cache,21,"query.example");
    check(late.stage(first,true,14000) && late.finish(true,23501)==ReverseCommit::empty &&
          !staged_cache.lookup(21,a,23501),"less than one second remaining is ignored");
    ReverseTransaction time_reversed(staged_cache,21,"query.example");
    check(time_reversed.stage(first,true,25000) && time_reversed.finish(true,24999)==ReverseCommit::invalid,
          "reversed clock cannot extend TTL");
    ReverseTransaction bad_query(staged_cache,21,"other.example");
    check(!bad_query.stage(first,true,26000) && bad_query.finish(true,26000)==ReverseCommit::invalid,
          "answer must belong to query");
    // Independent ordered-map model stresses expiration, late observations,
    // ambiguous names, capacity suspension and generation barriers.
    struct ModelValue { std::string name; std::uint64_t expires; };
    std::map<std::pair<std::uint64_t,unsigned>,ModelValue> model;
    ReverseCache differential(8,13,{0x9123,0x4321});
    auto differential_token=differential.token();
    auto stale_token=differential_token;
    std::uint64_t watermark=0,suspended=0;
    std::mt19937 random(0x21937);
    for (unsigned step=0;step<30000;++step) {
        auto now=std::uint64_t(step)*29;
        if (random()%8==0 && now>5000) now-=random()%5000;
        auto view=std::uint64_t(random()%3+1);
        auto number=random()%16+1;
        auto address=v4(static_cast<std::uint8_t>(number));
        auto key=std::pair{view,number};
        auto operation=random()%10;
        if (operation==0) {
            stale_token=differential_token;
            check(differential.clear(),"model clear succeeds");
            differential_token=differential.token();
            model.clear(); suspended=0;
        } else if (operation<7) {
            std::string name=std::format("name{}.example",random()%5);
            auto ttl=random()%15;
            auto use_stale=random()%12==0;
            auto token=use_stale ? stale_token : differential_token;
            ReverseRecord expected;
            if (token.epoch!=differential_token.epoch) expected=ReverseRecord::stale;
            else {
                watermark=std::max(watermark,now);
                auto expires=now+std::uint64_t(ttl)*1000;
                if (!ttl || expires<=watermark) expected=ReverseRecord::ignored;
                else {
                    std::erase_if(model,[&](auto const& item) { return item.second.expires<=watermark; });
                    auto found=model.find(key);
                    if (found==model.end()) {
                        if (model.size()>=8) { suspended=std::max(suspended,expires); expected=ReverseRecord::unavailable; }
                        else { model.emplace(key,ModelValue{name,expires}); expected=ReverseRecord::stored; }
                    } else {
                        if (!found->second.name.empty() && found->second.name!=name) found->second.name.clear();
                        found->second.expires=std::max(found->second.expires,expires);
                        expected=ReverseRecord::stored;
                    }
                }
            }
            auto actual=differential.record(view,name,std::span(&address,1),ttl,now,token);
            if (actual!=expected) { check(false,std::format("model record step {}",step)); break; }
        } else {
            watermark=std::max(watermark,now);
            auto found=model.find(key);
            if (found!=model.end() && found->second.expires<=watermark) { model.erase(found); found=model.end(); }
            auto actual=differential.lookup(view,address,now);
            auto expected=found!=model.end() && !found->second.name.empty() && suspended<=watermark;
            if (bool(actual)!=expected || (actual && actual->view()!=found->second.name)) {
                check(false,std::format("model lookup step {}",step)); break;
            }
        }
    }
    ReverseCache concurrent(64,9,{5,6}); auto concurrent_token=concurrent.token();
    std::array<std::thread,4> threads;
    for (unsigned i=0;i<threads.size();++i) threads[i]=std::thread([&,i] {
        auto address=v4(static_cast<std::uint8_t>(20+i));
        for (unsigned j=0;j<1000;++j) {
            if (concurrent.record(i,"thread.example",std::span(&address,1),60,1000,concurrent_token)!=ReverseRecord::stored ||
                !concurrent.lookup(i,address,1000)) std::terminate();
        }
    });
    for (auto& thread:threads) thread.join();
    if (!failures) std::cout << "DNS reverse view, conflict, bounds, generations and concurrency passed\n";
    return failures ? 1 : 0;
}
