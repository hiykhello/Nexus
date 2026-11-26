// Shared membership capacity functional tests.
import std;
import dns.message;
import dns.cache;
import dns.shared_cache;

namespace d=dns;
using Cache=dns_hp_experiment::GroupSnapshot;
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
auto configuration_and_single_group() -> void {
    auto invalid=[](std::span<std::size_t const> groups,std::size_t limit) {
        try { Cache cache(groups,Cache::SharedCapacity{limit},1); return false; }
        catch (std::invalid_argument const&) { return true; }
    };
    std::array<std::size_t,2> enabled{1,1},bad{1,2};
    require(invalid(enabled,1) && invalid(enabled,8193) && invalid(bad,10),"invalid shared capacity accepted");
    {
        std::array<std::size_t,1> groups{1}; Cache cache(groups,Cache::SharedCapacity{4352},1);
        auto reader=cache.reader(0);
        for (unsigned i=0;i<3000;++i) write(cache,0,key(0,i),i);
        require(cache.size(0)==3000 && cache.page_count(0)>32,"single group was limited to 1024");
        for (unsigned i=0;i<3000;++i) require(value(cache,0,key(0,i),reader)==i%256,"single-group result missing");
    }
    require(Cache::live_nodes()==0,"single-group nodes retained");
    {
        std::array<std::size_t,2> groups{0,0}; Cache cache(groups,Cache::SharedCapacity{0},1);
        auto reader=cache.reader(0); require(!value(cache,0,key(0,0),reader),"disabled group returned a value");
    }
}
auto borrowing_and_sharing() -> void {
    {
        std::array<std::size_t,3> groups{1,1,0}; Cache cache(groups,Cache::SharedCapacity{13},2);
        for (unsigned i=0;i<13;++i) write(cache,0,key(0,i),i);
        for (unsigned i=0;i<6;++i) {
            write(cache,1,key(1,i),10+i);
            require(cache.size(0)==12-i && cache.size(1)==i+1,"borrowed slots were not reclaimed");
        }
        require(cache.size(0)==7 && cache.size(1)==6,"base shares or remainder wrong");
        for (unsigned i=0;i<6;++i) require(!cache.contains_member(0,key(0,i)),"wrong borrowed member reclaimed");
        write(cache,1,key(1,6),42);
        require(cache.size(0)==7 && cache.size(1)==6 && !cache.contains_member(1,key(1,0)) &&
                cache.contains_member(1,key(1,6)),"group above base displaced another group");
        write(cache,0,key(0,13),43);
        require(cache.size(0)==7 && cache.size(1)==6 && cache.contains_member(1,key(1,1)),"own replacement crossed a share");
        auto reader=cache.reader(0); require(!value(cache,2,key(1,1),reader),"disabled group adopted an answer");
    }
    require(Cache::live_nodes()==0,"borrowing retained nodes");
    {
        std::array<std::size_t,2> groups{1,1}; Cache cache(groups,Cache::SharedCapacity{8},2);
        auto first=cache.reader(0),second=cache.reader(1);
        for (unsigned i=0;i<8;++i) write(cache,0,key(0,i),i);
        // Admission can evict its source member, but the borrowed node must
        // remain alive through publication of the new membership.
        for (unsigned i=0;i<4;++i) require(value(cache,1,key(0,i),second)==i,"shared adoption failed");
        require(cache.size(0)==4 && cache.size(1)==4 && Cache::live_nodes()==8,"shared membership accounting wrong");
        write(cache,0,key(0,7),91);
        require(value(cache,0,key(0,7),first)==91,"shared replacement failed");
        write_negative(cache,1,key(0,3),1000,30);
        auto neg=cache.lookup_negative(1,key(0,3),1000,second);
        require(neg && *neg && **neg==d::NegativeKind::name_not_found,"shared negative missing");
        auto different_view=key(0,3,2);
        require(!value(cache,0,different_view,first),"different view adopted an answer");
    }
    require(Cache::live_nodes()==0,"sharing retained nodes");
    {
        std::array<std::size_t,2> groups{1,1}; Cache cache(groups,Cache::SharedCapacity{8},2);
        auto first=cache.reader(0),second=cache.reader(1); auto subject=key(0,0);
        write(cache,0,subject,1);
        require(value(cache,1,subject,second)==1 && Cache::live_nodes()==1,"answer was not shared");
        write(cache,1,subject,2);
        require(value(cache,0,subject,first)==2 && value(cache,1,subject,second)==2 && Cache::live_nodes()==1,
                "shared replacement did not reach both groups");
        write_negative(cache,0,subject,1000,30);
        for (unsigned group=0;group<2;++group) {
            auto found=cache.lookup_negative(group,subject,1000,group ? second : first);
            require(found && *found && **found==d::NegativeKind::name_not_found,"shared negative did not reach both groups");
        }
        write_negative(cache,1,subject,1000,0);
        require(!cache.contains_member(0,subject) && !cache.contains_member(1,subject),"zero TTL did not invalidate all members");
    }
    require(Cache::live_nodes()==0,"shared replacement retained nodes");
}
auto expiration_and_seventeen_groups() -> void {
    {
        std::array<std::size_t,2> groups{1,1}; Cache cache(groups,Cache::SharedCapacity{4},2);
        write(cache,0,key(0,0),1,1000,1); write_negative(cache,0,key(0,1),1000,1);
        write(cache,0,key(0,2),2,1000,100); write(cache,1,key(1,0),3,1000,100);
        write(cache,1,key(1,1),4,3000,100);
        require(cache.size(0)==1 && cache.size(1)==2 && cache.contains_member(0,key(0,2)),
                "expired members were not reclaimed before usable answers");
    }
    {
        std::array<std::size_t,17> groups; groups.fill(1); Cache cache(groups,Cache::SharedCapacity{68},1);
        for (unsigned i=0;i<68;++i) write(cache,0,key(0,i),0);
        for (unsigned group=1;group<17;++group)
            for (unsigned i=0;i<4;++i) write(cache,group,key(group,i),group);
        for (unsigned group=0;group<17;++group) require(cache.size(group)==4,"17-group shares incorrect");
        for (unsigned i=0;i<20;++i) write(cache,0,key(17,i),99);
        for (unsigned group=1;group<17;++group) for (unsigned i=0;i<4;++i)
            require(cache.contains_member(group,key(group,i)),"17-group replacement stole protected share");
    }
    require(Cache::live_nodes()==0,"17-group cache retained nodes");
}
auto fragmentation() -> void {
    std::array<std::size_t,1> groups{1}; Cache cache(groups,Cache::SharedCapacity{2048},1); auto reader=cache.reader(0);
    std::uint64_t now=1000; unsigned sequence=0,merges=0;
    std::vector<d::CacheKey> survivors;
    auto next=[&] { return d::CacheKey{1,std::format("shared-fragment-{:06}.example.test",sequence++),1}; };
    survivors.push_back(next()); write(cache,0,survivors.back(),42,now,3600);
    for (unsigned round=0;round<480;++round) {
        d::CacheKey retained;
        for (unsigned i=1;i<=32;++i) {
            auto name=next(); if (i==16) retained=name;
            write(cache,0,name,42,now,i==16 ? 3600 : 1);
        }
        auto before=cache.page_count(0); now+=2000; write(cache,0,retained,42,now,3600);
        survivors.push_back(std::move(retained));
        auto pages=cache.page_count(0); merges+=pages<before;
        require(cache.size(0)==survivors.size() && pages<=2*survivors.size()/33+1 &&
                cache.directory_slots(0)<=512,"sparse pages exceeded their bound");
    }
    require(merges>0,"dynamic directory did not exercise sparse merges");
    for (auto const& name:survivors) require(value(cache,0,name,reader,now)==42,"fragmentation lost an answer");
}
auto refresh_reclamation() -> void {
    std::array<std::size_t,2> groups{1,1}; Cache cache(groups,Cache::SharedCapacity{2},2,5000);
    auto first=cache.reader(0),second=cache.reader(1); auto stale=key(0,0),other=key(0,1),new_name=key(1,0);
    write(cache,0,stale,1,1000,1); write(cache,0,other,2,1000,60);
    auto ready=cache.lookup_stale(0,stale,2000,first);
    auto token=cache.begin_refresh(0,stale,2000,2);
    require(ready && *ready && token && *token,"stale refresh did not start");
    write(cache,1,new_name,3,2000,60);
    require(!cache.contains_member(0,stale) && cache.contains_member(0,other) &&
            cache.contains_member(1,new_name),"later group did not reclaim the stale member");
    auto late=cache.publish(0,stale,answer(stale,4),2000,**token);
    require(!late && late.error()==d::CacheError::stale_query && cache.cancel_query(**token) &&
            value(cache,1,new_name,second,2000)==3,"evicted refresh published after reclamation");
}
auto reader_and_budget() -> void {
    {
        std::array<std::size_t,2> groups{1,1}; Cache cache(groups,Cache::SharedCapacity{4},2,0,1024*1024);
        auto old_reader=cache.reader(0),new_reader=cache.reader(1);
        for (unsigned i=0;i<4;++i) write(cache,0,key(0,i),i);
        auto old=cache.lookup_with_hook(0,key(0,0),1000,old_reader,[&] {
            write(cache,1,key(1,0),9);
            require(!cache.contains_member(0,key(0,0)) && cache.contains_member(1,key(1,0)),"reclamation failed");
            require(Cache::live_nodes()==5 && value(cache,1,key(1,0),new_reader)==9,"pinned history was lost");
        });
        require(old && *old && (**old).addresses[0].bytes[0]==0,"pinned reader lost its version");
        write(cache,1,key(1,1),10);
        require(Cache::live_nodes()==4 && cache.peak_charged_bytes()<=1024*1024,"history was not collected");
    }
    require(Cache::live_nodes()==0,"pinned cache retained nodes");
    {
        std::array<std::size_t,2> groups{1,1}; Cache cache(groups,Cache::SharedCapacity{2000},2,0,128*1024);
        auto held=cache.reader(0),reader=cache.reader(1); write(cache,0,key(0,0),7);
        auto old=cache.lookup_with_hook(0,key(0,0),1000,held,[&] {
            bool disabled=false;
            for (unsigned i=1;i<2000 && !disabled;++i) {
                auto name=key(0,i); auto token=cache.begin_query(0,name); require(token.has_value(),"budget token failed early");
                auto result=cache.publish(0,name,answer(name,1),1000,*token);
                if (!result) { require(result.error()==d::CacheError::disabled,"unexpected budget error"); disabled=true; }
            }
            require(disabled && !value(cache,0,key(0,0),reader),"budget did not close reads");
        });
        require(old && !*old && cache.peak_charged_bytes()<=128*1024,"old reader crossed disabled epoch");
        require(cache.clear(1000).has_value(),"budget clear failed"); write(cache,1,key(1,0),8);
        require(value(cache,1,key(1,0),reader)==8,"budget recovery failed");
    }
    require(Cache::live_nodes()==0,"budget test retained nodes");
}
auto adoption_at_budget() -> void {
    bool found=false;
    for (std::size_t budget=512;budget<=8192 && !found;budget+=8) {
        try {
            std::array<std::size_t,2> groups{1,1};
            Cache cache(groups,Cache::SharedCapacity{16},2,5000,budget);
            auto first=cache.reader(0),second=cache.reader(1); auto name=key(0,0);
            std::optional<d::CacheToken> borrowed;
            auto token=cache.begin_query(0,name);
            if (!token || !cache.publish(0,name,answer(name,17,1),1000,*token)) continue;
            // Retain the old root while replacing its value. Publication's
            // transient copy usually needs more space than a new membership,
            // but the old pinned page remains charged after publication.
            auto pinned=cache.lookup_with_hook(0,name,1000,first,[&] {
                auto replacement=cache.begin_query(0,name);
                if (!replacement || !cache.publish(0,name,answer(name,18,1),1000,*replacement)) return;
                auto shared=cache.lookup(1,name,1000,second);
                require(shared && *shared && (**shared).addresses[0].bytes[0]==18,"budget blocked a fresh shared answer");
                if (cache.size(1)!=0) return;
                require(cache.size(0)==1,"failed admission changed the source member");
                auto stale=cache.lookup_stale(1,name,2000,second);
                require(stale && *stale && (**stale).answer.addresses[0].bytes[0]==18 && cache.size(1)==0,
                        "budget blocked a stale shared answer");
                auto refresh=cache.begin_refresh(1,name,2000,1);
                require(refresh && *refresh,"unadmitted stale answer could not obtain a refresh token");
                auto duplicate=cache.begin_refresh(0,name,2000,1);
                require(duplicate && !*duplicate,"borrowed refresh did not suppress a duplicate");
                auto wrong=cache.publish(0,name,answer(name,19),2000,**refresh);
                require(!wrong && wrong.error()==d::CacheError::stale_query,"source group used another group's token");
                borrowed=**refresh;
            });
            if (borrowed) {
                require(pinned && *pinned && (**pinned).addresses[0].bytes[0]==17,"pinned answer changed");
                auto published=cache.publish(1,name,answer(name,20),2000,*borrowed);
                if (published) {
                    require(cache.size(1)==0 && value(cache,0,name,first,2000)==20,
                            "borrowed refresh did not update the source without admitting a member");
                    found=true;
                } else require(published.error()==d::CacheError::disabled,"unexpected budget publication failure");
            }
        } catch (Cache::BudgetExceeded const&) {}
    }
    require(found && Cache::live_nodes()==0,"failed to exercise shared lookup without admission");
}
auto borrowed_refresh() -> void {
    auto groups=std::array<std::size_t,4>{1,1,1,0};
    auto name=key(0,0);
    {
        Cache cache(groups,Cache::SharedCapacity{8},3,5000);
        auto first=cache.reader(0),third=cache.reader(2);
        write(cache,0,name,1,1000,1);
        require(value(cache,2,name,third)==1 && !cache.contains_member(1,name),"borrowed refresh setup failed");
        auto disabled=cache.begin_refresh(3,name,2000,2),limited=cache.begin_refresh(1,name,2000,0);
        require(disabled && !*disabled && limited && !*limited,"disabled or limited refresh registered");
        auto token=cache.begin_refresh(1,name,2000,2);
        require(token && *token,"borrowed refresh did not register");
        for (std::size_t group:{0,2,3}) {
            auto wrong=cache.publish(group,name,answer(name,8),2000,**token);
            auto negative=cache.publish_negative(group,name,d::NegativeKind::no_data,30,2000,**token);
            auto invalidate=cache.invalidate(group,name,2000,**token);
            require(!wrong && wrong.error()==d::CacheError::stale_query &&
                    !negative && negative.error()==d::CacheError::stale_query &&
                    !invalidate && invalidate.error()==d::CacheError::stale_query,"foreign group used refresh token");
        }
        auto duplicate=cache.begin_refresh(2,name,2000,2);
        require(duplicate && !*duplicate && cache.publish(1,name,answer(name,9),2000,**token),
                "borrowed refresh publication failed");
        require(!cache.contains_member(1,name) && value(cache,0,name,first,2000)==9 &&
                value(cache,2,name,third,2000)==9,"borrowed refresh lost or failed to update existing members");
    }
    for (bool zero:{false,true}) {
        Cache cache(groups,Cache::SharedCapacity{8},2,5000); auto first=cache.reader(0),third=cache.reader(1);
        write(cache,0,name,1,1000,1); require(value(cache,2,name,third)==1,"negative refresh setup failed");
        auto token=cache.begin_refresh(1,name,2000,1);
        require(token && *token && cache.publish_negative(1,name,d::NegativeKind::no_data,zero ? 0 : 30,2000,**token),
                "borrowed negative refresh failed");
        if (zero) require(!cache.contains_member(0,name) && !cache.contains_member(2,name),"zero TTL did not invalidate members");
        else for (std::size_t group:{0,2}) {
            auto result=cache.lookup_negative(group,name,2000,group==0 ? first : third);
            require(result && *result==d::NegativeKind::no_data,"borrowed negative did not update both members");
        }
    }
    {
        Cache cache(groups,Cache::SharedCapacity{3},2,5000); auto third=cache.reader(1);
        write(cache,0,name,1,1000,1); write(cache,0,key(0,1),2,1000,60);
        require(value(cache,2,name,third)==1,"reclamation setup failed");
        auto token=cache.begin_refresh(1,name,2000,1); require(token && *token,"reclamation refresh failed");
        write(cache,1,key(1,0),3,2000,60);
        require(!cache.contains_member(0,name) && cache.contains_member(2,name),"refresh source was not reclaimed");
        auto late=cache.publish(1,name,answer(name,4),2000,**token);
        require(!late && late.error()==d::CacheError::stale_query && cache.cancel_query(**token),
                "refresh published after its source was reclaimed");
    }
    for (unsigned change=0;change<3;++change) {
        Cache cache(groups,Cache::SharedCapacity{8},1,5000); auto reader=cache.reader(0);
        write(cache,0,name,1,1000,1);
        auto token=cache.begin_refresh(1,name,2000,1); require(token && *token,"late refresh setup failed");
        if (change==0) write(cache,0,name,5,2000,60);
        if (change==1) require(cache.clear(2000).has_value(),"refresh clear failed");
        auto late=cache.publish(1,name,answer(name,6),change==2 ? 7000 : 2000,**token);
        auto expected=change==1 ? d::CacheError::stale_generation : d::CacheError::stale_query;
        require(!late && late.error()==expected,"obsolete borrowed refresh was accepted");
        if (change==0) require(value(cache,0,name,reader,2000)==5,"late refresh changed newer answer");
        if (change==2) require(cache.cancel_query(**token).has_value(),"expired refresh could not be canceled");
    }
    require(Cache::live_nodes()==0,"borrowed refresh retained nodes");
}
auto configuration_generations() -> void {
    std::array<std::size_t,2> old_groups{1,1}; Cache old(old_groups,Cache::SharedCapacity{4},1);
    std::array<std::size_t,1> new_groups{1}; Cache replacement(new_groups,Cache::SharedCapacity{8},1);
    auto old_reader=old.reader(0),new_reader=replacement.reader(0); auto subject=key(0,0);
    auto pending=old.begin_query(0,subject); require(pending.has_value(),"old generation query failed");
    write(replacement,0,subject,7); require(old.publish(0,subject,answer(subject,3),1000,*pending).has_value(),"old query failed");
    require(value(old,0,subject,old_reader)==3 && value(replacement,0,subject,new_reader)==7,
            "configuration generations shared an answer");
    auto obsolete=old.begin_query(0,subject); require(obsolete && old.clear(1000),"old generation clear failed");
    auto late=old.publish(0,subject,answer(subject,9),1000,*obsolete);
    require(!late && late.error()==d::CacheError::stale_generation && value(replacement,0,subject,new_reader)==7,
            "late old-generation publication affected new configuration");
}

}
auto main() -> int {
    try {
        configuration_and_single_group(); borrowing_and_sharing(); expiration_and_seventeen_groups();
        fragmentation(); refresh_reclamation(); reader_and_budget(); adoption_at_budget();
        borrowed_refresh(); configuration_generations();
        std::puts("shared-capacity borrowing, protection, sharing and recovery passed"); return 0;
    } catch (std::exception const& error) { std::cerr << "shared capacity: " << error.what() << '\n'; return 1; }
}
