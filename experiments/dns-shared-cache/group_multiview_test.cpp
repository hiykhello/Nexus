// Independent sequential oracle for the experimental shared member cache.
// It keeps full value copies per group and linearly scans them. It intentionally
// does not use the snapshot's pages, node references or reclamation algorithm.
import std;
import dns.message;
import dns.cache;
import dns.group_snapshot;

namespace d=dns;
using Cache=dns_hp_experiment::GroupSnapshot;
using Key=d::CacheKey;
using Token=d::CacheToken;
using Error=d::CacheError;

namespace {
auto same(Key const& a,Key const& b) -> bool {
    return a.view==b.view && a.type==b.type && a.name==b.name;
}
auto token_equal(Token a,Token b) -> bool { return a.generation==b.generation && a.query==b.query; }
auto aliased(Key key,unsigned variant) -> Key {
    if (variant&1) for (auto& c:key.name) if (c>='a' && c<='z') c=static_cast<char>(c-'a'+'A');
    if (variant&2) key.name+='.';
    return key;
}
auto make_answer(Key const& key,unsigned value,unsigned ttl) -> d::AddressAnswer {
    d::Address address{}; address.size=key.type==1 ? 4 : 16;
    address.bytes[0]=static_cast<std::uint8_t>(value);
    address.bytes[1]=static_cast<std::uint8_t>(~address.bytes[0]);
    return {key.name,{key.name},{address},ttl};
}

// Array order models the original cache's first-on-equal-expiry eviction.
// Cached values are copied, so updating a key must explicitly replace every
// group holding that key. A value disappears when its final group evicts it.
class Oracle {
    struct Entry {
        Key key; unsigned value; std::optional<d::NegativeKind> negative;
        std::uint64_t expires,revision;
    };
    struct Group { std::size_t capacity; std::vector<Entry> entries; };
    struct Refresh { std::size_t source; std::uint64_t revision; };
    struct Pending { std::size_t group; Key key; std::uint64_t query; std::optional<Refresh> refresh; };
    std::vector<Group> groups_;
    std::vector<Pending> pending_;
    std::uint64_t generation_=1,next_=0;
    static constexpr std::uint64_t window=5000;
    std::size_t adoptions_=0,evictions_=0,publications_=0,refreshes_=0,stale_tokens_=0;

    static auto find(Group& group,Key const& key) {
        return std::ranges::find_if(group.entries,[&](Entry const& entry) { return same(entry.key,key); });
    }
    static auto fresh(Entry const& entry,std::uint64_t now) -> bool {
        return now<entry.expires && (entry.expires-now)/1000>0;
    }
    static auto stale(Entry const& entry,std::uint64_t now) -> bool {
        return !entry.negative && now>=entry.expires && now-entry.expires<window && window-(now-entry.expires)>=1000;
    }
    static auto prune(Group& group,std::uint64_t now) -> void {
        std::erase_if(group.entries,[&](Entry const& entry) {
            return now>=entry.expires && (entry.negative || now-entry.expires>=window);
        });
    }
    auto admit(Group& group,Entry entry,std::uint64_t now) -> void {
        prune(group,now);
        if (auto old=find(group,entry.key); old!=group.entries.end()) *old=std::move(entry);
        else if (group.entries.size()<group.capacity) group.entries.push_back(std::move(entry));
        else { ++evictions_; *std::ranges::min_element(group.entries,{},&Entry::expires)=std::move(entry); }
    }
public:
    enum class Kind { positive,negative,stale };
    struct Observed { unsigned value; std::optional<d::NegativeKind> negative; std::uint32_t ttl; std::uint64_t age; };
    explicit Oracle(std::span<std::size_t const> capacities) {
        for (auto capacity:capacities) groups_.push_back({capacity,{}});
    }
    auto begin(std::size_t group,Key key) -> std::expected<Token,Error> {
        if (pending_.size()==4096) return std::unexpected(Error::query_limit);
        pending_.push_back({group,std::move(key),++next_,{}});
        return Token{generation_,next_};
    }
    auto refresh(std::size_t group,Key key,std::uint64_t now,std::size_t max) -> std::expected<std::optional<Token>,Error> {
        auto& own=groups_[group]; auto entry=find(own,key);
        if (!own.capacity || (entry!=own.entries.end() && now<entry->expires)) return std::optional<Token>{};
        std::size_t source=group;
        if (entry==own.entries.end() || !stale(*entry,now)) {
            source=groups_.size();
            for (std::size_t i=0;i<groups_.size();++i) if (i!=group) {
                auto candidate=find(groups_[i],key);
                if (candidate!=groups_[i].entries.end() && stale(*candidate,now)) { source=i; entry=candidate; break; }
            }
            if (source==groups_.size()) return std::optional<Token>{};
        }
        if (std::ranges::any_of(pending_,[&](auto const& p) { return same(p.key,key); })) return std::optional<Token>{};
        if (static_cast<std::size_t>(std::ranges::count_if(pending_,[](auto const& p) { return p.refresh.has_value(); }))>=max)
            return std::optional<Token>{};
        if (pending_.size()==4096) return std::unexpected(Error::query_limit);
        auto revision=entry->revision;
        pending_.push_back({group,std::move(key),++next_,Refresh{source,revision}});
        ++refreshes_;
        return std::optional<Token>(Token{generation_,next_});
    }
    auto cancel(Token token) -> std::expected<void,Error> {
        if (token.generation!=generation_) return std::unexpected(Error::stale_generation);
        auto item=std::ranges::find(pending_,token.query,&Pending::query);
        if (item==pending_.end()) return std::unexpected(Error::stale_query);
        pending_.erase(item); return {};
    }
    auto publish(std::size_t group,Key const& key,unsigned value,std::optional<d::NegativeKind> negative,
                 unsigned ttl,std::uint64_t now,Token token,bool invalidate=false) -> std::expected<void,Error> {
        if (token.generation!=generation_) { ++stale_tokens_; return std::unexpected(Error::stale_generation); }
        auto pending=std::ranges::find(pending_,token.query,&Pending::query);
        if (pending==pending_.end() || pending->group!=group || !same(pending->key,key)) { ++stale_tokens_; return std::unexpected(Error::stale_query); }
        if (pending->refresh) {
            auto& source=groups_[pending->refresh->source]; auto entry=find(source,key);
            if (entry==source.entries.end() || entry->negative || entry->revision!=pending->refresh->revision ||
                (now>=entry->expires && now-entry->expires>=window)) return std::unexpected(Error::stale_query);
        }
        if (!invalidate && !groups_[group].capacity) return std::unexpected(Error::disabled);
        if (invalidate || !ttl) {
            for (auto& target:groups_) std::erase_if(target.entries,[&](Entry const& entry) { return same(entry.key,key); });
        } else {
            auto& own=groups_[pending->refresh ? pending->refresh->source : group]; prune(own,now);
            Entry replacement{key,value,negative,now+std::uint64_t(ttl)*1000,token.query};
            for (auto& target:groups_) if (auto existing=find(target,key); existing!=target.entries.end()) *existing=replacement;
            if (find(own,key)==own.entries.end()) admit(own,std::move(replacement),now);
        }
        std::erase_if(pending_,[&](Pending const& item) { return item.query<=token.query && same(item.key,key); });
        ++publications_;
        return {};
    }
    auto clear() -> void { for (auto& group:groups_) group.entries.clear(); pending_.clear(); ++generation_; next_=0; }
    auto size(std::size_t group) const -> std::size_t { return groups_[group].entries.size(); }
    auto lookup(std::size_t group,Key const& key,std::uint64_t now,Kind kind) -> std::optional<Observed> {
        auto& own=groups_[group]; if (!own.capacity) return {};
        auto entry=find(own,key);
        if (kind==Kind::stale) {
            if (entry!=own.entries.end() && fresh(*entry,now)) return {};
        } else if (entry!=own.entries.end() && fresh(*entry,now)) {
            if ((kind==Kind::positive && entry->negative) || (kind==Kind::negative && !entry->negative)) return {};
            return Observed{entry->value,entry->negative,static_cast<std::uint32_t>((entry->expires-now)/1000),0};
        }
        auto usable=[&](Entry const& candidate) { return kind==Kind::stale ? stale(candidate,now) : fresh(candidate,now); };
        if (entry==own.entries.end() || !usable(*entry)) {
            std::optional<Entry> source;
            for (std::size_t i=0;i<groups_.size();++i) if (i!=group) {
                auto candidate=find(groups_[i],key);
                if (candidate!=groups_[i].entries.end() && usable(*candidate)) { source=*candidate; break; }
            }
            if (!source) return {};
            ++adoptions_;
            admit(own,*source,now); entry=find(own,key);
        }
        if (kind==Kind::stale) return Observed{entry->value,{},1,now-entry->expires};
        if ((kind==Kind::positive && entry->negative) || (kind==Kind::negative && !entry->negative)) return {};
        return Observed{entry->value,entry->negative,static_cast<std::uint32_t>((entry->expires-now)/1000),0};
    }
    auto exercised() const -> bool {
        std::cout<<"adoptions="<<adoptions_<<" evictions="<<evictions_<<" publications="<<publications_
                 <<" refreshes="<<refreshes_<<" rejected_tokens="<<stale_tokens_<<'\n';
        return adoptions_>100 && evictions_>100 && publications_>1000 && stale_tokens_>100;
    }
};

template<class T>
auto equal_status(std::expected<T,Error> const& a,std::expected<T,Error> const& b) -> bool {
    return a.has_value()==b.has_value() && (a || a.error()==b.error());
}
auto checked_lookup(Oracle& oracle,Cache& cache,Cache::Reader& reader,std::size_t group,Key const& key,
                    std::uint64_t now,Oracle::Kind kind,unsigned variant) -> bool {
    auto expected=oracle.lookup(group,key,now,kind);
    auto valid_answer=[&](d::AddressAnswer const& result) {
        return expected && result.canonical_name==key.name && result.chain==std::vector<std::string>{key.name} &&
            result.ttl==expected->ttl && result.addresses.size()==1 && result.addresses[0].size==(key.type==1 ? 4 : 16) &&
            result.addresses[0].bytes[0]==static_cast<std::uint8_t>(expected->value) &&
            result.addresses[0].bytes[1]==static_cast<std::uint8_t>(~result.addresses[0].bytes[0]);
    };
    if (kind==Oracle::Kind::positive) {
        auto result=cache.lookup(group,aliased(key,variant),now,reader);
        return result && result->has_value()==expected.has_value() && (!*result || valid_answer(**result));
    }
    if (kind==Oracle::Kind::negative) {
        auto result=cache.lookup_negative(group,aliased(key,variant),now,reader);
        return result && result->has_value()==expected.has_value() && (!*result || **result==*expected->negative);
    }
    auto result=cache.lookup_stale(group,aliased(key,variant),now,reader);
    return result && result->has_value()==expected.has_value() && (!*result || (valid_answer((**result).answer) && (**result).age_ms==expected->age));
}

auto run(std::uint32_t seed) -> bool {
    std::array<std::size_t,17> capacities{};
    for (std::size_t i=0;i<capacities.size();++i) capacities[i]=i%8==0 ? 0 : 3+i%10;
    Cache cache(capacities,1,5000); auto reader=cache.reader(0); Oracle oracle(capacities);
    std::vector<Key> keys;
    for (unsigned view=0;view<4;++view) for (unsigned name=0;name<12;++name) for (auto type:{1,28})
        keys.push_back({view,std::format("item-{:02}.example",name),static_cast<std::uint16_t>(type)});
    struct Query { std::size_t group; Key key; Token token; };
    std::vector<Query> queries;
    std::mt19937 rng(seed); std::uint64_t now=1000;
    auto fail=[&](unsigned step,std::string_view operation) {
        std::cerr<<"seed "<<seed<<" step "<<step<<" "<<operation<<"\n"; return false;
    };
    for (unsigned step=0;step<50000;++step) {
        auto group=static_cast<std::size_t>(rng()%capacities.size()); auto key=keys[rng()%keys.size()];
        auto variant=rng()%4; auto action=rng()%100;
        now+=rng()%11;
        if (action<24) {
            auto kind=static_cast<Oracle::Kind>(rng()%3);
            if (!checked_lookup(oracle,cache,reader,group,key,now,kind,variant)) return fail(step,"lookup");
        } else if (action<53) {
            auto expected=oracle.begin(group,key),actual=cache.begin_query(group,aliased(key,variant));
            if (!equal_status(expected,actual) || (expected && !token_equal(*expected,*actual))) return fail(step,"begin");
            if (actual) queries.push_back({group,key,*actual});
        } else if (action<65) {
            auto expected=oracle.refresh(group,key,now,4),actual=cache.begin_refresh(group,aliased(key,variant),now,4);
            if (!equal_status(expected,actual) || (expected && (expected->has_value()!=actual->has_value() ||
                (*expected && !token_equal(**expected,**actual))))) return fail(step,"refresh");
            if (actual && *actual) queries.push_back({group,key,**actual});
        } else if (action<95 && !queries.empty()) {
            auto query=queries[rng()%queries.size()];
            if (rng()%20==0) query.group=(query.group+1)%capacities.size();
            if (rng()%20==0) query.key=keys[rng()%keys.size()];
            unsigned ttl=rng()%15, value=rng()%256, disposition=rng()%5;
            std::optional<d::NegativeKind> negative;
            if (disposition==1 || disposition==2) negative=disposition==1 ? d::NegativeKind::no_data : d::NegativeKind::name_not_found;
            bool invalidate=disposition==3;
            auto expected=oracle.publish(query.group,query.key,value,negative,ttl,now,query.token,invalidate);
            auto input=aliased(query.key,variant);
            auto actual=invalidate ? cache.invalidate(query.group,input,now,query.token)
                : negative ? cache.publish_negative(query.group,input,*negative,ttl,now,query.token)
                           : cache.publish(query.group,input,make_answer(query.key,value,ttl),now,query.token);
            if (!equal_status(expected,actual)) return fail(step,"publish");
        } else if (action<99 && !queries.empty()) {
            auto at=rng()%queries.size(); auto expected=oracle.cancel(queries[at].token),actual=cache.cancel_query(queries[at].token);
            if (!equal_status(expected,actual)) return fail(step,"cancel");
            queries.erase(queries.begin()+at);
        }
        if (rng()%4000==0) {
            oracle.clear(); if (!cache.clear(now)) return fail(step,"clear");
        }
        if (queries.size()>256) {
            auto at=rng()%queries.size(); auto expected=oracle.cancel(queries[at].token),actual=cache.cancel_query(queries[at].token);
            if (!equal_status(expected,actual)) return fail(step,"bounded cancel");
            queries.erase(queries.begin()+at);
        }
        if (step%37==0) {
            for (std::size_t i=0;i<capacities.size();++i) if (oracle.size(i)!=cache.size(i)) return fail(step,"membership size");
            for (unsigned i=0;i<8;++i) {
                auto g=rng()%capacities.size(); auto const& k=keys[rng()%keys.size()];
                auto kind=static_cast<Oracle::Kind>(rng()%3);
                if (!checked_lookup(oracle,cache,reader,g,k,now,kind,rng()%4)) return fail(step,"sample lookup");
            }
        }
    }
    return oracle.exercised();
}

auto all_views() -> bool {
    std::array<std::size_t,17> capacities; capacities.fill(8);
    Cache cache(capacities,1,5000); auto reader=cache.reader(0);
    std::array<Key,8> keys;
    for (unsigned i=0;i<keys.size();++i) {
        keys[i]={i/2,"same-name.example",static_cast<std::uint16_t>(i%2 ? 28 : 1)};
        auto token=cache.begin_query(i,keys[i]);
        if (!token || !cache.publish(i,keys[i],make_answer(keys[i],10+i,1),1000,*token)) return false;
    }
    for (std::size_t group=0;group<capacities.size();++group) for (unsigned i=0;i<keys.size();++i) {
        auto hit=cache.lookup(group,aliased(keys[i],group%4),1000,reader);
        if (!hit || !*hit || (**hit).addresses[0].bytes[0]!=10+i) return false;
    }
    if (Cache::live_nodes()!=8) return false;
    auto negative=cache.begin_query(1,keys[0]);
    if (!negative || !cache.publish_negative(1,keys[0],d::NegativeKind::name_not_found,20,1000,*negative)) return false;
    for (std::size_t group=0;group<capacities.size();++group) {
        auto hit=cache.lookup_negative(group,keys[0],1000,reader);
        auto other=cache.lookup(group,keys[2],1000,reader);
        if (!hit || *hit!=d::NegativeKind::name_not_found || !other || !*other || (**other).addresses[0].bytes[0]!=12) return false;
    }
    auto stale_a=cache.lookup_stale(0,keys[4],2000,reader),stale_b=cache.lookup_stale(16,keys[6],2000,reader);
    if (!stale_a || !*stale_a || !stale_b || !*stale_b) return false;
    auto first=cache.begin_refresh(0,keys[4],2000,4),duplicate=cache.begin_refresh(16,keys[4],2000,4);
    auto distinct=cache.begin_refresh(16,keys[6],2000,4);
    if (!first || !*first || !duplicate || *duplicate || !distinct || !*distinct) return false;
    auto newer=cache.begin_query(1,keys[4]);
    if (!newer || !cache.publish(1,keys[4],make_answer(keys[4],90,20),2000,*newer)) return false;
    auto old=cache.publish(0,keys[4],make_answer(keys[4],91,20),2000,**first);
    if (old || old.error()!=Error::stale_query || !cache.publish(16,keys[6],make_answer(keys[6],92,20),2000,**distinct)) return false;
    auto before_clear=cache.begin_query(0,keys[0]);
    if (!before_clear || !cache.clear(2000)) return false;
    auto late=cache.publish(0,keys[0],make_answer(keys[0],99,20),2000,*before_clear);
    if (late || late.error()!=Error::stale_generation) return false;
    for (std::size_t group=0;group<capacities.size();++group) for (auto const& item:keys) {
        auto positive=cache.lookup(group,item,2000,reader);
        auto negative_hit=cache.lookup_negative(group,item,2000,reader);
        if (!positive || *positive || !negative_hit || *negative_hit) return false;
    }
    return true;
}
}
int main() {
    if (!all_views()) { std::cerr<<"17-group view isolation failed\n"; return 1; }
    for (auto seed:{20261030u,52137u,94621u,194503u}) if (!run(seed)) return 1;
    if (Cache::live_nodes()) { std::cerr<<"leaked cache nodes\n"; return 2; }
    std::puts("17 groups, four views, A/AAAA and 200000 mixed differential operations passed");
}
