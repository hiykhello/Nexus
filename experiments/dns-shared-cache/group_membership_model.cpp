// Single-threaded semantic model only. Its shared_ptrs, map, allocations and
// linear scans are not the proposed production synchronization or index.
import std;

namespace {
struct Key {
    unsigned view;
    std::string name;
    unsigned type;
    auto operator<=>(Key const&) const = default;
};
struct Reply {
    unsigned value;
    bool negative;
    std::uint64_t expires;
    auto operator<=>(Reply const&) const = default;
};
struct Record { Key key; Reply reply; };
struct Binding { std::shared_ptr<Record const> record; std::uint64_t order; };
struct Group { std::size_t capacity; std::vector<Binding> bindings; std::uint64_t next_order=0; };
struct Shared { std::shared_ptr<Record const> record; std::size_t memberships=0; };

class MembershipModel {
    std::vector<Group> groups_;
    std::map<Key,Shared> shared_;

    static auto find(Group& group,Key const& key) {
        return std::ranges::find_if(group.bindings,[&](auto const& binding) { return binding.record->key==key; });
    }
    auto remove(Group& group,std::size_t index) -> void {
        auto item=shared_.find(group.bindings[index].record->key);
        if (item==shared_.end() || !item->second.memberships) std::terminate();
        if (!--item->second.memberships) shared_.erase(item);
        group.bindings.erase(group.bindings.begin()+index);
    }
    auto prune(Group& group,std::uint64_t now) -> void {
        for (std::size_t i=0;i<group.bindings.size();)
            if (group.bindings[i].record->reply.expires<=now) remove(group,i); else ++i;
    }
    auto make_room(Group& group) -> void {
        if (group.bindings.size()<group.capacity) return;
        auto victim=std::ranges::min_element(group.bindings,{},[](auto const& binding) {
            return std::pair{binding.record->reply.expires,binding.order};
        });
        remove(group,static_cast<std::size_t>(victim-group.bindings.begin()));
    }
    auto attach(Group& group,Shared& shared) -> void {
        group.bindings.push_back({shared.record,++group.next_order});
        ++shared.memberships;
    }
public:
    explicit MembershipModel(std::span<std::size_t const> capacities) {
        for (auto capacity:capacities) {
            groups_.push_back({capacity});
            groups_.back().bindings.reserve(capacity);
        }
    }
    auto publish(std::size_t group_index,Key key,Reply reply,std::uint64_t now) -> bool {
        auto& group=groups_.at(group_index);
        if (!group.capacity) return false;
        if (reply.expires<=now) { invalidate(key); return true; }
        auto record=std::make_shared<Record const>(Record{key,reply});
        prune(group,now);
        bool present=find(group,key)!=group.bindings.end();
        if (!present) make_room(group);
        auto [item,inserted]=shared_.try_emplace(key,Shared{record,0});
        if (!inserted) {
            item->second.record=record;
            for (auto& other:groups_) for (auto& binding:other.bindings)
                if (binding.record->key==key) binding.record=record;
        }
        if (!present) attach(group,item->second);
        return true;
    }
    auto lookup(std::size_t group_index,Key const& key,std::uint64_t now) -> std::optional<Reply> {
        auto& group=groups_.at(group_index);
        if (!group.capacity) return {};
        prune(group,now);
        if (auto item=find(group,key); item!=group.bindings.end()) return item->record->reply;
        auto item=shared_.find(key);
        if (item==shared_.end() || item->second.record->reply.expires<=now) return {};
        make_room(group);
        // make_room only removes a different key: this group did not hold key.
        attach(group,item->second);
        return item->second.record->reply;
    }
    auto invalidate(Key const& key) -> void {
        for (auto& group:groups_) {
            auto item=find(group,key);
            if (item!=group.bindings.end()) remove(group,static_cast<std::size_t>(item-group.bindings.begin()));
        }
    }
    auto release_group(std::size_t index) -> void {
        auto& group=groups_.at(index);
        while (!group.bindings.empty()) remove(group,group.bindings.size()-1);
        group.capacity=0;
    }
    auto clear() -> void {
        for (auto& group:groups_) group.bindings.clear();
        shared_.clear();
    }
    [[nodiscard]] auto size(std::size_t group) const -> std::size_t { return groups_.at(group).bindings.size(); }
    [[nodiscard]] auto unique_records() const -> std::size_t { return shared_.size(); }
    [[nodiscard]] auto memberships() const -> std::size_t {
        std::size_t result=0; for (auto const& group:groups_) result+=group.bindings.size(); return result;
    }
    [[nodiscard]] auto consistent() const -> bool {
        std::map<Key,std::size_t> counts;
        std::size_t total_capacity=0;
        for (auto const& group:groups_) {
            if (group.bindings.size()>group.capacity) return false;
            total_capacity+=group.capacity;
            std::set<Key> group_keys;
            for (auto const& binding:group.bindings) {
                auto const& key=binding.record->key;
                auto item=shared_.find(key);
                if (!group_keys.insert(key).second || item==shared_.end() || item->second.record!=binding.record) return false;
                ++counts[key];
            }
        }
        if (shared_.size()>memberships() || memberships()>total_capacity || counts.size()!=shared_.size()) return false;
        for (auto const& [key,item]:shared_) if (counts[key]!=item.memberships || !item.memberships) return false;
        return true;
    }
};

auto key(unsigned group,unsigned i,unsigned view=1) -> Key {
    return {view,std::format("group-{}-{:04}.example",group,i),1};
}
auto fairness() -> bool {
    std::array<std::size_t,2> capacity{256,256}; MembershipModel cache(capacity);
    constexpr std::uint64_t now=1000;
    for (unsigned i=0;i<256;++i) if (!cache.publish(0,key(0,i),{1,false,3601000},now)) return false;
    for (unsigned i=0;i<256;++i) if (!cache.publish(1,key(1,i),{2,false,601000},now)) return false;
    for (unsigned i=0;i<256;++i) if (!cache.publish(0,key(2,i),{3,false,7201000},now)) return false;
    unsigned old=0,fresh=0,other=0;
    for (unsigned i=0;i<256;++i) {
        old+=cache.lookup(0,key(0,i),now).has_value();
        fresh+=cache.lookup(0,key(2,i),now).has_value();
        other+=cache.lookup(1,key(1,i),now).has_value();
    }
    std::println("membership fairness: A old {}, A new {}, B {}, {} unique",old,fresh,other,cache.unique_records());
    return old==0 && fresh==256 && other==256 && cache.unique_records()==512 && cache.consistent();
}
auto overlap_and_updates() -> bool {
    std::array<std::size_t,2> capacity{256,256}; MembershipModel cache(capacity);
    for (unsigned i=0;i<256;++i) if (!cache.publish(0,key(0,i),{i,false,60000},1000)) return false;
    for (unsigned i=0;i<256;++i) {
        auto result=cache.lookup(1,key(0,i),1000);
        if (!result || result->value!=i || result->negative) return false;
    }
    std::println("membership overlap: {} bindings, {} unique",cache.memberships(),cache.unique_records());
    if (cache.memberships()!=512 || cache.unique_records()!=256 || !cache.consistent()) return false;
    auto different=key(0,0,2);
    if (cache.lookup(1,different,1000) || !cache.publish(1,different,{700,false,60000},1000)) return false;
    if (!cache.publish(0,key(0,1),{900,true,60000},1000)) return false;
    auto updated=cache.lookup(1,key(0,1),1000),separate=cache.lookup(1,different,1000);
    if (!updated || updated->value!=900 || !updated->negative || !separate || separate->value!=700) return false;
    if (!cache.publish(0,key(0,1),{0,false,1000},1000) || cache.lookup(0,key(0,1),1000) || cache.lookup(1,key(0,1),1000)) return false;
    if (!cache.lookup(1,different,1000) || !cache.consistent()) return false;
    cache.clear();
    return !cache.memberships() && !cache.unique_records() && !cache.lookup(1,different,1000) && cache.consistent();
}
auto eviction_and_expiry() -> bool {
    std::array<std::size_t,2> capacity{1,1}; MembershipModel cache(capacity);
    auto x=key(0,0),y=key(0,1),z=key(0,2);
    if (!cache.publish(0,x,{1,false,10000},1000) || !cache.lookup(1,x,1000)) return false;
    if (!cache.publish(0,y,{2,false,20000},1000) || cache.unique_records()!=2 || !cache.lookup(1,x,1000)) return false;
    if (!cache.publish(1,z,{3,false,30000},1000) || cache.unique_records()!=2 || cache.lookup(0,x,1000)) return false;
    if (!cache.lookup(1,y,1000) || cache.unique_records()!=1 || cache.memberships()!=2) return false;
    cache.release_group(0);
    if (cache.lookup(0,y,1000) || !cache.lookup(1,y,1000) || cache.unique_records()!=1) return false;
    return !cache.lookup(1,y,20000) && cache.unique_records()==0 && cache.consistent();
}
auto full_capacity_and_mixed() -> bool {
    std::array<std::size_t,17> capacities; capacities.fill(256); MembershipModel cache(capacities);
    for (unsigned group=0;group<17;++group) for (unsigned i=0;i<256;++i)
        if (!cache.publish(group,key(group,i),{i,false,100000},1000)) return false;
    if (cache.unique_records()!=4352 || cache.memberships()!=4352 || !cache.consistent()) return false;
    std::mt19937 random(41);
    for (unsigned step=0;step<5000;++step) {
        auto group=random()%17, owner=random()%17, index=random()%320;
        auto item=key(owner,index,1+random()%3);
        switch (random()%5) {
            case 0: cache.invalidate(item); break;
            case 1: (void)cache.lookup(group,item,1000); break;
            default: if (!cache.publish(group,item,{step,step%3==0,10000+step},1000)) return false;
        }
        if (step%100==0 && !cache.consistent()) return false;
    }
    return cache.consistent();
}
}

int main() {
    if (!fairness()) { std::cerr<<"fairness failed\n"; return 1; }
    if (!overlap_and_updates()) { std::cerr<<"overlap or update failed\n"; return 2; }
    if (!eviction_and_expiry()) { std::cerr<<"eviction or expiry failed\n"; return 3; }
    if (!full_capacity_and_mixed()) { std::cerr<<"capacity or mixed trace failed\n"; return 4; }
    std::puts("membership model: view, update, invalidation, expiry, release and capacity passed");
}
