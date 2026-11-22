// Include after bounded_table.hpp and the DNS module imports.
#pragma once
namespace dns_hp_experiment {
struct ActualKeyHash {
    auto operator()(dns::CacheKey const& key) const noexcept -> std::size_t {
        auto hash=std::hash<std::string>{}(key.name);
        hash^=std::hash<std::uint64_t>{}(key.view)+0x9e3779b9+(hash<<6)+(hash>>2);
        hash^=std::hash<std::uint16_t>{}(key.type)+0x9e3779b9+(hash<<6)+(hash>>2);
        return hash;
    }
};
struct ActualKeyEqual {
    auto operator()(dns::CacheKey const& a,dns::CacheKey const& b) const noexcept -> bool {
        return a.view==b.view && a.type==b.type && a.name==b.name;
    }
};
struct ActualValue { dns::AddressAnswer answer; std::uint64_t expires; };
using ActualTable=BoundedTable<dns::CacheKey,ActualValue,ActualKeyHash,ActualKeyEqual>;
}
