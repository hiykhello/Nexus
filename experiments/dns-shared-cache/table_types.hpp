// Shared value shape for the experimental containers, not the production cache.
#pragma once
#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace dns_hp_experiment {
struct Key {
    std::uint64_t view;
    std::string name;
    std::uint16_t type;
    bool operator==(Key const&) const = default;
};
struct KeyHash {
    std::size_t operator()(Key const& key) const noexcept {
        auto h=std::hash<std::string>{}(key.name);
        h^=std::hash<std::uint64_t>{}(key.view)+0x9e3779b9+(h<<6)+(h>>2);
        h^=std::hash<std::uint16_t>{}(key.type)+0x9e3779b9+(h<<6)+(h>>2);
        return h;
    }
};
struct Answer {
    std::string canonical_name;
    std::vector<std::string> chain;
    std::array<std::uint8_t,16> address{};
    std::uint64_t expires=0;
    std::uint64_t revision=0;
};
}
