// Compiled O(log N) merged CIDR interval and sorted domain/suffix index for large Kind::any rule-sets.
export module rules.any_index;
import std;
import encoding.endian;

export namespace rules::any_detail {
    inline auto read_be32(std::array<std::uint8_t, 16> const& bytes, std::size_t off = 0) noexcept -> std::uint32_t {
        return encoding::read_be32(std::span<std::uint8_t const, 4>(bytes.data() + off, 4));
    }

    inline auto ipv4_range(std::array<std::uint8_t, 16> const& addr, unsigned prefix) noexcept
        -> std::pair<std::uint32_t, std::uint32_t> {
        if (prefix == 0) return {0u, 0xffffffffu};
        std::uint32_t mask = prefix == 32 ? 0xffffffffu : (0xffffffffu << (32u - prefix));
        std::uint32_t lo = read_be32(addr) & mask;
        return {lo, lo | ~mask};
    }

    inline auto ipv6_range(std::array<std::uint8_t, 16> addr, unsigned prefix) noexcept
        -> std::pair<std::array<std::uint8_t, 16>, std::array<std::uint8_t, 16>> {
        auto lo = addr;
        auto hi = addr;
        auto bytes = prefix / 8;
        auto rem = prefix % 8;
        if (rem) {
            auto mask = static_cast<std::uint8_t>(0xffu << (8u - rem));
            lo[bytes] &= mask;
            hi[bytes] |= static_cast<std::uint8_t>(~mask);
            ++bytes;
        }
        for (std::size_t i = bytes; i < 16; ++i) { lo[i] = 0; hi[i] = 0xff; }
        return {lo, hi};
    }

    inline auto add_one_v6(std::array<std::uint8_t, 16> v) noexcept -> std::optional<std::array<std::uint8_t, 16>> {
        for (int i = 15; i >= 0; --i) {
            if (v[static_cast<std::size_t>(i)] != 0xff) { ++v[static_cast<std::size_t>(i)]; return v; }
            v[static_cast<std::size_t>(i)] = 0;
        }
        return std::nullopt;
    }

    template<class Interval>
    auto merge_v4(std::vector<Interval>& ranges) -> void {
        if (ranges.empty()) return;
        std::ranges::sort(ranges, [](auto const& a, auto const& b) {
            return std::tie(a.first, a.last) < std::tie(b.first, b.last);
        });
        std::size_t out = 0;
        for (std::size_t i = 1; i < ranges.size(); ++i) {
            if (ranges[i].first <= ranges[out].last ||
                (ranges[out].last < 0xffffffffu && ranges[i].first == ranges[out].last + 1u)) {
                ranges[out].last = std::max(ranges[out].last, ranges[i].last);
            } else {
                ranges[++out] = ranges[i];
            }
        }
        ranges.resize(out + 1);
    }

    template<class Interval>
    auto merge_v6(std::vector<Interval>& ranges) -> void {
        if (ranges.empty()) return;
        std::ranges::sort(ranges, [](auto const& a, auto const& b) {
            return std::tie(a.first, a.last) < std::tie(b.first, b.last);
        });
        std::size_t out = 0;
        for (std::size_t i = 1; i < ranges.size(); ++i) {
            auto next = add_one_v6(ranges[out].last);
            if (ranges[i].first <= ranges[out].last || (next && ranges[i].first <= *next)) {
                if (ranges[i].last > ranges[out].last) ranges[out].last = ranges[i].last;
            } else {
                ranges[++out] = ranges[i];
            }
        }
        ranges.resize(out + 1);
    }

    template<class Interval>
    auto contains_v4(std::vector<Interval> const& ranges, std::uint32_t ip) noexcept -> bool {
        if (ranges.empty()) return false;
        auto it = std::upper_bound(ranges.begin(), ranges.end(), ip,
            [](std::uint32_t val, Interval const& r) { return val < r.first; });
        return it != ranges.begin() && ip <= std::prev(it)->last;
    }

    template<class Interval>
    auto contains_v6(std::vector<Interval> const& ranges, std::array<std::uint8_t, 16> const& ip) noexcept -> bool {
        if (ranges.empty()) return false;
        auto it = std::upper_bound(ranges.begin(), ranges.end(), ip,
            [](std::array<std::uint8_t, 16> const& val, Interval const& r) { return val < r.first; });
        return it != ranges.begin() && ip <= std::prev(it)->last;
    }

    inline auto match_sorted_domain(auto const& entries, std::vector<std::uint32_t> const& sorted_ids,
        std::string_view key) noexcept -> bool {
        auto it = std::lower_bound(sorted_ids.begin(), sorted_ids.end(), key,
            [&](std::uint32_t id, std::string_view v) { return entries[id].text < v; });
        return it != sorted_ids.end() && entries[*it].text == key;
    }

    inline auto match_any_domain(auto const& entries, auto const& idx, std::string_view raw) noexcept -> bool {
        std::array<char, 253> lowered{};
        auto name = raw;
        if (std::ranges::any_of(name, [](char c) { return c >= 'A' && c <= 'Z'; })) {
            if (name.size() > lowered.size()) return false;
            for (std::size_t i = 0; i < name.size(); ++i) {
                char c = name[i];
                lowered[i] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c;
            }
            name = std::string_view(lowered.data(), name.size());
        }
        if (!idx.domains.empty() && match_sorted_domain(entries, idx.domains, name)) return true;
        if (!idx.suffixes.empty()) {
            for (;;) {
                if (match_sorted_domain(entries, idx.suffixes, name)) return true;
                auto dot = name.find('.');
                if (dot == std::string_view::npos) break;
                name.remove_prefix(dot + 1);
            }
        }
        return false;
    }

    inline auto match_any_ip_one(auto const& idx, std::array<std::uint8_t, 16> const& bytes,
        unsigned family, bool match_mapped) noexcept -> bool {
        if (family == 4) return contains_v4(idx.ipv4, read_be32(bytes));
        if (family != 6) return false;
        if (contains_v6(idx.ipv6, bytes)) return true;
        if (match_mapped && !idx.ipv4.empty() &&
            std::all_of(bytes.begin(), bytes.begin() + 10, [](auto b) { return b == 0; }) &&
            bytes[10] == 0xff && bytes[11] == 0xff) {
            return contains_v4(idx.ipv4, read_be32(bytes, 12));
        }
        return false;
    }

    inline auto compile_any_index(auto const& entries, auto const& children,
        std::uint32_t first, std::uint32_t count, auto ip_kind, auto domain_kind, auto suffix_kind,
        auto& any_indexes) -> std::uint32_t {
        using Idx = typename std::remove_reference_t<decltype(any_indexes)>::value_type;
        Idx compiled{};
        for (std::uint32_t i = 0; i < count; ++i) {
            auto cid = children[first + i];
            auto const& ce = entries[cid];
            if (ce.kind == ip_kind) {
                compiled.has_ip = true;
                if (ce.ip.family == 4) {
                    auto [lo, hi] = ipv4_range(ce.ip.address, ce.ip.prefix);
                    compiled.ipv4.push_back({lo, hi});
                } else {
                    auto [lo, hi] = ipv6_range(ce.ip.address, ce.ip.prefix);
                    compiled.ipv6.push_back({lo, hi});
                }
            } else if (ce.kind == domain_kind) {
                compiled.has_domain = true;
                compiled.domains.push_back(cid);
            } else if (ce.kind == suffix_kind) {
                compiled.has_domain = true;
                compiled.suffixes.push_back(cid);
            } else {
                compiled.remainder.push_back(cid);
            }
        }
        if (!compiled.has_ip && !compiled.has_domain) return std::numeric_limits<std::uint32_t>::max();
        merge_v4(compiled.ipv4);
        merge_v6(compiled.ipv6);
        auto cmp = [&](std::uint32_t a, std::uint32_t b) { return entries[a].text < entries[b].text; };
        std::ranges::sort(compiled.domains, cmp);
        std::ranges::sort(compiled.suffixes, cmp);
        auto id = static_cast<std::uint32_t>(any_indexes.size());
        any_indexes.push_back(std::move(compiled));
        return id;
    }
}
