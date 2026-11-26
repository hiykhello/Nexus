// Expand TUN route-address-set and route-exclude-address-set CIDRs from rule sets.
export module cli.tun_route_sets;
import std;
import config;
import platform.ip_address;
import rules;

export namespace cli::detail {
    inline constexpr std::size_t max_tun_route_cidrs = 65536;

    inline auto collect_ip_cidrs(rules::RuleSet const& set, std::vector<std::string>& out,
        bool include_v4, bool include_v6, std::size_t limit = max_tun_route_cidrs) -> void {
        std::unordered_set<std::string> seen(out.begin(), out.end());
        auto visit = [&](auto&& self, rules::Rule const& r) -> void {
            if (out.size() >= limit) return;
            if (r.type == "ip-cidr") {
                bool is_v6 = r.value.contains(':');
                if ((is_v6 && include_v6) || (!is_v6 && include_v4)) {
                    if (seen.insert(r.value).second) out.push_back(r.value);
                }
                return;
            }
            if (r.type == "and" || r.type == "or") {
                for (auto const& ch : r.children) self(self, ch);
            }
        };
        for (auto const& r : set.rules) visit(visit, r);
    }

    inline auto collect_ip_cidrs_mmap(rules::MmapMatcher const& mm, std::vector<std::string>& out,
        bool include_v4, bool include_v6, std::size_t limit = max_tun_route_cidrs) -> std::expected<void, std::string> {
        std::unordered_set<std::string> seen(out.begin(), out.end());
        auto push = [&](std::string cidr) -> bool {
            if (out.size() >= limit) return false;
            if (seen.insert(cidr).second) out.push_back(std::move(cidr));
            return out.size() < limit;
        };
        if (!mm.ip_cidr_match_source()) {
            if (include_v4) {
                for (std::uint32_t i = 0; i < mm.v4_count() && out.size() < limit; ++i) {
                    auto [lo, hi] = mm.v4_at(i);
                    std::uint64_t cur = lo, end = hi;
                    while (cur <= end && out.size() < limit) {
                        unsigned tz = cur == 0 ? 32u : static_cast<unsigned>(std::countr_zero(cur));
                        std::uint64_t rem = end - cur + 1;
                        unsigned max_k = rem >= (std::uint64_t{1} << 32) ? 32u : static_cast<unsigned>(63 - std::countl_zero(rem));
                        unsigned k = std::min(tz, max_k);
                        auto cidr = std::format("{}.{}.{}.{}/{}", (cur >> 24) & 0xffu, (cur >> 16) & 0xffu,
                            (cur >> 8) & 0xffu, cur & 0xffu, 32u - k);
                        if (!push(std::move(cidr))) break;
                        cur += (std::uint64_t{1} << k);
                    }
                }
            }
            if (include_v6) {
                using V6 = std::array<std::uint8_t, 16>;
                auto ctz = [](V6 const& v) noexcept -> unsigned {
                    for (int idx = 15; idx >= 0; --idx)
                        if (v[static_cast<std::size_t>(idx)] != 0)
                            return static_cast<unsigned>((15 - idx) * 8 + std::countr_zero(v[static_cast<std::size_t>(idx)]));
                    return 128u;
                };
                auto fits = [](V6 const& cur, V6 const& end, unsigned k) noexcept -> bool {
                    if (k == 128) return cur == V6{} && end == V6{255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255};
                    V6 top = cur;
                    unsigned b = 15 - (k / 8), r = k % 8;
                    if (r) top[b] |= static_cast<std::uint8_t>((1u << r) - 1u);
                    for (std::size_t j = b + 1; j < 16; ++j) top[j] = 0xffu;
                    return top <= end;
                };
                auto add_p2 = [](V6 cur, unsigned k, bool& wrapped) noexcept -> V6 {
                    wrapped = false;
                    if (k >= 128) { wrapped = true; return V6{}; }
                    unsigned carry = 1u << (k % 8);
                    for (int j = static_cast<int>(15 - (k / 8)); j >= 0 && carry; --j) {
                        unsigned s = static_cast<unsigned>(cur[static_cast<std::size_t>(j)]) + carry;
                        cur[static_cast<std::size_t>(j)] = static_cast<std::uint8_t>(s & 0xffu);
                        carry = s >> 8;
                    }
                    wrapped = carry != 0;
                    return cur;
                };
                for (std::uint32_t i = 0; i < mm.v6_count() && out.size() < limit; ++i) {
                    auto [cur, end] = mm.v6_at(i);
                    while (out.size() < limit) {
                        unsigned k = ctz(cur);
                        while (k > 0 && !fits(cur, end, k)) --k;
                        auto txt = platform::format_ip_address(cur);
                        if (!txt || !push(std::format("{}/{}", *txt, 128u - k))) break;
                        bool wrapped = false;
                        cur = add_p2(cur, k, wrapped);
                        if (wrapped || cur > end) break;
                    }
                }
            }
        }
        if (mm.tail_beve_bytes() > 0 && out.size() < limit) {
            auto tail = rules::parse_beve(mm.tail_beve());
            if (!tail) return std::unexpected(tail.error().message);
            collect_ip_cidrs(*tail, out, include_v4, include_v6, limit);
        }
        return {};
    }

    inline auto expand_tun_set_list(std::vector<std::string> const& tags,
        std::vector<std::pair<std::string, config::BlockRules>> const& specs,
        std::function<std::expected<rules::RuleSet, std::string>(config::BlockRules const&)> const& loader,
        std::vector<std::string>& out, bool include_v4, bool include_v6) -> std::expected<void, std::string> {
        for (auto const& tag : tags) {
            auto it = std::ranges::find_if(specs, [&](auto const& item) { return item.first == tag; });
            if (it == specs.end()) return std::unexpected("TUN rule-set not found: " + tag);
            auto parsed = loader(it->second);
            if (!parsed) return std::unexpected(std::move(parsed.error()));
            collect_ip_cidrs(*parsed, out, include_v4, include_v6, max_tun_route_cidrs);
        }
        return {};
    }
}
