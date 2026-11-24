// Expand TUN route-address-set and route-exclude-address-set CIDRs from rule sets.
export module cli.tun_route_sets;
import std;
import config;
import rules;

export namespace cli::detail {
    inline auto collect_ip_cidrs(rules::RuleSet const& set, std::vector<std::string>& out,
        bool include_v4, bool include_v6, std::size_t limit = 64) -> void {
        auto visit = [&](auto&& self, rules::Rule const& r) -> void {
            if (out.size() >= limit) return;
            if (r.type == "ip-cidr") {
                bool is_v6 = r.value.contains(':');
                if ((is_v6 && include_v6) || (!is_v6 && include_v4)) {
                    if (!std::ranges::contains(out, r.value)) out.push_back(r.value);
                }
                return;
            }
            if (r.type == "and" || r.type == "or") {
                for (auto const& ch : r.children) self(self, ch);
            }
        };
        for (auto const& r : set.rules) visit(visit, r);
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
            collect_ip_cidrs(*parsed, out, include_v4, include_v6);
        }
        return {};
    }
}
