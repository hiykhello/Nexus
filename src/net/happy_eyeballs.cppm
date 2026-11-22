export module net.happy_eyeballs;
import std;

export namespace net {
    // RFC 8305 Section 5: Connection Attempt Delay (300 ms recommended).
    inline constexpr std::chrono::milliseconds kHappyEyeballsFallbackDelay{300};

    template<class T, class IsV6>
    [[nodiscard]] auto has_dual_stack_families(std::span<T const> candidates, IsV6&& is_v6) noexcept -> bool {
        bool seen_v4 = false;
        bool seen_v6 = false;
        for (auto const& item : candidates) {
            if (is_v6(item)) seen_v6 = true;
            else seen_v4 = true;
            if (seen_v4 && seen_v6) return true;
        }
        return false;
    }

    // RFC 8305 Section 4: Interleave IPv6 and IPv4 address candidates (First Address Family Count = 1)
    // preserving relative order within each address family. Single-stack inputs are returned unchanged.
    template<class T, class IsV6>
    [[nodiscard]] auto interleave_happy_eyeballs(std::span<T const> candidates, IsV6&& is_v6, bool prefer_ipv6 = true) -> std::vector<T> {
        std::vector<T> v6;
        std::vector<T> v4;
        v6.reserve(candidates.size());
        v4.reserve(candidates.size());
        for (auto const& item : candidates) {
            if (is_v6(item)) v6.push_back(item);
            else v4.push_back(item);
        }
        if (v6.empty() || v4.empty()) {
            return std::vector<T>(candidates.begin(), candidates.end());
        }
        auto const& primary = prefer_ipv6 ? v6 : v4;
        auto const& secondary = prefer_ipv6 ? v4 : v6;
        std::vector<T> out;
        out.reserve(candidates.size());
        std::size_t i = 0;
        std::size_t j = 0;
        while (i < primary.size() || j < secondary.size()) {
            if (i < primary.size()) out.push_back(primary[i++]);
            if (j < secondary.size()) out.push_back(secondary[j++]);
        }
        return out;
    }
}
