export module packet.tun_network_plan;
import std;
import platform.ip_address;

export namespace packet {
    struct TunCidr {
        std::uint8_t family = 0; // 4 or 6
        std::array<std::uint8_t, 16> address{};
        std::uint8_t prefix = 0;
        auto operator==(TunCidr const&) const -> bool = default;
    };

    [[nodiscard]] inline auto parse_tun_cidr(std::string_view text) -> std::optional<TunCidr> {
        auto slash = text.find('/');
        if (slash == std::string_view::npos || slash == 0 || slash + 1 >= text.size())
            return std::nullopt;
        if (text.find('/', slash + 1) != std::string_view::npos) return std::nullopt;
        auto pfx_sv = text.substr(slash + 1);
        if (pfx_sv.size() > 3 || (pfx_sv.size() > 1 && pfx_sv.front() == '0')) return std::nullopt;
        unsigned prefix = 0;
        auto [end, ec] = std::from_chars(pfx_sv.data(), pfx_sv.data() + pfx_sv.size(), prefix);
        if (ec != std::errc{} || end != pfx_sv.data() + pfx_sv.size()) return std::nullopt;
        auto parsed = platform::parse_ip_address(text.substr(0, slash));
        if (!parsed) return std::nullopt;
        std::uint8_t family = parsed->size == 4 ? 4 : 6;
        unsigned max_prefix = family == 4 ? 32u : 128u;
        if (prefix < 1 || prefix > max_prefix) return std::nullopt;
        TunCidr out{.family = family, .address = parsed->bytes, .prefix = static_cast<std::uint8_t>(prefix)};
        if (family == 4) std::fill(out.address.begin() + 4, out.address.end(), 0);
        return out;
    }

    [[nodiscard]] inline auto mask_tun_cidr(TunCidr cidr) noexcept -> TunCidr {
        std::size_t bytes = cidr.family == 6 ? 16 : cidr.family == 4 ? 4 : 0;
        if (!bytes) return cidr;
        std::size_t keep = cidr.prefix / 8;
        std::size_t rem = cidr.prefix % 8;
        if (keep < bytes && rem)
            cidr.address[keep] &= static_cast<std::uint8_t>(0xffu << (8 - rem));
        for (std::size_t i = keep + (rem != 0); i < cidr.address.size(); ++i)
            cidr.address[i] = 0;
        return cidr;
    }

    struct TunRoutePlanInput {
        std::optional<TunCidr> inet4, inet6;
        std::uint16_t mtu = 1500;
        bool auto_route = false, route_exclude_private = false;
        std::vector<TunCidr> includes, excludes;
    };

    struct TunRoutePlan {
        std::vector<TunCidr> addresses, routes, excludes;
        std::uint16_t mtu = 1500;
    };

    [[nodiscard]] inline auto plan_cross_platform_tun_routes(TunRoutePlanInput const& input)
        -> std::expected<TunRoutePlan, std::string> {
        if (input.mtu < 68 || input.mtu > 65535)
            return std::unexpected("TUN MTU must be between 68 and 65535");
        if (input.inet6 && input.mtu < 1280)
            return std::unexpected("IPv6 TUN requires MTU >= 1280");
        auto push_unique = [](std::vector<TunCidr>& dst, TunCidr const& val) {
            if (!std::ranges::contains(dst, val)) dst.push_back(val);
        };
        auto family_enabled = [&](std::uint8_t family) noexcept -> bool {
            return (family == 4 && input.inet4) || (family == 6 && input.inet6);
        };
        auto valid_cidr = [](TunCidr const& c) noexcept -> bool {
            return (c.family == 4 && c.prefix >= 1 && c.prefix <= 32) ||
                   (c.family == 6 && c.prefix >= 1 && c.prefix <= 128);
        };
        TunRoutePlan plan;
        plan.mtu = input.mtu;
        if (input.inet4) {
            if (!valid_cidr(*input.inet4) || input.inet4->family != 4)
                return std::unexpected("invalid IPv4 TUN address");
            auto addr = *input.inet4;
            std::fill(addr.address.begin() + 4, addr.address.end(), 0);
            push_unique(plan.addresses, addr);
        }
        if (input.inet6) {
            if (!valid_cidr(*input.inet6) || input.inet6->family != 6)
                return std::unexpected("invalid IPv6 TUN address");
            push_unique(plan.addresses, *input.inet6);
        }
        if (input.auto_route) {
            if (plan.addresses.empty())
                return std::unexpected("auto-route requires at least one TUN address");
            if (!input.includes.empty()) {
                for (auto const& inc : input.includes) {
                    if (!valid_cidr(inc)) return std::unexpected("invalid route-include CIDR");
                    if (family_enabled(inc.family)) push_unique(plan.routes, mask_tun_cidr(inc));
                }
            } else {
                if (input.inet4) {
                    push_unique(plan.routes, TunCidr{4, {0}, 1});
                    push_unique(plan.routes, TunCidr{4, {128}, 1});
                }
                if (input.inet6) {
                    push_unique(plan.routes, TunCidr{6, {0}, 1});
                    push_unique(plan.routes, TunCidr{6, {0x80}, 1});
                }
            }
        }
        for (auto const& exc : input.excludes) {
            if (!valid_cidr(exc)) return std::unexpected("invalid route-exclude CIDR");
            if (family_enabled(exc.family)) push_unique(plan.excludes, mask_tun_cidr(exc));
        }
        if (input.route_exclude_private) {
            constexpr std::array private_cidrs{
                TunCidr{4, {10}, 8}, TunCidr{4, {172, 16}, 12},
                TunCidr{4, {192, 168}, 16}, TunCidr{4, {100, 64}, 10},
                TunCidr{4, {169, 254}, 16}, TunCidr{6, {0xfc}, 7},
                TunCidr{6, {0xfe, 0x80}, 10}
            };
            for (auto const& exc : private_cidrs)
                if (family_enabled(exc.family)) push_unique(plan.excludes, exc);
        }
        return plan;
    }
}
