// DNS fake-ip KDL configuration parser implementation.
module config;
import std;
import glaze;
import config.kdl_common;

namespace config {
    using namespace config::kdl;
    auto dns_ipv4(std::string_view) -> std::optional<std::array<std::uint8_t, 4>>;
    auto dns_ipv6(std::string_view) -> std::optional<std::array<std::uint8_t, 16>>;

    auto parse_fakeip(Node const& child) -> std::expected<std::pair<DnsFakeIp, std::string>, std::string> {
        auto pool = text_property(child, "ipv4-pool"), server = text_property(child, "server");
        auto state_value = property(child, "state-directory");
        auto state = text_property(child, "state-directory");
        auto ipv6_value = property(child, "ipv6-pool");
        auto ipv6 = text_property(child, "ipv6-pool");
        auto ttl_value = property(child, "ttl-seconds");
        auto ttl = ttl_value ? integer(*ttl_value) : std::optional<std::uint64_t>{60};
        auto init_value = property(child, "initialize");
        auto initialize = init_value && !init_value->tag ? std::get_if<bool>(&init_value->data) : nullptr;
        if (child.tag || !child.arguments.empty() || !child.children.empty() ||
            child.properties.size() != 2 + bool(state_value) + bool(ttl_value) + bool(init_value) + bool(ipv6_value) ||
            (ipv6_value && !ipv6) || !pool || !server ||
            !valid_name(*server) || (state_value && (!state || !state->starts_with('/') || state->contains('\0'))) ||
            !ttl || !*ttl || *ttl > std::numeric_limits<std::uint32_t>::max() || (init_value && !initialize))
            return error("invalid DNS fake-ip options");
        std::string_view cidr = *pool;
        auto slash = cidr.find('/');
        if (slash == cidr.npos) return error("fake-ip ipv4-pool requires a CIDR");
        auto address = dns_ipv4(cidr.substr(0, slash));
        auto suffix = cidr.substr(slash + 1);
        unsigned prefix = 0;
        auto [end, parsed] = std::from_chars(suffix.data(), suffix.data() + suffix.size(), prefix);
        if (!address || parsed != std::errc{} || end != suffix.data() + suffix.size() || prefix < 16 || prefix > 32)
            return error("fake-ip ipv4-pool must have a prefix from 16 to 32");
        std::uint32_t base = 0;
        for (auto byte : *address) base = (base << 8) | byte;
        auto mask = (std::uint32_t{1} << (32 - prefix)) - 1;
        if (base & mask) return error("fake-ip ipv4-pool has host bits");
        DnsFakeIp result{base, base | mask, static_cast<std::uint32_t>(*ttl), state ? *state : std::string{}, 0, initialize && *initialize};
        if (ipv6) {
            std::string_view range = *ipv6;
            auto separator = range.find('/');
            if (separator == range.npos) return error("fake-ip ipv6-pool requires a CIDR");
            auto network = dns_ipv6(range.substr(0, separator));
            auto width = range.substr(separator + 1);
            unsigned length = 0;
            auto [finish, status] = std::from_chars(width.data(), width.data() + width.size(), length);
            if (!network || status != std::errc{} || finish != width.data() + width.size() ||
                length < 7 || length > 96 || ((*network)[0] & 0xfe) != 0xfc)
                return error("fake-ip ipv6-pool must be a unique-local CIDR with a prefix from 7 to 96");
            for (auto bit = length; bit < 128; ++bit)
                if ((*network)[bit / 8] & (0x80u >> (bit % 8))) return error("fake-ip ipv6-pool has host bits");
            std::array<std::uint8_t, 12> high{};
            std::copy_n(network->begin(), high.size(), high.begin());
            result.ipv6 = std::pair{high, static_cast<std::uint8_t>(length)};
        }
        return std::pair{std::move(result), *server};
    }
}
