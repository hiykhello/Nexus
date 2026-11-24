export module packet.tun_network_types;
import std;
import platform.netlink_codec;
import packet.tun_linux;

export namespace packet {
    struct TunAddress {
        std::uint8_t family = 0;
        std::array<std::uint8_t, 16> bytes{};
        std::uint8_t prefix = 0;
        auto operator==(TunAddress const &) const -> bool = default;
    };
    struct TunUidRange {
        std::uint32_t min = 0, max = 0;
        auto operator==(TunUidRange const &) const -> bool = default;
    };
    struct TunRedirectOptions {
        std::uint16_t port=0;
        bool tcp_dns=false, udp_dns=false, exclude_mptcp=false;
        std::array<TunAddress,2> protected_destinations{};
        std::uint8_t protected_count=0;
        std::uint32_t input_mark=0, output_mark=0, reset_mark=0;
        std::array<TunUidRange,16> include_uids{}, exclude_uids{};
        std::uint8_t include_uid_count=0, exclude_uid_count=0;
        std::array<std::array<char,16>,8> include_interfaces{}, exclude_interfaces{};
        std::uint8_t include_if_count=0, exclude_if_count=0;
    };
    struct TunNetworkOptions {
        std::uint32_t mtu = 1420;
        std::array<TunAddress, 16> addresses{};
        std::size_t address_count = 0;
        std::array<TunAddress, 64> routes{};
        std::size_t route_count = 0;
        auto operator==(TunNetworkOptions const &) const -> bool = default;
    };
    enum class TunNetworkError { configuration, state, device, netlink, ownership, conflict, readback, entropy };
    enum class TunNetworkStage { validate, identify, claim, mtu, address, route, enable, verify, disable, remove_route, remove_address, close };
    struct TunCleanupIssue {
        TunNetworkError code;
        TunNetworkStage stage;
        std::error_code system;
    };
    struct TunCleanupReport {
        std::array<TunCleanupIssue, 8> issues{};
        std::size_t recorded = 0, total = 0;
        bool device_closed = false, device_removed = false, socket_closed = false;
        auto add(TunCleanupIssue issue) noexcept -> void {
            if (recorded < issues.size()) issues[recorded++] = issue;
            ++total;
        }
    };
    struct TunNetworkFailure {
        TunNetworkError code;
        TunNetworkStage stage;
        std::error_code system;
        std::optional<platform::netlink::Failure> netlink;
        std::optional<TunFailure> device;
    };
    struct TunNetworkStatus {
        bool started = false, stopped = false;
        std::int32_t ifindex = 0;
        std::size_t addresses = 0, routes = 0, reconciled = 0;
    };
    namespace tun_network_detail {
        inline auto fail(TunNetworkError code, TunNetworkStage stage, std::error_code system = {}) -> std::unexpected<TunNetworkFailure> {
            return std::unexpected(TunNetworkFailure{.code = code, .stage = stage, .system = system});
        }
        inline auto ip_bytes(std::uint8_t family) noexcept -> std::size_t { return family == 4 ? 4 : family == 6 ? 16 : 0; }
        inline auto valid(TunAddress const &address, bool route) noexcept -> bool {
            auto size = ip_bytes(address.family);
            if (!size || address.prefix > size * 8 || (route && !address.prefix)) return false;
            if (address.family == 4 && std::ranges::any_of(std::span(address.bytes).subspan(4), [](auto byte) { return byte != 0; })) return false;
            if (route) {
                auto complete = address.prefix / 8, remainder = address.prefix % 8;
                if (remainder && (address.bytes[complete] & ((1u << (8 - remainder)) - 1))) return false;
                for (std::size_t i = complete + (remainder != 0); i < size; ++i)
                    if (address.bytes[i]) return false;
            } else if (address.family == 4) {
                if (!address.bytes[0] || address.bytes[0] == 127 || address.bytes[0] >= 224 || (address.bytes[0] == 169 && address.bytes[1] == 254)) return false;
            } else {
                bool zero = std::ranges::all_of(address.bytes, [](auto byte) { return !byte; });
                bool loopback = std::ranges::all_of(std::span(address.bytes).first(15), [](auto byte) { return !byte; }) && address.bytes[15] == 1;
                bool mapped = std::ranges::all_of(std::span(address.bytes).first(10), [](auto byte) { return !byte; }) && address.bytes[10] == 255 && address.bytes[11] == 255;
                if (zero || loopback || mapped || address.bytes[0] == 255 || (address.bytes[0] == 254 && (address.bytes[1] & 192) == 128)) return false;
            }
            return true;
        }
        inline auto contains(TunAddress const &network, TunAddress const &candidate) noexcept -> bool {
            if (network.family != candidate.family || network.prefix > candidate.prefix) return false;
            auto complete = network.prefix / 8, remainder = network.prefix % 8;
            if (!std::ranges::equal(std::span(network.bytes).first(complete), std::span(candidate.bytes).first(complete))) return false;
            return !remainder || ((network.bytes[complete] ^ candidate.bytes[complete]) & static_cast<std::uint8_t>(255u << (8 - remainder))) == 0;
        }
        inline auto validate(TunNetworkOptions const &options, bool allow_empty = false) noexcept -> bool {
            if (options.mtu < 68 || options.mtu > 65535 || (!allow_empty && !options.address_count) || options.address_count > options.addresses.size() ||
                options.route_count > options.routes.size())
                return false;
            bool ipv6 = false;
            for (std::size_t i = 0; i < options.address_count; ++i) {
                auto const &address = options.addresses[i];
                if (!valid(address, false)) return false;
                ipv6 |= address.family == 6;
                for (std::size_t j = 0; j < i; ++j)
                    if (options.addresses[j].family == address.family && options.addresses[j].bytes == address.bytes) return false;
            }
            for (std::size_t i = 0; i < options.route_count; ++i) {
                auto const &route = options.routes[i];
                if (!valid(route, true)) return false;
                ipv6 |= route.family == 6;
                for (std::size_t j = 0; j < i; ++j)
                    if (options.routes[j] == route) return false;
                if (!std::ranges::any_of(std::span(options.addresses).first(options.address_count), [&](auto const &local) { return local.family == route.family; })) return false;
            }
            return !ipv6 || options.mtu >= 1280;
        }
    } // namespace tun_network_detail
} // namespace packet
