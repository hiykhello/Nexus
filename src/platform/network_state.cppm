export module platform.network_state;
import std;
import utility;

export namespace platform::network {
    using Clock = std::chrono::steady_clock;

    namespace constants {
        inline constexpr std::uint8_t af_inet = 2;
        inline constexpr std::uint8_t af_inet6 = 10;
        inline constexpr std::uint8_t rt_scope_universe = 0;
        inline constexpr std::uint32_t rt_table_main = 254;
        inline constexpr std::uint8_t rtn_unicast = 1;
        inline constexpr std::uint32_t rtnh_f_linkdown = 16;
        inline constexpr std::uint32_t iff_up = 0x1u;
        inline constexpr std::uint32_t iff_lower_up = 0x10000u;
        inline constexpr std::uint32_t ifa_f_tentative = 0x40u;
        inline constexpr std::uint32_t ifa_f_dadfailed = 0x08u;
    }

    enum class MonitorError {
        configuration,
        closed,
        protocol,
        limit,
        timeout,
        uncertain,
        sequence_exhausted,
        system,
        unsupported,
    };

    struct MonitorFailure {
        MonitorError code = MonitorError::system;
        std::error_code system{};
    };

    inline auto fail_monitor(MonitorError code, std::error_code system = {}) -> std::unexpected<MonitorFailure> {
        return std::unexpected(MonitorFailure{code, system});
    }

    struct Link {
        std::uint32_t index = 0, flags = 0;
        std::uint16_t hardware = 0;
        std::string name, kind;
        [[nodiscard]] auto up(this Link const& self) noexcept -> bool;
        [[nodiscard]] auto carrier(this Link const& self) noexcept -> bool;
    };

    struct Address {
        std::array<std::uint8_t, 16> local{};
        std::uint32_t index = 0, flags = 0;
        std::uint8_t family = 0, prefix = 0, scope = 0;
        [[nodiscard]] auto usable(this Address const& self) noexcept -> bool;
    };

    struct Route {
        std::array<std::uint8_t, 16> destination{};
        std::optional<std::array<std::uint8_t, 16>> gateway, preferred_source;
        std::uint32_t table = 0, priority = 0, index = 0, flags = 0;
        std::uint8_t family = 0, prefix = 0, source_prefix = 0, type = 0, protocol = 0, scope = 0;
        bool multiple_hops = false;
        [[nodiscard]] auto default_route(this Route const& self) noexcept -> bool {
            return self.prefix == 0 && self.source_prefix == 0;
        }
    };

    using MacAddress = std::array<std::uint8_t, 6>;
    enum class NetworkType : std::uint8_t { wifi, cellular, ethernet, other };
    [[nodiscard]] auto infer_network_type(Link const&) noexcept -> NetworkType;

    struct Neighbor {
        std::array<std::uint8_t, 16> address{};
        MacAddress mac{};
        std::uint32_t index = 0;
        std::uint8_t family = 0;
    };

    struct Snapshot {
        std::vector<Link> links;
        std::vector<Address> addresses;
        std::vector<Route> routes;
        std::vector<Neighbor> neighbors;
        std::array<std::optional<MacAddress>, 2> gateway_macs;
        std::optional<NetworkType> default_network_type{};
        std::optional<bool> network_is_expensive{};
        std::optional<bool> network_is_constrained{};
        std::optional<std::string> wifi_ssid{};
        std::optional<MacAddress> wifi_bssid{};
        std::uint32_t default_interface_index = 0;
        std::uint64_t generation = 0;
        Clock::time_point observed;
        [[nodiscard]] auto neighbor_mac(this Snapshot const&, std::span<std::uint8_t const> address,
            std::uint32_t index = 0) noexcept -> std::optional<MacAddress>;
        [[nodiscard]] auto gateway_mac(this Snapshot const& self, bool ipv6) noexcept -> std::optional<MacAddress> {
            return self.gateway_macs[ipv6];
        }
        [[nodiscard]] auto find_link(this Snapshot const& self, std::uint32_t index) noexcept -> Link const*;
        [[nodiscard]] auto default_interface_addresses(this Snapshot const& self)
            -> std::vector<std::pair<std::array<std::uint8_t, 16>, std::uint8_t>>;
    };

    // Control-thread owner of one network state observer. Consumers retain an
    // immutable snapshot. A detected change or overrun invalidates the live
    // view until a complete, consistent readback succeeds.
    class Monitor {
        struct Impl;
        std::unique_ptr<Impl> impl_;
        utility::atomic_shared_ptr<Snapshot const> live_;
        std::uint64_t generation_ = 0;
        bool include_neighbors_ = false;

        auto invalidate() noexcept -> void { live_.store({}, std::memory_order_release); }
    public:
        explicit Monitor(bool include_neighbors = false);
        ~Monitor();
        Monitor(Monitor const&) = delete;
        auto operator=(Monitor const&) -> Monitor& = delete;

        [[nodiscard]] auto started() const noexcept -> bool;
        auto enable_neighbors() noexcept -> void;
        [[nodiscard]] auto start(Clock::time_point deadline) -> std::expected<void, MonitorFailure>;
        [[nodiscard]] auto poll(Clock::time_point deadline) -> std::expected<bool, MonitorFailure>;
        [[nodiscard]] auto refresh(Clock::time_point deadline) -> std::expected<void, MonitorFailure>;
        [[nodiscard]] auto get() const noexcept -> std::shared_ptr<Snapshot const> {
            return live_.load(std::memory_order_acquire);
        }
        auto stop() noexcept -> void;
    };
}
