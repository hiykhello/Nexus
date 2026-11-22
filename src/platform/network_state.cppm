export module platform.network_state;
import std;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.netlink_socket;
import platform.netlink_watch;

export namespace platform::network {
    using Clock=std::chrono::steady_clock;

    struct Link {
        std::uint32_t index=0,flags=0;
        std::uint16_t hardware=0;
        std::string name,kind;
        [[nodiscard]] auto up(this Link const& self) noexcept -> bool;
        [[nodiscard]] auto carrier(this Link const& self) noexcept -> bool;
    };

    struct Address {
        std::array<std::uint8_t,16> local{};
        std::uint32_t index=0,flags=0;
        std::uint8_t family=0,prefix=0,scope=0;
        [[nodiscard]] auto usable(this Address const& self) noexcept -> bool;
    };

    struct Route {
        std::array<std::uint8_t,16> destination{};
        std::optional<std::array<std::uint8_t,16>> gateway,preferred_source;
        std::uint32_t table=0,priority=0,index=0,flags=0;
        std::uint8_t family=0,prefix=0,source_prefix=0,type=0,protocol=0,scope=0;
        bool multiple_hops=false;
        [[nodiscard]] auto default_route(this Route const& self) noexcept -> bool {
            return self.prefix==0 && self.source_prefix==0;
        }
    };

    using MacAddress=std::array<std::uint8_t,6>;

    struct Neighbor {
        std::array<std::uint8_t,16> address{};
        MacAddress mac{};
        std::uint32_t index=0;
        std::uint8_t family=0;
    };

    struct Snapshot {
        std::vector<Link> links;
        std::vector<Address> addresses;
        std::vector<Route> routes;
        std::vector<Neighbor> neighbors;
        std::array<std::optional<MacAddress>,2> gateway_macs;
        std::uint64_t generation=0;
        Clock::time_point observed;
        [[nodiscard]] auto neighbor_mac(this Snapshot const&,std::span<std::uint8_t const> address,
            std::uint32_t index=0) noexcept -> std::optional<MacAddress>;
        [[nodiscard]] auto gateway_mac(this Snapshot const& self,bool ipv6) noexcept -> std::optional<MacAddress> {
            return self.gateway_macs[ipv6];
        }
        [[nodiscard]] auto find_link(this Snapshot const& self,std::uint32_t index) noexcept -> Link const*;
    };

    // Control-thread owner of one network namespace. Consumers retain an
    // immutable snapshot. A detected change or overrun invalidates the live
    // view until a complete, consistent readback succeeds.
    class Monitor {
        netlink::Socket<> query_;
        netlink::Watch watch_;
        std::atomic<std::shared_ptr<Snapshot const>> live_;
        std::uint64_t generation_=0;
        bool include_neighbors_;

        auto drain(this Monitor& self) -> std::expected<std::size_t,netlink::Failure>;
        auto invalidate(this Monitor& self) noexcept -> void {self.live_.store({},std::memory_order_release);}
    public:
        explicit Monitor(bool include_neighbors=false) noexcept : include_neighbors_(include_neighbors) {}
        [[nodiscard]] auto started(this Monitor const& self) noexcept -> bool {
            return self.watch_.native_handle()>=0;
        }
        auto enable_neighbors(this Monitor& self) noexcept -> void {
            if (!std::exchange(self.include_neighbors_,true)) self.stop();
        }
        [[nodiscard]] auto start(this Monitor& self,Clock::time_point deadline) -> std::expected<void,netlink::Failure>;
        [[nodiscard]] auto poll(this Monitor& self,Clock::time_point deadline) -> std::expected<bool,netlink::Failure>;
        [[nodiscard]] auto refresh(this Monitor& self,Clock::time_point deadline) -> std::expected<void,netlink::Failure>;
        [[nodiscard]] auto get(this Monitor const& self) noexcept -> std::shared_ptr<Snapshot const> {
            return self.live_.load(std::memory_order_acquire);
        }
        auto stop(this Monitor& self) noexcept -> void;
    };
}
