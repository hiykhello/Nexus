export module packet.bridge;
import std;
import packet;

export namespace packet::bridge {
    struct BridgeConfig {
        std::string tun_interface{"nexus-tun0"};
        std::string physical_interface{"eth0"};
        std::uint16_t mtu = 1500;
        bool allow_ipv4 = true;
        bool allow_ipv6 = true;
        bool drop_link_local = true;
        std::vector<std::array<std::uint8_t, 6>> allowed_source_macs{};
    };

    enum class Direction { tun_to_phys, phys_to_tun };

    enum class ForwardError {
        truncated,
        invalid_version,
        protocol_disabled,
        ttl_expired,
        mtu_exceeded,
        link_local_blocked,
        loop_detected,
        filtered,
    };

    struct BridgeStats {
        std::uint64_t forwarded_v4 = 0;
        std::uint64_t forwarded_v6 = 0;
        std::uint64_t dropped_ttl = 0;
        std::uint64_t dropped_mtu = 0;
        std::uint64_t dropped_loop = 0;
        std::uint64_t dropped_filtered = 0;
    };

    class Layer3Bridge {
        BridgeConfig config_{};
        BridgeStats stats_{};

    public:
        explicit Layer3Bridge(BridgeConfig cfg) : config_(std::move(cfg)) {}

        [[nodiscard]] auto forward(Direction dir, std::string_view ingress_if,
                                   std::span<std::uint8_t const> packet,
                                   std::optional<std::array<std::uint8_t, 6>> src_mac = std::nullopt)
            -> std::expected<packet::Bytes, ForwardError>;

        [[nodiscard]] auto stats() const noexcept -> BridgeStats const& { return stats_; }
        [[nodiscard]] auto config() const noexcept -> BridgeConfig const& { return config_; }
    };
}
