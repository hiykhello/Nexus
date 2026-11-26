export module tailscale.wireguard_tun;
import std;
import net.udp_socket;
import tailscale.control;
import tailscale.control_messages;
import tailscale.magic_dns;
import tailscale.map_session;
import wireguard;

export namespace tailscale::wireguard_tun {
    struct Options {
        std::string_view interface;
        net::UdpEndpoint local_endpoint;
        std::span<const net::UdpEndpoint> protected_endpoints;
        std::uint16_t mtu = 1280;
        bool accept_routes = false;
        std::uint16_t relay_region = 0;
        bool discover_paths = false;
        std::optional<net::UdpEndpoint> stun_server;
        std::optional<control::NodePublic> exit_node;
        std::string_view exit_node_name;
        bool exit_node_allow_lan_access = true;
        std::span<const control_messages::Prefix> advertise_routes;
        std::shared_ptr<magic_dns::Resolver> magic_dns;
    };

    // Thread-safe WireGuard+TUN device wrapper for Tailscale control snapshots.
    // A failed update withdraws the device, peer permissions, and MagicDNS records.
    class Device {
        struct Impl;
        std::unique_ptr<Impl> impl_;
    public:
        struct RelayPacket {
            wireguard::Key peer;
            std::vector<std::uint8_t> bytes;
            std::uint64_t revision;
        };
        Device(std::span<const std::uint8_t> key, Options options);
        ~Device();
        Device(Device const&) = delete;
        auto operator=(Device const&) -> Device& = delete;
        auto open() -> bool;
        auto local_endpoint() const -> std::optional<net::UdpEndpoint>;
        auto mapping() const noexcept -> std::optional<net::UdpEndpoint>;
        auto discovery_key() const noexcept -> std::optional<control_messages::DiscoKey>;
        auto healthy() const noexcept -> bool;
        auto install(map_session::State const&) -> bool;
        auto revoke() noexcept -> void;
        auto poll() -> bool;
        struct UserspaceNetwork {
            std::optional<std::array<std::uint8_t,4>> ipv4;
            std::optional<std::array<std::uint8_t,16>> ipv6;
            std::uint64_t revision;
        };
        auto userspace_network() const noexcept -> std::optional<UserspaceNetwork>;
        auto send_ip(std::span<const std::uint8_t>) -> bool;
        auto receive_ip() -> std::optional<std::vector<std::uint8_t>>;
        auto select_relay(std::uint16_t region) noexcept -> void;
        auto relay_ready(bool) noexcept -> void;
        auto set_relay_wake(void(*)(void*) noexcept, void*) noexcept -> void;
        [[nodiscard]] auto watch_fds() const noexcept -> std::array<int, 2>;
        [[nodiscard]] auto has_active_peers() const noexcept -> bool;
        [[nodiscard]] auto using_exit_node() const noexcept -> bool;
        [[nodiscard]] auto lan_bypass_routes() const -> std::vector<control_messages::Prefix>;
        [[nodiscard]] auto magic_dns() const noexcept -> std::shared_ptr<magic_dns::Resolver>;
        auto next_relay_packet() -> std::optional<RelayPacket>;
        auto valid_relay_packet(RelayPacket const&) const noexcept -> bool;
        auto deliver_relay(wireguard::Key const&, std::span<const std::uint8_t>) -> bool;
    };
}
