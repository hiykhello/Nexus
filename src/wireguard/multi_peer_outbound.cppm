export module wireguard.multi_peer_outbound;
import std;
import crypto;
import net.udp_socket;
import wireguard;
import wireguard.crypto;
import wireguard.endpoint;
import wireguard.identity;
import wireguard.noise;
import wireguard.port_types;
import wireguard.registry;
import wireguard.routing;

export namespace wireguard {
    enum class PeerActivationState : std::uint8_t {
        asleep,
        waking,
        active,
    };

    enum class MultiPeerError {
        configuration,
        closed,
        full,
        duplicate_peer,
        peer_not_found,
        invalid_prefix,
        no_route,
        queue_full,
        clock,
        entropy,
        protocol,
    };

    struct OutboundPeerSpec {
        Key peer_public{};
        std::optional<SecretKey> psk;
        EndpointAddress endpoint{};
        std::vector<AllowedPrefix> allowed_ips;
        std::size_t mtu = 1420;
        std::chrono::seconds persistent_keepalive{0};
        ReservedProfile reserved{};
        bool on_demand = false;
        std::chrono::seconds idle_timeout{120};
    };

    struct OutboundDatagram {
        PeerHandle peer{};
        EndpointAddress destination{};
        std::vector<std::uint8_t> bytes;
        OutboundKind kind = OutboundKind::data;
    };

    struct InboundPacket {
        PeerHandle peer{};
        std::vector<std::uint8_t> ip_packet;
    };

    struct MultiPeerStats {
        std::size_t peer_count = 0;
        std::size_t active_peers = 0;
        std::size_t waking_peers = 0;
        std::size_t asleep_peers = 0;
        std::uint64_t wakes = 0;
        std::uint64_t sleeps = 0;
        std::uint64_t tx_datagrams = 0;
        std::uint64_t rx_packets = 0;
        std::uint64_t route_misses = 0;
        std::uint64_t rpf_drops = 0;
    };

    // Multi-peer WireGuard outbound router with longest-prefix AllowedIPs dispatch,
    // reverse-path filtering, per-peer reserved-byte profiles (e.g. WARP), and
    // on-demand lazy handshake activation + automatic idle-sleep key cleansing.
    class MultiPeerOutbound {
    public:
        static constexpr std::size_t peer_capacity = 64;
        static constexpr std::size_t prefix_capacity = 1024;
        static constexpr std::size_t max_rx_queue = 512;

    private:
        struct Slot {
            bool occupied = false;
            PeerHandle handle{};
            PeerHandle internal_handle{};
            OutboundPeerSpec spec;
            std::optional<Endpoint> endpoint;
            Timestamp saved_timestamp{};
            PeerActivationState state = PeerActivationState::active;
            Clock::time_point last_activity{};
            std::optional<EndpointDatagram> pending_tx;
        };

        SecretKey private_bytes_;
        std::optional<crypto::X25519Private> identity_;
        std::expected<IdentityIngress, identity::Failure> ingress_;
        PeerRegistry<peer_capacity> registry_;
        routing::RouteTable<peer_capacity, prefix_capacity> routes_;
        PeerKeys<peer_capacity> keys_;
        std::array<Slot, peer_capacity> slots_{};
        std::array<std::optional<std::uint16_t>, peer_capacity> internal_to_slot_{};
        std::uint64_t next_public_gen_ = 1;
        std::deque<InboundPacket> rx_queue_;
        std::optional<Clock::time_point> observed_;
        std::size_t next_poll_slot_ = 0;
        bool closed_ = false;
        MultiPeerStats stats_{};

        auto find_by_public(PeerHandle handle) noexcept -> Slot*;
        auto find_by_public(PeerHandle handle) const noexcept -> Slot const*;
        auto find_by_internal(PeerHandle internal) noexcept -> Slot*;
        auto find_by_internal(PeerHandle internal) const noexcept -> Slot const*;
        auto bind_internal_handle(Slot& slot) -> std::expected<void, MultiPeerError>;
        auto unbind_internal_handle(Slot& slot) noexcept -> void;

        auto observe(Clock::time_point now) noexcept -> std::expected<void, MultiPeerError>;
        auto create_endpoint_for(Slot& slot) -> std::expected<void, MultiPeerError>;
        auto sleep_slot(Slot& slot) noexcept -> void;
        auto wake_slot(Slot& slot, Clock::time_point now) -> std::expected<void, MultiPeerError>;
        auto prepare_handshake(Slot& slot, HandshakeRequest req, Clock::time_point now,
                               std::chrono::system_clock::time_point wall)
            -> std::expected<void, MultiPeerError>;
        auto sync_registry(Slot& slot) noexcept -> void;

        explicit MultiPeerOutbound(SecretKey private_bytes, crypto::X25519Private identity) noexcept;

    public:
        ~MultiPeerOutbound();
        MultiPeerOutbound(MultiPeerOutbound const&) = delete;
        auto operator=(MultiPeerOutbound const&) -> MultiPeerOutbound& = delete;
        MultiPeerOutbound(MultiPeerOutbound&&) = delete;
        auto operator=(MultiPeerOutbound&&) -> MultiPeerOutbound& = delete;

        [[nodiscard]] static auto create(std::span<std::uint8_t const> local_private_key)
            -> std::expected<std::unique_ptr<MultiPeerOutbound>, MultiPeerError>;

        [[nodiscard]] auto add_peer(OutboundPeerSpec spec, Clock::time_point now)
            -> std::expected<PeerHandle, MultiPeerError>;
        [[nodiscard]] auto remove_peer(PeerHandle handle) noexcept
            -> std::expected<void, MultiPeerError>;
        [[nodiscard]] auto update_peer_endpoint(PeerHandle handle, EndpointAddress endpoint) noexcept
            -> std::expected<void, MultiPeerError>;

        // Route an inner IPv4/IPv6 packet by longest AllowedIPs prefix match.
        // If the matched peer is on-demand and asleep, transparently wakes it,
        // queues the packet, and schedules handshake initiation.
        [[nodiscard]] auto enqueue_ip(std::span<std::uint8_t const> ip_packet, Clock::time_point now)
            -> std::expected<PeerHandle, MultiPeerError>;

        // Feed an outer UDP datagram from any peer sharing this outbound port.
        // Validates authentication, updates peer state, and enforces strict RPF.
        [[nodiscard]] auto receive_udp(std::span<std::uint8_t const> wire, EndpointAddress source,
                                       Clock::time_point now)
            -> std::expected<bool, MultiPeerError>;

        // Advance timers, enforce on-demand idle-sleep transitions, and emit due
        // outer UDP datagrams (handshakes, encrypted transport, keepalives).
        [[nodiscard]] auto poll_tx(Clock::time_point now, std::chrono::system_clock::time_point wall,
                                   std::size_t max_datagrams = 64)
            -> std::expected<std::vector<OutboundDatagram>, MultiPeerError>;

        [[nodiscard]] auto take_rx() noexcept -> std::optional<InboundPacket>;
        [[nodiscard]] auto peer_state(PeerHandle handle) const noexcept
            -> std::optional<PeerActivationState>;
        [[nodiscard]] auto lookup_destination(std::span<std::uint8_t const> ip_packet) const noexcept
            -> std::optional<PeerHandle>;
        [[nodiscard]] auto stats() const noexcept -> MultiPeerStats;
        auto close() noexcept -> void;
    };
}
