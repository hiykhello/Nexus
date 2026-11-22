export module tailscale.derp_server;
import std;
import crypto;
export import tailscale.derp;
export import tailscale.derp_messages;

export namespace tailscale::derp {
    struct OutboundFrame {
        std::uint64_t connection_id = 0;
        std::vector<std::uint8_t> frame;
    };

    struct RelayStats {
        std::size_t connected_peers = 0;
        std::uint64_t packets_forwarded = 0;
        std::uint64_t packets_dropped = 0;
        std::uint64_t pings_replied = 0;
    };

    class DerpRelayServer {
        struct PeerSession {
            std::uint64_t connection_id = 0;
            Key node{};
            bool preferred = false;
            std::uint64_t last_seen_ms = 0;
        };
        crypto::X25519Private server_key_;
        Key server_public_{};
        std::size_t max_peers_;
        std::vector<PeerSession> peers_;
        RelayStats stats_{};

        DerpRelayServer(crypto::X25519Private key, Key pub, std::size_t max_peers) noexcept
            : server_key_(std::move(key)), server_public_(pub), max_peers_(max_peers) {}
    public:
        [[nodiscard]] static auto create(crypto::X25519Private server_key, std::size_t max_peers = 1024)
            -> std::expected<DerpRelayServer, std::string>;
        [[nodiscard]] static auto generate(std::size_t max_peers = 1024)
            -> std::expected<DerpRelayServer, std::string>;

        [[nodiscard]] auto public_key() const noexcept -> Key const& { return server_public_; }
        [[nodiscard]] auto accept_connection(std::uint64_t connection_id) -> std::expected<OutboundFrame, std::string>;
        [[nodiscard]] auto handle_frame(std::uint64_t connection_id, Frame frame, std::uint64_t now_ms)
            -> std::expected<std::vector<OutboundFrame>, std::string>;
        auto disconnect(std::uint64_t connection_id) -> std::vector<OutboundFrame>;
        [[nodiscard]] auto has_peer(Key const& node) const noexcept -> bool;
        [[nodiscard]] auto stats() const noexcept -> RelayStats const& { return stats_; }
    };
}
