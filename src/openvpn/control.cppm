export module openvpn.control;
import std;
export import openvpn.wire;

export namespace openvpn {
    class ControlChannel {
        struct Unacked {
            ControlPacket pkt;
            std::uint64_t last_sent_ms = 0;
        };

        std::uint64_t local_sid_;
        std::uint64_t remote_sid_ = 0;
        bool server_role_;
        bool handshake_started_ = false;
        std::uint32_t next_tx_pid_ = 1;
        std::uint32_t expected_rx_pid_ = 1;
        std::vector<std::uint32_t> pending_acks_;
        std::deque<Unacked> unacked_;
        std::map<std::uint32_t, std::vector<std::uint8_t>> rx_reorder_;

        auto retire_acks(ControlPacket const& pkt) -> void;
    public:
        explicit ControlChannel(std::uint64_t local_sid, bool server_role = false) noexcept
            : local_sid_(local_sid), server_role_(server_role) {}

        [[nodiscard]] auto begin_client_reset(std::uint64_t now_ms) -> ControlPacket;
        [[nodiscard]] auto make_server_reset(std::uint64_t now_ms) -> ControlPacket;
        [[nodiscard]] auto on_packet(ControlPacket const& pkt, std::uint64_t now_ms)
            -> std::expected<std::vector<std::uint8_t>, std::string>;
        [[nodiscard]] auto enqueue_tls_bytes(std::span<std::uint8_t const> data, std::uint64_t now_ms)
            -> std::vector<ControlPacket>;
        [[nodiscard]] auto take_ack() -> std::optional<ControlPacket>;
        [[nodiscard]] auto retransmit_due(std::uint64_t now_ms, std::uint64_t rto_ms = 500)
            -> std::vector<ControlPacket>;

        [[nodiscard]] auto local_session_id() const noexcept -> std::uint64_t { return local_sid_; }
        [[nodiscard]] auto remote_session_id() const noexcept -> std::uint64_t { return remote_sid_; }
        [[nodiscard]] auto handshake_started() const noexcept -> bool { return handshake_started_; }
        [[nodiscard]] auto has_unacked() const noexcept -> bool { return !unacked_.empty(); }
    };

    [[nodiscard]] auto parse_static_key_v1(std::string_view pem)
        -> std::expected<std::array<std::uint8_t, 256>, std::string>;
}
