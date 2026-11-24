export module openvpn.session;
import std;
export import openvpn.types;
export import openvpn.wire;
import crypto;
import crypto.aead_context;

export namespace openvpn {
    enum class SessionState { disconnected, hard_reset_sent, tls_handshake, established, reconnecting };

    class DataChannel {
        Cipher cipher_{Cipher::aes_256_gcm};
        std::uint32_t peer_id_{0};
        std::uint8_t key_id_{0};
        std::array<std::uint8_t, 8> tx_iv_{};
        std::array<std::uint8_t, 8> rx_iv_{};
        crypto::AeadContext tx_aead_{};
        crypto::AeadContext rx_aead_{};
        ReplayWindow rx_replay_{};
        std::uint32_t tx_packet_id_{0};
        bool ready_{false};

    public:
        DataChannel() = default;
        ~DataChannel() { crypto::cleanse(tx_iv_); crypto::cleanse(rx_iv_); }
        DataChannel(DataChannel const&) = delete;
        auto operator=(DataChannel const&) -> DataChannel& = delete;

        [[nodiscard]] auto init(Cipher cipher, KeyMaterial const& keys,
                                std::uint32_t peer_id, std::uint8_t key_id = 0) -> std::expected<void, std::string>;
        [[nodiscard]] auto seal_data_v2(std::span<std::uint8_t const> plaintext)
            -> std::expected<std::vector<std::uint8_t>, std::string>;
        [[nodiscard]] auto open_data_v2(std::span<std::uint8_t const> frame)
            -> std::expected<std::vector<std::uint8_t>, std::string>;
        [[nodiscard]] auto ready() const noexcept -> bool { return ready_; }
    };

    class SessionStateMachine {
        Config config_{};
        SessionState state_{SessionState::disconnected};
        std::uint64_t local_session_id_{0};
        std::uint64_t remote_session_id_{0};
        std::uint32_t next_control_pid_{0};
        std::uint32_t generation_{0};
        std::vector<std::uint32_t> pending_acks_;

    public:
        explicit SessionStateMachine(Config cfg, std::uint64_t local_sid)
            : config_(std::move(cfg)), local_session_id_(local_sid) {}

        [[nodiscard]] auto begin_connect() -> std::expected<ControlPacket, std::string>;
        [[nodiscard]] auto on_control_packet(ControlPacket const& pkt) -> std::expected<void, std::string>;
        [[nodiscard]] auto make_control_message(std::vector<std::uint8_t> tls_bytes) -> std::expected<ControlPacket, std::string>;
        [[nodiscard]] auto make_ack() -> std::optional<ControlPacket>;
        auto mark_established() noexcept -> void { state_ = SessionState::established; }
        [[nodiscard]] auto trigger_reconnect(std::uint64_t new_local_sid) -> ControlPacket;

        [[nodiscard]] auto state() const noexcept -> SessionState { return state_; }
        [[nodiscard]] auto generation() const noexcept -> std::uint32_t { return generation_; }
        [[nodiscard]] auto local_session_id() const noexcept -> std::uint64_t { return local_session_id_; }
        [[nodiscard]] auto remote_session_id() const noexcept -> std::uint64_t { return remote_session_id_; }
    };
}
