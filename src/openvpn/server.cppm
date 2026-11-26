export module openvpn.server;
import std;
import crypto;
export import openvpn.types;
export import openvpn.wire;
export import openvpn.control;
export import openvpn.session;
export import openvpn.tls_crypt;

export namespace openvpn {
    using ClientAuthCallback = std::function<bool(
        std::string_view username,
        std::string_view password,
        std::span<std::uint8_t const> client_cert_der)>;

    struct ServerOptions {
        Cipher cipher = Cipher::aes_256_gcm;
        std::uint32_t peer_id = 1;
        std::uint32_t replay_window = 64;
        std::uint16_t mtu = 1400;
        TlsAuthMode tls_auth_mode = TlsAuthMode::none;
        KeyDirection key_direction = KeyDirection::bidirectional;
        bool tls_auth_sha1 = false;
        std::string static_key_pem;
        bool require_client_cert = false;
        std::string client_ca_pem;
        std::string server_options{"V4,dev-type tun,link-mtu 1500,tun-mtu 1400,cipher AES-256-GCM"};
        PushConfig push_config;
        ClientAuthCallback auth_callback;
    };

    enum class ServerState : std::uint8_t {
        awaiting_reset,
        tls_handshake,
        awaiting_key_method2,
        awaiting_push_request,
        established,
        closed,
    };

    struct ServerStepOutput {
        std::vector<std::vector<std::uint8_t>> wire_packets;
        std::vector<std::uint8_t> tls_rx_bytes;
        std::vector<std::uint8_t> tls_tx_plaintext;
        std::vector<std::vector<std::uint8_t>> ip_packets;
        bool keepalive_received = false;
    };

    // Pure BoringSSL-crypto OpenVPN server inbound session state machine.
    // Supports tls-auth / tls-crypt control channel protection, reliable
    // ControlChannel TLS transport, optional mTLS client certificate chain
    // verification, Key Method 2 key derivation, PUSH_REPLY, and P_DATA_V2 AEAD.
    class ServerSession {
        ServerOptions options_;
        ServerState state_ = ServerState::awaiting_reset;
        std::uint64_t server_session_id_ = 0;
        std::optional<ControlChannel> control_;
        TlsAuthCodec tls_auth_;
        TlsCryptCodec tls_crypt_;
        std::optional<DataChannel> data_;
        std::vector<std::uint8_t> client_cert_der_;
        bool client_cert_verified_ = false;
        bool tls_ready_ = false;
        std::string authenticated_user_;
        std::vector<std::uint8_t> app_rx_buf_;
        std::uint32_t current_timestamp_s_ = 0;

        [[nodiscard]] auto wrap_control(std::span<std::uint8_t const> plain)
            -> std::expected<std::vector<std::uint8_t>, std::string>;
        [[nodiscard]] auto unwrap_control(std::span<std::uint8_t const> wire)
            -> std::expected<std::vector<std::uint8_t>, std::string>;
        [[nodiscard]] auto encode_and_wrap(ControlPacket const& pkt)
            -> std::expected<std::vector<std::uint8_t>, std::string>;
        [[nodiscard]] auto handle_key_method2(std::span<std::uint8_t const> payload, ServerStepOutput& out)
            -> std::expected<void, std::string>;
        [[nodiscard]] auto handle_push_request(ServerStepOutput& out)
            -> std::expected<void, std::string>;

    public:
        ServerSession() = default;
        ~ServerSession();
        ServerSession(ServerSession const&) = delete;
        auto operator=(ServerSession const&) -> ServerSession& = delete;

        [[nodiscard]] auto init(ServerOptions options, std::uint64_t server_session_id = 0)
            -> std::expected<void, std::string>;

        // Verify and bind an incoming client mTLS certificate chain once TLS handshake presents it.
        [[nodiscard]] auto verify_client_certificate(std::span<std::uint8_t const> leaf_der,
                                                     std::span<crypto::Bytes const> chain_der,
                                                     std::int64_t unix_time_s)
            -> std::expected<void, std::string>;

        // Notify the session that the outer TLS control-channel handshake completed.
        [[nodiscard]] auto on_tls_established() -> std::expected<void, std::string>;

        // Feed raw outer UDP/TCP-unframed OpenVPN wire packet (control or P_DATA_V2).
        [[nodiscard]] auto on_wire_packet(std::span<std::uint8_t const> wire,
                                          std::uint64_t now_ms,
                                          std::uint32_t unix_time_s = 0)
            -> std::expected<ServerStepOutput, std::string>;

        // Queue outgoing TLS handshake or TLS-encrypted record bytes onto the reliable control channel.
        [[nodiscard]] auto enqueue_tls_tx(std::span<std::uint8_t const> tls_bytes,
                                          std::uint64_t now_ms,
                                          std::uint32_t unix_time_s = 0)
            -> std::expected<std::vector<std::vector<std::uint8_t>>, std::string>;

        // Feed decrypted TLS control-channel application plaintext (KeyMethod2Client / PUSH_REQUEST).
        // Returns plaintext response bytes to encrypt over the TLS control channel.
        [[nodiscard]] auto on_tls_plaintext(std::span<std::uint8_t const> plaintext)
            -> std::expected<ServerStepOutput, std::string>;

        // Retransmit unacked control packets due for retransmission.
        [[nodiscard]] auto poll_retransmit(std::uint64_t now_ms, std::uint64_t rto_ms = 500,
                                           std::uint32_t unix_time_s = 0)
            -> std::expected<std::vector<std::vector<std::uint8_t>>, std::string>;

        // Seal an outbound inner IP packet as P_DATA_V2 once established.
        [[nodiscard]] auto seal_ip_packet(std::span<std::uint8_t const> ip_packet)
            -> std::expected<std::vector<std::uint8_t>, std::string>;

        // Seal an OpenVPN data-channel keepalive ping once established.
        [[nodiscard]] auto seal_keepalive()
            -> std::expected<std::vector<std::uint8_t>, std::string>;

        auto close() noexcept -> void;

        [[nodiscard]] auto state() const noexcept -> ServerState { return state_; }
        [[nodiscard]] auto established() const noexcept -> bool { return state_ == ServerState::established; }
        [[nodiscard]] auto peer_id() const noexcept -> std::uint32_t { return options_.peer_id; }
        [[nodiscard]] auto server_session_id() const noexcept -> std::uint64_t { return server_session_id_; }
        [[nodiscard]] auto authenticated_user() const noexcept -> std::string_view { return authenticated_user_; }
    };
}
