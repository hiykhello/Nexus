export module openconnect.dtls;
import std;
import crypto;
export import openconnect.types;
export import openconnect.cstp;

export namespace openconnect {
    // 64-bit sliding anti-replay window for 48-bit DTLS 1.2 / 1.3 sequence numbers.
    class DtlsReplayWindow {
        std::uint64_t highest_ = 0;
        std::uint64_t bitmap_ = 0;
        bool initialized_ = false;
    public:
        [[nodiscard]] auto check_and_record(std::uint64_t seq) noexcept -> bool;
        [[nodiscard]] auto reconstruct_seq16(std::uint16_t seq16) const noexcept -> std::uint64_t;
        auto reset() noexcept -> void { highest_ = 0; bitmap_ = 0; initialized_ = false; }
    };

    struct DtlsConfig {
        DtlsVersion version = DtlsVersion::dtls1_2;
        DtlsCipher cipher = DtlsCipher::aes_256_gcm;
        bool server_role = false;
        std::vector<std::uint8_t> session_id;
        std::array<std::uint8_t, 48> master_secret{};
        std::uint16_t mtu = 1400;
        ~DtlsConfig() { crypto::cleanse(master_secret); }
    };

    enum class DtlsState : std::uint8_t {
        idle,
        client_hello_sent,
        server_hello_sent,
        established,
        failed,
    };

    enum class FallbackReason : std::uint8_t {
        none,
        handshake_timeout,
        dpd_timeout,
        transport_error,
        unsupported_peer,
    };

    enum class FallbackAction : std::uint8_t {
        none,
        send_dpd_req,
        fallback_to_cstp,
    };

    // Pure BoringSSL-libcrypto DTLS 1.2 (RFC 6347) and DTLS 1.3 (RFC 9147) UDP
    // datagram tunnel engine with AnyConnect 1-byte payload framing.
    class DtlsTransport {
        DtlsVersion version_ = DtlsVersion::dtls1_2;
        DtlsCipher cipher_ = DtlsCipher::aes_256_gcm;
        bool server_role_ = false;
        DtlsState state_ = DtlsState::idle;
        std::uint16_t mtu_ = 1400;

        std::vector<std::uint8_t> session_id_;
        std::array<std::uint8_t, 48> master_secret_{};
        std::array<std::uint8_t, 32> client_random_{};
        std::array<std::uint8_t, 32> server_random_{};
        std::vector<std::uint8_t> handshake_transcript_;

        std::vector<std::uint8_t> tx_key_, rx_key_;
        std::vector<std::uint8_t> tx_iv_, rx_iv_;
        std::uint16_t tx_epoch_ = 0, rx_epoch_ = 0;
        std::uint64_t tx_seq_ = 0;
        DtlsReplayWindow rx_replay_;
        bool keys_ready_ = false;

        [[nodiscard]] auto derive_traffic_keys() -> std::expected<void, std::string>;
        [[nodiscard]] auto compute_verify_data(bool for_server) const
            -> std::expected<std::vector<std::uint8_t>, std::string>;
        [[nodiscard]] auto seal_record(std::uint8_t content_type, std::span<std::uint8_t const> plaintext)
            -> std::expected<std::vector<std::uint8_t>, std::string>;
        [[nodiscard]] auto open_record(std::span<std::uint8_t const> datagram)
            -> std::expected<std::pair<std::uint8_t, std::vector<std::uint8_t>>, std::string>;

    public:
        DtlsTransport() = default;
        ~DtlsTransport();
        DtlsTransport(DtlsTransport const&) = delete;
        auto operator=(DtlsTransport const&) -> DtlsTransport& = delete;

        [[nodiscard]] auto init(DtlsConfig const& config) -> std::expected<void, std::string>;

        // Client: generate initial DTLS ClientHello datagram carrying X-DTLS-Session-ID.
        [[nodiscard]] auto build_client_hello() -> std::expected<std::vector<std::uint8_t>, std::string>;

        // Client or Server: process an incoming handshake UDP datagram and return
        // zero or more outgoing handshake datagrams (ServerHello+CCS+Finished or Client CCS+Finished).
        [[nodiscard]] auto on_handshake_datagram(std::span<std::uint8_t const> datagram)
            -> std::expected<std::vector<std::vector<std::uint8_t>>, std::string>;

        // Seal an AnyConnect DTLS tunnel frame (1-byte CstpType prefix + payload).
        [[nodiscard]] auto seal_tunnel_frame(CstpType type, std::span<std::uint8_t const> payload)
            -> std::expected<std::vector<std::uint8_t>, std::string>;

        // Open and authenticate an incoming DTLS application datagram into a CstpFrame.
        [[nodiscard]] auto open_tunnel_frame(std::span<std::uint8_t const> datagram)
            -> std::expected<CstpFrame, std::string>;

        auto reset() noexcept -> void;

        [[nodiscard]] auto state() const noexcept -> DtlsState { return state_; }
        [[nodiscard]] auto established() const noexcept -> bool { return state_ == DtlsState::established; }
        [[nodiscard]] auto version() const noexcept -> DtlsVersion { return version_; }
        [[nodiscard]] auto cipher() const noexcept -> DtlsCipher { return cipher_; }
        [[nodiscard]] auto mtu() const noexcept -> std::uint16_t { return mtu_; }
    };

    // Automatic DTLS-to-CSTP fallback controller tracking handshake deadlines,
    // missed DPD probes, and consecutive UDP/AEAD errors.
    class DtlsFallbackController {
        std::uint64_t handshake_timeout_ms_ = 5000;
        std::uint64_t dpd_interval_ms_ = 30000;
        std::uint32_t max_missed_dpd_ = 3;
        std::uint32_t max_consecutive_errors_ = 5;

        std::uint64_t handshake_start_ms_ = 0;
        std::uint64_t last_rx_ms_ = 0;
        std::uint64_t last_dpd_tx_ms_ = 0;
        std::uint32_t missed_dpd_ = 0;
        std::uint32_t consecutive_errors_ = 0;
        bool active_ = false;
        bool established_ = false;
        FallbackReason reason_ = FallbackReason::none;

    public:
        explicit DtlsFallbackController(std::uint64_t handshake_timeout_ms = 5000,
                                        std::uint64_t dpd_interval_ms = 30000,
                                        std::uint32_t max_missed_dpd = 3,
                                        std::uint32_t max_consecutive_errors = 5) noexcept;

        auto begin_handshake(std::uint64_t now_ms) noexcept -> void;
        auto on_established(std::uint64_t now_ms) noexcept -> void;
        auto on_rx_valid(std::uint64_t now_ms) noexcept -> void;
        auto on_dpd_response(std::uint64_t now_ms) noexcept -> void;
        auto on_transport_error(Session& session) noexcept -> FallbackAction;
        auto on_unsupported(Session& session) noexcept -> FallbackAction;
        auto poll(std::uint64_t now_ms, Session& session) noexcept -> FallbackAction;

        [[nodiscard]] auto active() const noexcept -> bool { return active_; }
        [[nodiscard]] auto reason() const noexcept -> FallbackReason { return reason_; }
        [[nodiscard]] auto missed_dpd() const noexcept -> std::uint32_t { return missed_dpd_; }
    };

    [[nodiscard]] auto parse_dtls_cipher_name(std::string_view name) noexcept -> DtlsCipher;
}

namespace openconnect::detail {
    auto append_supported_versions_ch(std::vector<std::uint8_t>& body, DtlsVersion version) -> void;
    auto append_supported_versions_sh(std::vector<std::uint8_t>& body, DtlsVersion version) -> void;
    [[nodiscard]] auto validate_client_hello_version(std::span<std::uint8_t const> body,
                                                     std::size_t after_session_id,
                                                     DtlsVersion expected) noexcept
        -> std::expected<void, std::string>;
    [[nodiscard]] auto validate_server_hello_version(std::span<std::uint8_t const> body,
                                                     std::size_t after_session_id,
                                                     DtlsVersion expected) noexcept
        -> std::expected<void, std::string>;
}
