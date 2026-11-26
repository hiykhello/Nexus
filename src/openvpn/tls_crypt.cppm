export module openvpn.tls_crypt;
import std;
import crypto;
import tls.server_credential;
export import openvpn.types;

export namespace openvpn {
    // 64-bit sliding anti-replay window for OpenVPN tls-auth / tls-crypt control packets.
    class ControlReplayWindow {
        std::uint32_t max_time_ = 0;
        std::uint32_t max_id_ = 0;
        std::uint64_t bitmap_ = 0;
        bool initialized_ = false;
    public:
        [[nodiscard]] auto check_and_record(std::uint32_t packet_id, std::uint32_t timestamp) noexcept -> bool;
        auto reset() noexcept -> void { max_time_ = 0; max_id_ = 0; bitmap_ = 0; initialized_ = false; }
    };

    // OpenVPN --tls-auth (v1) static-key HMAC packet authenticator for control packets.
    // Supports HMAC-SHA256 (default) and legacy HMAC-SHA1 with key-direction 0 / 1 / bidirectional.
    class TlsAuthCodec {
        std::array<std::uint8_t, 64> tx_key_{};
        std::array<std::uint8_t, 64> rx_key_{};
        bool use_sha1_ = false;
        std::uint32_t tx_packet_id_ = 0;
        ControlReplayWindow replay_;
        bool active_ = false;
    public:
        TlsAuthCodec() = default;
        ~TlsAuthCodec();
        TlsAuthCodec(TlsAuthCodec const&) = delete;
        auto operator=(TlsAuthCodec const&) -> TlsAuthCodec& = delete;
        TlsAuthCodec(TlsAuthCodec&& other) noexcept;
        auto operator=(TlsAuthCodec&& other) noexcept -> TlsAuthCodec&;

        [[nodiscard]] auto init(std::span<std::uint8_t const, 256> static_key,
                                KeyDirection direction, bool server_role,
                                bool use_sha1 = false) noexcept -> bool;

        [[nodiscard]] auto active() const noexcept -> bool { return active_; }
        [[nodiscard]] auto tag_size() const noexcept -> std::size_t { return use_sha1_ ? 20u : 32u; }

        // Wrap a plain encoded control packet [opcode_kid:1][sid:8][rest...] with HMAC + pkt_id + timestamp.
        [[nodiscard]] auto wrap(std::span<std::uint8_t const> plain_control,
                                std::uint32_t timestamp) -> std::expected<std::vector<std::uint8_t>, std::string>;

        // Verify HMAC + replay window and strip [hmac][pkt_id][timestamp], returning plain control packet.
        [[nodiscard]] auto unwrap(std::span<std::uint8_t const> wire_packet)
            -> std::expected<std::vector<std::uint8_t>, std::string>;
    };

    // OpenVPN --tls-crypt (v2) static-key AES-256-CTR + HMAC-SHA256 authenticated
    // control-channel encryption codec.
    class TlsCryptCodec {
        std::array<std::uint8_t, 32> tx_cipher_key_{};
        std::array<std::uint8_t, 32> tx_hmac_key_{};
        std::array<std::uint8_t, 32> rx_cipher_key_{};
        std::array<std::uint8_t, 32> rx_hmac_key_{};
        std::uint32_t tx_packet_id_ = 0;
        ControlReplayWindow replay_;
        bool active_ = false;
    public:
        TlsCryptCodec() = default;
        ~TlsCryptCodec();
        TlsCryptCodec(TlsCryptCodec const&) = delete;
        auto operator=(TlsCryptCodec const&) -> TlsCryptCodec& = delete;
        TlsCryptCodec(TlsCryptCodec&& other) noexcept;
        auto operator=(TlsCryptCodec&& other) noexcept -> TlsCryptCodec&;

        [[nodiscard]] auto init(std::span<std::uint8_t const, 256> static_key,
                                bool server_role) noexcept -> bool;

        [[nodiscard]] auto active() const noexcept -> bool { return active_; }

        // Wrap [opcode_kid:1][sid:8][body...] into [header:17][hmac_sha256:32][aes256_ctr(body)].
        [[nodiscard]] auto wrap(std::span<std::uint8_t const> plain_control,
                                std::uint32_t timestamp) -> std::expected<std::vector<std::uint8_t>, std::string>;

        // Decrypt AES-256-CTR body, verify HMAC-SHA256 in constant time, check replay window.
        [[nodiscard]] auto unwrap(std::span<std::uint8_t const> wire_packet)
            -> std::expected<std::vector<std::uint8_t>, std::string>;
    };

    // Pure BoringSSL-libcrypto mTLS client certificate & private key credential holder
    // for OpenVPN client/server mutual TLS authentication.
    class MtlsCredentials {
        tls::ServerCredential cred_;
        std::array<std::uint8_t, 32> leaf_sha256_{};
        explicit MtlsCredentials(tls::ServerCredential&& cred, std::array<std::uint8_t, 32> fp) noexcept;
    public:
        [[nodiscard]] static auto load(std::span<std::uint8_t const> cert_pem_or_der,
                                       std::span<std::uint8_t const> key_pem_or_der)
            -> std::expected<MtlsCredentials, std::string>;

        [[nodiscard]] static auto generate_ephemeral_ed25519()
            -> std::expected<MtlsCredentials, std::string>;

        [[nodiscard]] auto certificate_der() const noexcept -> std::span<std::uint8_t const>;
        [[nodiscard]] auto chain_der() const noexcept -> std::span<crypto::Bytes const>;
        [[nodiscard]] auto sha256_fingerprint() const noexcept -> std::span<std::uint8_t const, 32> { return leaf_sha256_; }
        [[nodiscard]] auto signature_schemes() const noexcept -> std::span<std::uint16_t const>;
        [[nodiscard]] auto sign_certificate_verify(std::uint16_t scheme, crypto::Hash hash,
                                                   std::span<std::uint8_t const> transcript_hash) const
            -> std::expected<crypto::Bytes, std::string>;
        [[nodiscard]] auto credential() const noexcept -> tls::ServerCredential const& { return cred_; }
    };

    // Verify a peer's DER leaf + optional intermediate chain against one or more PEM/DER CA anchors
    // using BoringSSL libcrypto X509_STORE.
    [[nodiscard]] auto verify_mtls_peer_chain(std::span<std::uint8_t const> leaf_der,
                                              std::span<crypto::Bytes const> chain_der,
                                              std::span<std::uint8_t const> ca_pem_or_der,
                                              std::int64_t unix_time_s)
        -> std::expected<void, std::string>;
}
