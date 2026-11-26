export module shadowtls.v3;
import std;
import crypto;

export namespace shadowtls {
    inline constexpr std::uint8_t tls_record_change_cipher_spec = 20;
    inline constexpr std::uint8_t tls_record_alert = 21;
    inline constexpr std::uint8_t tls_record_handshake = 22;
    inline constexpr std::uint8_t tls_record_application_data = 23;
    inline constexpr std::uint8_t tls_handshake_client_hello = 1;
    inline constexpr std::uint8_t tls_handshake_server_hello = 2;

    inline constexpr std::size_t tls_header_size = 5;
    inline constexpr std::size_t hmac_tag_size = 4;
    inline constexpr std::size_t tls_hmac_header_size = tls_header_size + hmac_tag_size;
    inline constexpr std::size_t tls_random_size = 32;
    inline constexpr std::size_t tls_session_id_size = 32;
    inline constexpr std::size_t max_plaintext_chunk = 16384;
    inline constexpr std::size_t max_record_payload = 18432;

    enum class RecordStatus { incomplete, complete, malformed, too_large };
    struct RecordStep {
        RecordStatus status = RecordStatus::incomplete;
        std::size_t consumed = 0;
        std::span<std::uint8_t const> record{};
    };

    // Incremental single-TLS-record framer over a TCP byte stream.
    class TlsRecordReader {
        std::array<std::uint8_t, tls_header_size> header_{};
        std::size_t header_bytes_ = 0;
        std::size_t payload_size_ = 0;
        std::vector<std::uint8_t> buffer_;
        bool failed_ = false;
    public:
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input) -> RecordStep;
        auto consume() noexcept -> void;
        [[nodiscard]] auto pending() const noexcept -> bool;
    };

    // Stamp a ShadowTLS v3 ClientHello handshake body (starting at handshake byte 0)
    // with 28 random bytes followed by 4-byte HMAC-SHA1(password, body_with_zero_tag).
    [[nodiscard]] auto stamp_client_hello_session_id(
        std::string_view password,
        std::span<std::uint8_t> handshake_body,
        std::span<std::uint8_t const, tls_session_id_size - hmac_tag_size> random28) -> bool;

    // Verify a complete TLS ClientHello record against candidate user passwords.
    [[nodiscard]] auto verify_client_hello(
        std::span<std::uint8_t const> record,
        std::span<std::string_view const> passwords) -> std::optional<std::size_t>;

    // Extract lowercased TLS SNI hostname from a complete ClientHello record.
    [[nodiscard]] auto extract_client_hello_sni(
        std::span<std::uint8_t const> record) -> std::optional<std::string>;

    // Strict SSRF-hardened DNS hostname validator for wildcard-sni dynamic dialing.
    [[nodiscard]] auto valid_wildcard_sni_host(std::string_view sni) noexcept -> bool;

    // IP-level SSRF filters for wildcard-sni resolved endpoints (blocks loopback, RFC1918,
    // CGNAT, link-local/IMDS, ULA, site-local fec0::/10, multicast, and IPv4-mapped / NAT64 64:ff9b::/96 private IPs).
    [[nodiscard]] inline auto is_blocked_wildcard_ipv4(std::array<std::uint8_t, 4> const& b) noexcept -> bool {
        return b[0] == 0 || b[0] == 10 || b[0] == 127 ||
            (b[0] == 100 && (b[1] & 0xc0u) == 64) ||
            (b[0] == 169 && b[1] == 254) ||
            (b[0] == 172 && (b[1] & 0xf0u) == 16) ||
            (b[0] == 192 && b[1] == 168) ||
            (b[0] == 192 && b[1] == 0 && b[2] == 0) ||
            b[0] >= 224;
    }

    [[nodiscard]] inline auto is_blocked_wildcard_ipv6(std::array<std::uint8_t, 16> const& b) noexcept -> bool {
        bool all_zero = true, loopback = true, v4_mapped = true, nat64_wk_zero = true;
        for (std::size_t i = 0; i < 16; ++i) {
            if (b[i]) all_zero = false;
            if (i < 15 && b[i]) loopback = false;
            if (i < 10 && b[i]) v4_mapped = false;
            if (i >= 4 && i < 12 && b[i]) nat64_wk_zero = false;
        }
        if (all_zero || (loopback && b[15] == 1) || b[0] == 0xffu) return true;
        if (b[0] == 0xfeu && ((b[1] & 0xc0u) == 0x80u || (b[1] & 0xc0u) == 0xc0u)) return true; // fe80::/10 & fec0::/10
        if ((b[0] & 0xfeu) == 0xfcu) return true;                                                // fc00::/7 ULA
        if (v4_mapped && b[10] == 0xffu && b[11] == 0xffu)                                       // ::ffff:0:0/96
            return is_blocked_wildcard_ipv4({b[12], b[13], b[14], b[15]});
        if (b[0] == 0x00u && b[1] == 0x64u && b[2] == 0xffu && b[3] == 0x9bu) {
            if (nat64_wk_zero) return is_blocked_wildcard_ipv4({b[12], b[13], b[14], b[15]});    // 64:ff9b::/96
            if (b[4] == 0x00u && b[5] == 0x01u) return true;                                     // 64:ff9b:1::/48 local NAT64
        }
        return false;
    }

    enum class WildcardSniMode : std::uint8_t { off, authed, all };

    [[nodiscard]] auto parse_wildcard_sni_mode(std::string_view text) noexcept -> std::optional<WildcardSniMode>;

    struct HandshakeEndpoint {
        std::string host;
        std::uint16_t port = 0;
        bool is_wildcard = false;
        auto operator==(HandshakeEndpoint const&) const -> bool = default;
    };

    struct SniHandshakeEntry {
        std::string server_name;
        std::string host;
        std::uint16_t port = 0;
    };

    // Select ShadowTLS v3 handshake backend from ClientHello SNI, explicit per-SNI map,
    // wildcard-sni policy, and authentication status.
    [[nodiscard]] auto select_handshake_target(
        std::optional<std::string_view> sni,
        bool authenticated,
        std::string_view default_host,
        std::uint16_t default_port,
        std::span<SniHandshakeEntry const> sni_map,
        WildcardSniMode wildcard_mode) -> HandshakeEndpoint;

    // Extract ServerHello.random (32 bytes) from a complete TLS Handshake record.
    [[nodiscard]] auto extract_server_random(
        std::span<std::uint8_t const> record) noexcept -> std::optional<std::array<std::uint8_t, tls_random_size>>;

    // Return true iff record is a TLS ServerHello negotiating TLS 1.3 (supported_versions == 0x0304).
    [[nodiscard]] auto is_server_hello_tls13(std::span<std::uint8_t const> record) noexcept -> bool;

    // SHA-256(password || server_random) used by ShadowTLS v3 to mask server TLS 1.3 records.
    [[nodiscard]] auto derive_mask_key(
        std::string_view password,
        std::span<std::uint8_t const, tls_random_size> server_random) -> std::expected<std::array<std::uint8_t, 32>, crypto::Error>;

    auto xor_mask(std::span<std::uint8_t> data, std::span<std::uint8_t const, 32> key) noexcept -> void;

    [[nodiscard]] auto encode_alert_record() -> std::expected<std::array<std::uint8_t, 31>, crypto::Error>;

    // Server-side helper during TLS handshake relay: XOR-masks upstream real server
    // ApplicationData records with mask_key and inserts the 4-byte HMAC-SHA1 tag.
    class ServerHandshakeMasker {
        crypto::HmacSha1Context hmac_;
        std::array<std::uint8_t, 32> mask_key_{};
        ServerHandshakeMasker(crypto::HmacSha1Context hmac, std::array<std::uint8_t, 32> mask_key) noexcept;
    public:
        ~ServerHandshakeMasker();
        ServerHandshakeMasker(ServerHandshakeMasker&&) noexcept = default;
        auto operator=(ServerHandshakeMasker&&) noexcept -> ServerHandshakeMasker& = default;
        [[nodiscard]] static auto create(
            std::string_view password,
            std::span<std::uint8_t const, tls_random_size> server_random) -> std::expected<ServerHandshakeMasker, crypto::Error>;
        [[nodiscard]] auto mask_record(std::span<std::uint8_t const> record) -> std::expected<std::vector<std::uint8_t>, crypto::Error>;
    };

    // Client-side helper during TLS handshake relay: verifies masked server
    // ApplicationData records and unmasks them back into valid TLS records.
    class ClientHandshakeUnmasker {
        crypto::HmacSha1Context hmac_;
        std::array<std::uint8_t, 32> mask_key_{};
        ClientHandshakeUnmasker(crypto::HmacSha1Context hmac, std::array<std::uint8_t, 32> mask_key) noexcept;
    public:
        ~ClientHandshakeUnmasker();
        ClientHandshakeUnmasker(ClientHandshakeUnmasker&&) noexcept = default;
        auto operator=(ClientHandshakeUnmasker&&) noexcept -> ClientHandshakeUnmasker& = default;
        [[nodiscard]] static auto create(
            std::string_view password,
            std::span<std::uint8_t const, tls_random_size> server_random) -> std::expected<ClientHandshakeUnmasker, crypto::Error>;
        [[nodiscard]] auto unmask_record(std::span<std::uint8_t const> record) -> std::expected<std::vector<std::uint8_t>, crypto::Error>;
        [[nodiscard]] auto take_hmac() && noexcept -> crypto::HmacSha1Context { return std::move(hmac_); }
    };

    enum class StreamRole : std::uint8_t { client, server };

    // Chained HMAC-SHA1 ApplicationData tunnel framing shared by client & server after cutover.
    // Every encoded record carries [0x17, 3, 3, u16(4 + chunk.size()), hmac4, chunk] and folds
    // hmac4 back into the running HMAC state (write="C", read="S" on client; opposite on server).
    // On receive, optional hmac_ignore absorbs leftover masked handshake ApplicationData records.
    class VerifiedStream {
        crypto::HmacSha1Context hmac_write_;
        crypto::HmacSha1Context hmac_read_;
        std::optional<crypto::HmacSha1Context> hmac_ignore_;
        std::optional<crypto::HmacSha1Context> read_seed_;
        VerifiedStream(crypto::HmacSha1Context write, crypto::HmacSha1Context read,
                       std::optional<crypto::HmacSha1Context> ignore,
                       std::optional<crypto::HmacSha1Context> read_seed) noexcept;
    public:
        enum class DecodeStatus { payload, ignored_handshake, alert_closed, auth_failed, malformed };
        struct Decoded {
            DecodeStatus status = DecodeStatus::malformed;
            std::span<std::uint8_t const> payload{};
        };
        [[nodiscard]] static auto create(
            StreamRole role,
            std::string_view password,
            std::span<std::uint8_t const, tls_random_size> server_random,
            std::optional<crypto::HmacSha1Context> ignore_handshake_hmac = {},
            bool keep_read_seed = false) -> std::expected<VerifiedStream, crypto::Error>;
        [[nodiscard]] auto encode(std::span<std::uint8_t const> plaintext) -> std::expected<std::vector<std::uint8_t>, crypto::Error>;
        [[nodiscard]] auto decode(std::span<std::uint8_t const> record) -> Decoded;
        // Server cutover probe (matching copyByFrameUntilHMACMatches): tests whether record is the
        // first client tunnel record signed directly from the initial HMAC(password, server_random) state.
        [[nodiscard]] auto accept_cutover_record(std::span<std::uint8_t const> record) -> Decoded;
    };
}
