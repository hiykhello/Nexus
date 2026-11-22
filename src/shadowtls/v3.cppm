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
