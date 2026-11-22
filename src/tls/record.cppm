export module tls.record;
export import crypto;
import std;

export namespace tls {
    enum class RecordError { invalid_key, invalid_input, invalid_record, authentication_failed, invalid_state, crypto_error, key_usage_limit, record_overflow };
    enum class ContentType : std::uint8_t { alert = 21, handshake = 22, application_data = 23 };
    enum class RecordDirection { send, receive };
    struct PlaintextRecord { ContentType type; crypto::Bytes content; };
    struct KtlsKeyMaterial {
        crypto::Aead algorithm = crypto::Aead::aes_128_gcm;
        crypto::Bytes key;
        std::array<std::uint8_t, 12> iv{};
        std::uint64_t sequence = 0;
        KtlsKeyMaterial() noexcept = default;
        KtlsKeyMaterial(KtlsKeyMaterial const&) = delete;
        auto operator=(KtlsKeyMaterial const&) -> KtlsKeyMaterial& = delete;
        KtlsKeyMaterial(KtlsKeyMaterial&& other) noexcept;
        auto operator=(KtlsKeyMaterial&& other) noexcept -> KtlsKeyMaterial&;
        ~KtlsKeyMaterial();
    };
    // One instance owns one direction and one traffic key epoch. Never reuse a key/IV in another sender.
    class RecordLayer {
        crypto::Aead algorithm_;
        crypto::Bytes key_;
        std::array<std::uint8_t,12> iv_{};
        std::uint64_t sequence_ = 0;
        std::uint64_t send_limit_;
        RecordDirection direction_;
        bool active_ = true;
        bool legacy_ = false;
        RecordLayer(crypto::Aead algorithm, crypto::Bytes key, std::array<std::uint8_t,12> iv, RecordDirection direction, std::uint64_t send_limit);
        auto nonce() const -> std::array<std::uint8_t,12>;
        auto advance() noexcept -> void;
        auto seal_tls12(ContentType,std::span<std::uint8_t const>) -> std::expected<crypto::Bytes,RecordError>;
        auto open_tls12(std::span<std::uint8_t const>) -> std::expected<PlaintextRecord,RecordError>;
    public:
        ~RecordLayer();
        RecordLayer(RecordLayer const&) = delete;
        auto operator=(RecordLayer const&) -> RecordLayer& = delete;
        RecordLayer(RecordLayer&&) noexcept;
        auto operator=(RecordLayer&&) noexcept -> RecordLayer&;
        // The send limit can be lowered, but cannot exceed the conservative 2^24-record cap.
        // Receive keys are not subject to this local send policy.
        [[nodiscard]] static auto create(RecordDirection direction, crypto::Aead algorithm,
            std::span<std::uint8_t const> key, std::span<std::uint8_t const> iv, std::uint64_t send_limit = 1u << 24) -> std::expected<RecordLayer,RecordError>;
        [[nodiscard]] static auto create_tls12_gcm(RecordDirection direction,crypto::Aead algorithm,
            std::span<std::uint8_t const> key,std::span<std::uint8_t const,4> iv) -> std::expected<RecordLayer,RecordError>;
        [[nodiscard]] static auto create_tls12(RecordDirection direction,crypto::Aead algorithm,
            std::span<std::uint8_t const> key,std::span<std::uint8_t const> iv) -> std::expected<RecordLayer,RecordError>;
        [[nodiscard]] auto tls12() const noexcept -> bool { return legacy_; }
        [[nodiscard]] auto algorithm() const noexcept -> crypto::Aead { return algorithm_; }
        [[nodiscard]] auto tls12_overhead() const noexcept -> std::size_t {
            return algorithm_==crypto::Aead::chacha20_poly1305 ? 21 : 29;
        }
        [[nodiscard]] auto usable(RecordDirection direction) const noexcept -> bool { return active_ && direction_==direction; }
        [[nodiscard]] auto send_limit() const noexcept -> std::uint64_t { return send_limit_; }
        [[nodiscard]] auto send_remaining() const noexcept -> std::uint64_t { return active_ && direction_==RecordDirection::send ? send_limit_-sequence_ : 0; }
        [[nodiscard]] auto seal(ContentType type, std::span<std::uint8_t const> content, std::size_t padding = 0)
            -> std::expected<crypto::Bytes,RecordError>;
        // Expects exactly one complete TLSCiphertext. Any malformed or unauthentic record terminates this state.
        [[nodiscard]] auto open(std::span<std::uint8_t const> record) -> std::expected<PlaintextRecord,RecordError>;
        // Atomically extracts TLS 1.3 key/IV/sequence for kernel kTLS handoff and
        // deactivates + cleanses this user-space layer so nonces can never be reused.
        [[nodiscard]] auto export_ktls_material() -> std::optional<KtlsKeyMaterial>;
    };
}
