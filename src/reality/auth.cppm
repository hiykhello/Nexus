export module reality.auth;
export import crypto;
import std;
export namespace reality {
    enum class AuthError { invalid_hello, cryptographic_failure, authentication_failed, invalid_certificate, invalid_state };
    struct Identity { std::array<std::uint8_t,3> version{}; std::uint32_t timestamp=0; std::array<std::uint8_t,8> short_id{}; };
    // Move-only authentication key, erased on destruction and on move. The view
    // remains valid only while this object is alive and unmoved.
    class AuthKey {
        std::array<std::uint8_t,32> bytes_{};
        bool valid_=false;
        explicit AuthKey(std::span<std::uint8_t const,32> bytes) noexcept;
    public:
        ~AuthKey();
        AuthKey(AuthKey const&)=delete;
        auto operator=(AuthKey const&) -> AuthKey& = delete;
        AuthKey(AuthKey&&) noexcept;
        auto operator=(AuthKey&&) noexcept -> AuthKey&;
        [[nodiscard]] static auto derive(crypto::X25519Private const& own, std::span<std::uint8_t const> peer,
            std::span<std::uint8_t const> random) -> std::expected<AuthKey,AuthError>;
        [[nodiscard]] auto view() const noexcept -> std::span<std::uint8_t const>;
        // Checks the Reality HMAC on a DER leaf certificate only. The caller
        // must still verify TLS CertificateVerify, Finished and handshake state.
        [[nodiscard]] auto verify_certificate(std::span<std::uint8_t const> der) const -> std::expected<void,AuthError>;
    };
    struct SealedHello { crypto::Bytes wire; AuthKey key; };
    struct OpenedHello { Identity identity; AuthKey key; };
    // Input includes the handshake header, not a TLS record. Caller supplies the
    // private key matching the transmitted key share. On open, the caller must
    // extract client_public from the same ClientHello. This does not authenticate
    // the server certificate, SNI, timestamp or user policy, or validate TLS policy.
    // The caller must use a fresh ephemeral key and ClientHello random per attempt;
    // reusing the key and random repeats the AES-GCM key and nonce.
    [[nodiscard]] auto seal_client_hello(std::span<std::uint8_t const> hello, crypto::X25519Private const& ephemeral,
        std::span<std::uint8_t const> server_public, Identity identity) -> std::expected<SealedHello,AuthError>;
    [[nodiscard]] auto open_client_hello(std::span<std::uint8_t const> hello, crypto::X25519Private const& server_private,
        std::span<std::uint8_t const> client_public) -> std::expected<OpenedHello,AuthError>;
}
