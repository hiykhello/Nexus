export module nexus.tls.client_auth;
export import nexus.tls.finished;
export import nexus.tls.certificate_trust;
import std;

export namespace nexus::tls {
    enum class ClientAuthError { invalid_state, malformed_certificate, untrusted_certificate, invalid_signature, invalid_finished, crypto_error };
    // Starts after the caller validates and appends EncryptedExtensions. The caller must validate
    // all preceding messages and must not deliver application data until the full handshake is complete.
    // Supports a server Certificate with empty request context and no certificate-entry extensions.
    class ClientAuth {
        enum class State { certificate, signature, finished, client_finished, complete, failed } state_ = State::certificate;
        crypto::Hash hash_;
        Transcript transcript_;
        Secret client_traffic_, server_traffic_;
        crypto::Bytes leaf_;
        std::optional<ClientFinished> finished_;
    public:
        ClientAuth(crypto::Hash hash, Transcript&& transcript, Secret&& client, Secret&& server) noexcept;
        ClientAuth(ClientAuth const&) = delete;
        auto operator=(ClientAuth const&) -> ClientAuth& = delete;
        ClientAuth(ClientAuth&& other) noexcept;
        auto operator=(ClientAuth&& other) noexcept -> ClientAuth&;
        [[nodiscard]] auto certificate(std::span<std::uint8_t const> message,
            std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind,
            std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<void,ClientAuthError>;
        [[nodiscard]] auto certificate_verify(std::span<std::uint8_t const> message,
            std::span<std::uint16_t const> offered_schemes) -> std::expected<void,ClientAuthError>;
        [[nodiscard]] auto server_finished(std::span<std::uint8_t const> message) -> std::expected<void,ClientAuthError>;
        [[nodiscard]] auto server_finished_hash() const -> std::expected<crypto::Bytes,ClientAuthError>;
        [[nodiscard]] auto client_finished() -> std::expected<crypto::Bytes,ClientAuthError>;
    };
}
