export module tls.client_auth;
export import tls.finished;
export import tls.certificate_trust;
import std;

export namespace tls {
    enum class ClientAuthError { invalid_state, malformed_certificate, untrusted_certificate, invalid_signature, invalid_finished, crypto_error };
    using CertificateVerifier = std::move_only_function<bool(std::span<std::span<std::uint8_t const> const>) const>;
    // Starts after the caller validates and appends EncryptedExtensions. The caller must validate
    // all preceding messages and must not deliver application data until the full handshake is complete.
    // Server certificates may include previously requested OCSP and SCT data.
    class ClientAuth {
        enum class State { certificate, signature, finished, client_finished, complete, failed } state_ = State::certificate;
        crypto::Hash hash_;
        Transcript transcript_;
        Secret client_traffic_, server_traffic_;
        crypto::Bytes leaf_;
        bool status_requested_=false,sct_requested_=false;
        std::optional<ClientFinished> finished_;
        auto certificate_chain(std::span<std::uint8_t const> message)
            -> std::expected<std::vector<std::span<std::uint8_t const>>,ClientAuthError>;
        auto accept_certificate(std::span<std::uint8_t const> message,std::span<std::span<std::uint8_t const> const> chain)
            -> std::expected<void,ClientAuthError>;
    public:
        ClientAuth(crypto::Hash hash, Transcript&& transcript, Secret&& client, Secret&& server,
            bool status_requested=false,bool sct_requested=false) noexcept;
        // Requires a validated selected PSK and matching handshake keys. Peer
        // possession is proved by Finished; no certificate flight is accepted.
        [[nodiscard]] static auto resumed(crypto::Hash hash,Transcript&& transcript,Secret&& client,Secret&& server) noexcept -> ClientAuth;
        ClientAuth(ClientAuth const&) = delete;
        auto operator=(ClientAuth const&) -> ClientAuth& = delete;
        ClientAuth(ClientAuth&& other) noexcept;
        auto operator=(ClientAuth&& other) noexcept -> ClientAuth&;
        [[nodiscard]] auto certificate(std::span<std::uint8_t const> message,
            std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind,
            std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<void,ClientAuthError>;
        // Authenticates the parsed chain with the supplied policy. The normal
        // CertificateVerify and Finished checks remain mandatory afterwards.
        [[nodiscard]] auto certificate(std::span<std::uint8_t const> message,
            CertificateVerifier const& verifier,std::span<std::uint8_t const> transcript_wire={})
            -> std::expected<void,ClientAuthError>;
        template<class Verifier>
        [[nodiscard]] auto certificate_with(std::span<std::uint8_t const> message,Verifier&& verifier,
            std::span<std::uint8_t const> transcript_wire={}) -> std::expected<void,ClientAuthError> {
            auto chain=certificate_chain(message);
            if (!chain) return std::unexpected(chain.error());
            auto verified=std::forward<Verifier>(verifier)(std::span<std::span<std::uint8_t const> const>(*chain));
            if constexpr (std::same_as<std::remove_cvref_t<decltype(verified)>,std::expected<void,CertificateTrustError>>) {
                if (!verified) return std::unexpected(verified.error()==CertificateTrustError::crypto_error ?
                    ClientAuthError::crypto_error : ClientAuthError::untrusted_certificate);
            } else {
                static_assert(std::same_as<std::remove_cvref_t<decltype(verified)>,bool>,"certificate policy returns bool or expected<void,CertificateTrustError>");
                if (!verified) return std::unexpected(ClientAuthError::untrusted_certificate);
            }
            return accept_certificate(transcript_wire.empty() ? message : transcript_wire,*chain);
        }
        [[nodiscard]] auto certificate_verify(std::span<std::uint8_t const> message,
            std::span<std::uint16_t const> offered_schemes) -> std::expected<void,ClientAuthError>;
        [[nodiscard]] auto server_finished(std::span<std::uint8_t const> message) -> std::expected<void,ClientAuthError>;
        [[nodiscard]] auto server_finished_hash() const -> std::expected<crypto::Bytes,ClientAuthError>;
        [[nodiscard]] auto client_finished(std::span<std::uint8_t const> preceding={}) -> std::expected<crypto::Bytes,ClientAuthError>;
        [[nodiscard]] auto completed_transcript_hash() const -> std::expected<crypto::Bytes,ClientAuthError>;
    };
}
