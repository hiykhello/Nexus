export module tls.transcript;
export import crypto;
import std;

export namespace tls {
    enum class TranscriptError { malformed_message, invalid_retry_state, crypto_error };
    class Transcript {
        crypto::Hash hash_;
        crypto::DigestContext digest_;
        std::size_t messages_ = 0;
        bool first_is_client_hello_ = false, retry_ = false;
        Transcript(crypto::Hash hash, crypto::DigestContext&& digest) : hash_(hash), digest_(std::move(digest)) {}
    public:
        Transcript(Transcript&&) noexcept = default;
        auto operator=(Transcript&&) noexcept -> Transcript& = default;
        Transcript(Transcript const&) = delete;
        auto operator=(Transcript const&) -> Transcript& = delete;
        [[nodiscard]] static auto create(crypto::Hash hash) -> std::expected<Transcript,TranscriptError>;
        // Accepts one complete handshake message including its four-byte header, not a TLS record.
        [[nodiscard]] auto append(std::span<std::uint8_t const> message) -> std::expected<void,TranscriptError>;
        [[nodiscard]] auto snapshot() const -> std::expected<crypto::Bytes,TranscriptError>;
        // Consumes this empty or post-HRR transcript, hashing only the exact
        // final-length Hello prefix through PSK identities. The encoded length
        // deliberately exceeds the supplied prefix; ordinary append stays strict.
        [[nodiscard]] auto client_hello_binder_hash(std::span<std::uint8_t const> prefix) &&
            -> std::expected<crypto::Bytes,TranscriptError>;
        // Must be called after ClientHello1 and before appending HelloRetryRequest.
        [[nodiscard]] auto hello_retry_request() -> std::expected<void,TranscriptError>;
    };
}
