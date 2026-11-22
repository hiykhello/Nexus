export module tls.finished;
export import tls.schedule;
export import tls.transcript;
import std;

export namespace tls {
    enum class FinishedError { invalid_state, malformed_message, verification_failed, crypto_error };
    // Construct after the certificate/CV flight or an explicitly selected PSK
    // has authorized these transcript and traffic keys. This helper validates
    // neither policy; arbitrary caller-supplied keys do not prove peer identity.
    class ClientFinished {
        crypto::Hash hash_;
        Transcript transcript_;
        Secret client_traffic_;
        Secret server_traffic_;
        enum class State { await_server, await_client, complete, failed } state_ = State::await_server;
    public:
        ClientFinished(crypto::Hash hash, Transcript&& transcript, Secret&& client_traffic, Secret&& server_traffic) noexcept;
        ClientFinished(ClientFinished const&) = delete;
        auto operator=(ClientFinished const&) -> ClientFinished& = delete;
        ClientFinished(ClientFinished&& other) noexcept;
        auto operator=(ClientFinished&& other) noexcept -> ClientFinished&;
        // Full handshake message, including header; consumes the state on any failure.
        [[nodiscard]] auto verify_server(std::span<std::uint8_t const> message) -> std::expected<void,FinishedError>;
        // For a handshake without client authentication; returns a complete message and appends it to transcript.
        [[nodiscard]] auto make_client(std::span<std::uint8_t const> preceding={}) -> std::expected<crypto::Bytes,FinishedError>;
        [[nodiscard]] auto transcript_hash() const -> std::expected<crypto::Bytes,FinishedError>;
    };
}
