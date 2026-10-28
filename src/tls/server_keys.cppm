export module nexus.tls.server_keys;
export import nexus.tls.server_negotiation;
export import nexus.tls.record;
export import nexus.tls.schedule;
export import nexus.tls.transcript;
import std;
export namespace nexus::tls {
    enum class ServerKeyError { invalid_hello, negotiation_failed, retry_required, invalid_peer, crypto_error };
    // Handshake epoch only: neither endpoint is authenticated until Finished is verified.
    struct ServerHandshakeKeys {
        crypto::Bytes server_hello;
        std::uint16_t signature_scheme;
        crypto::Hash hash;
        Transcript transcript;
        Secret handshake_secret, client_traffic, server_traffic;
        RecordLayer write, read;
    };
    // The input is the complete, exact ClientHello handshake message, without record headers.
    // The caller must ensure certificate_schemes match its configured certificate and key.
    [[nodiscard]] auto server_handshake_keys(std::span<std::uint8_t const> client_hello,
        std::span<std::uint16_t const> certificate_schemes) -> std::expected<ServerHandshakeKeys,ServerKeyError>;
    // X25519 or X25519MLKEM768 retry, without cookies or PSK. Inputs are exact handshake messages.
    [[nodiscard]] auto server_retry_hello(std::span<std::uint8_t const> first,
        std::span<std::uint16_t const> certificate_schemes) -> std::expected<crypto::Bytes,ServerKeyError>;
    [[nodiscard]] auto server_handshake_keys_retry(std::span<std::uint8_t const> first,
        std::span<std::uint8_t const> retry, std::span<std::uint8_t const> second,
        std::span<std::uint16_t const> certificate_schemes) -> std::expected<ServerHandshakeKeys,ServerKeyError>;
}
