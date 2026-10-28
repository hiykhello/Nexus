export module nexus.tls.client_keys;
export import nexus.tls.record;
export import nexus.tls.schedule;
export import nexus.tls.transcript;
import std;

export namespace nexus::tls {
    enum class ClientKeyError { malformed_hello, invalid_offer, invalid_server, key_mismatch, invalid_peer, crypto_error };
    // Internal handshake epoch, not an authenticated TLS connection.
    struct ClientHandshakeKeys {
        crypto::Hash hash;
        Transcript transcript;
        Secret handshake_secret;
        Secret client_traffic;
        Secret server_traffic;
        RecordLayer write;
        RecordLayer read;
    };
    // Consumes the ephemeral key, verifies it matches the offered X25519 share, and binds exact wire messages.
    // Direct TLS 1.3 without PSK. This does not authenticate the server.
    [[nodiscard]] auto client_handshake_keys(std::span<std::uint8_t const> client_hello,
        std::span<std::uint8_t const> server_hello, crypto::X25519Private&& private_key)
        -> std::expected<ClientHandshakeKeys,ClientKeyError>;
    // Validates the complete retry sequence and consumes the second ClientHello key.
    [[nodiscard]] auto client_handshake_keys_retry(std::span<std::uint8_t const> first, std::span<std::uint8_t const> retry,
        std::span<std::uint8_t const> second, std::span<std::uint8_t const> server, crypto::X25519Private&& key)
        -> std::expected<ClientHandshakeKeys,ClientKeyError>;
}
