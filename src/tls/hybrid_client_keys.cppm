export module nexus.tls.hybrid_client_keys;
export import nexus.tls.client_keys;
export import nexus.tls.hybrid;
import std;

export namespace nexus::tls {
    // Consumes hybrid ephemeral keys, validates actual Hello messages and initializes unauthenticated handshake keys.
    // This direct path does not authenticate the server.
    [[nodiscard]] auto client_hybrid_handshake_keys(std::span<std::uint8_t const> client_hello,
        std::span<std::uint8_t const> server_hello, HybridClient&& ephemeral)
        -> std::expected<ClientHandshakeKeys,ClientKeyError>;
    // Validates the complete retry sequence and consumes the second ClientHello key.
    [[nodiscard]] auto client_hybrid_handshake_keys_retry(std::span<std::uint8_t const> first, std::span<std::uint8_t const> retry,
        std::span<std::uint8_t const> second, std::span<std::uint8_t const> server, HybridClient&& key)
        -> std::expected<ClientHandshakeKeys,ClientKeyError>;
}
