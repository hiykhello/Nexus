export module reality.client;
export import reality.auth;
export import tls.client_session_handshake;
import std;

export namespace reality {
    // Authenticates only the driver's first Hello and binds its certificate
    // verifier to the private key matching the transmitted initial share.
    [[nodiscard]] auto authenticate_client_hello(tls::ClientHelloDriver& driver,
        std::span<std::uint8_t const> server_public,Identity identity) -> std::expected<void,tls::ClientHelloDriverError>;
    // Generates a fresh random and initial share for every attempt; the
    // server's public key is borrowed only during this synchronous call.
    [[nodiscard]] auto create_client_session(tls::ClientHello hello,std::span<std::uint8_t const> server_public,
        Identity identity,std::uint16_t initial_group=0x001d)
        -> std::expected<tls::ClientSessionHandshake,tls::ClientSessionHandshakeError>;
    [[nodiscard]] auto create_client_session(tls::ClientHello hello,std::span<std::uint16_t const> initial_groups,
        std::span<std::uint8_t const> server_public,Identity identity)
        -> std::expected<tls::ClientSessionHandshake,tls::ClientSessionHandshakeError>;
}
