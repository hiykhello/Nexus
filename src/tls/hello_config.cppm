export module tls.hello_config;
export import tls.hello;
import std;

export namespace tls {
    // Retain an existing padding extension, or add one when the target needs
    // at least its four-byte header. The size refers to the ClientHello body.
    [[nodiscard]] auto repad_client_hello(ClientHello& hello,std::size_t target_body_size,
        std::size_t max_body_size=65531) -> std::expected<void,HelloError>;
    enum class ClientHelloConfigError { invalid_server_name, invalid_alpn, invalid_group, random_error };
    // SNI is optional and independent of certificate identity; ALPN is a list of opaque protocol IDs.
    // Only implemented X25519, X25519MLKEM768, P256/P384/P521 and TLS1.3 algorithms are offered.
    [[nodiscard]] auto make_client_hello(std::optional<std::string_view> server_name,
        std::span<std::string_view const> alpn, std::span<std::uint16_t const> groups)
        -> std::expected<ClientHello,ClientHelloConfigError>;
}
