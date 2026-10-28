export module nexus.tls.server_negotiation;
export import nexus.tls.hello;
import std;
export namespace nexus::tls {
    enum class ServerNegotiationError { invalid_hello, unsupported_psk, missing_extension, malformed_extension,
        no_cipher, no_group, no_signature, invalid_key_share };
    struct ServerSelection {
        std::uint16_t cipher_suite;
        std::uint16_t signature_scheme;
        std::uint16_t group;
        // An absent share for the selected group means a retry is required.
        std::optional<std::array<std::uint8_t,32>> x25519_share;
        std::optional<std::array<std::uint8_t,1216>> hybrid_share;
    };
    // Schemes must correspond to the configured certificate and private key, validated by the caller.
    // The returned peer share still requires key agreement and public-key validation.
    // PSK, early data and actual HelloRetryRequest processing are not implemented here.
    [[nodiscard]] auto negotiate_server(ClientHello const& hello, std::span<std::uint16_t const> certificate_schemes)
        -> std::expected<ServerSelection,ServerNegotiationError>;
}
