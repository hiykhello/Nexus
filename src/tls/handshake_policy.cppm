export module tls.handshake_policy;
export import tls.hello;
import std;

export namespace tls {
    enum class HandshakeTransport : std::uint8_t { tcp,quic };
    enum class HandshakePolicyError { invalid_hello,invalid_session_id,missing_transport_parameters,invalid_alpn,unsupported_psk,too_large,unsupported_transport_parameters };
    [[nodiscard]] auto validate_handshake_transport(ClientHello const& hello,HandshakeTransport transport) noexcept -> std::expected<void,HandshakePolicyError>;
    // Parameter bytes borrow the exact ClientHello's extension storage. Native
    // QUIC validates parameter values and connection-ID binding immediately.
    [[nodiscard]] auto offers_alpn(ClientHello const& hello,std::span<std::uint8_t const> required) noexcept -> bool;
    template<bool AllowPsk=false,bool AllowEarly=false>
    [[nodiscard]] auto quic_client_parameters(ClientHello const& hello,std::span<std::uint8_t const> required)
        -> std::expected<std::span<std::uint8_t const>,HandshakePolicyError> {
        using E=HandshakePolicyError;
        if (!hello.validate_tls13() || !hello.validate_encoding()) return std::unexpected(E::invalid_hello);
        auto transport=validate_handshake_transport(hello,HandshakeTransport::quic); if (!transport) return std::unexpected(transport.error());
        if (!AllowPsk && hello.extension(41)) return std::unexpected(E::unsupported_psk);
        if (auto* early=hello.extension(42); early && (!AllowEarly || !early->data.empty() || !hello.extension(41)))
            return std::unexpected(E::unsupported_psk);
        auto* parameters=hello.extension(0x39);
        if (!parameters) return std::unexpected(E::missing_transport_parameters);
        if (!offers_alpn(hello,required)) return std::unexpected(E::invalid_alpn);
        // Legacy/record offers in CH can be ignored; RFC 9001 A.2 contains
        // both record_size_limit and renegotiation_info. They are not negotiated.
        return std::span<std::uint8_t const>(parameters->data);
    }
    // A present QUIC parameter span emits extension 0x39 even if it is empty.
    // The caller has already validated ALPN and extension offers against CH.
    [[nodiscard]] auto encode_encrypted_extensions(std::span<std::uint8_t const> alpn,
        std::optional<std::span<std::uint8_t const>> quic_parameters={}) -> std::expected<std::vector<std::uint8_t>,HandshakePolicyError>;
}
