export module tls.encrypted_extensions;
export import tls.hello;
import tls.handshake_policy;
import std;

export namespace tls {
    enum class EncryptedExtensionsError { malformed, duplicate, unoffered, unsupported, invalid_selection, missing_required, invalid_record_limit };
    struct EncryptedExtensions {
        std::optional<std::vector<std::uint8_t>> alpn;
        std::optional<std::uint16_t> peer_record_size_limit;
        std::vector<std::uint16_t> peer_groups;
        std::optional<std::uint16_t> application_settings_code;
        std::vector<std::uint8_t> application_settings;
        std::vector<std::uint8_t> ech_retry_configs;
        std::vector<std::vector<std::uint8_t>> peer_trust_anchors;
        bool server_name_acknowledged = false;
    };
    // One complete handshake message and the exact parsed ClientHello. Supports server_name,
    // ALPN, ALPS, supported_groups and record_size_limit; other extensions are rejected.
    // The caller must enforce the selected record limit and handshake ordering.
    [[nodiscard]] auto validate_encrypted_extensions(ClientHello const& client, std::span<std::uint8_t const> message)
        -> std::expected<EncryptedExtensions,EncryptedExtensionsError>;
    struct QuicEncryptedExtensions {
        EncryptedExtensions common;
        // Valid only while the original input message remains alive/unmoved.
        std::span<std::uint8_t const> transport_parameters;
        bool accepted_early=false;
    };
    namespace detail {
        auto validate_extensions(ClientHello const& client,std::span<std::uint8_t const> message,bool quic,std::span<std::uint8_t const>* parameters,bool* early=nullptr)
            -> std::expected<EncryptedExtensions,EncryptedExtensionsError>;
    }
    template<bool AllowPsk=false,bool AllowEarly=false>
    [[nodiscard]] auto validate_quic_encrypted_extensions(ClientHello const& client,std::span<std::uint8_t const> message,std::span<std::uint8_t const> required)
        -> std::expected<QuicEncryptedExtensions,EncryptedExtensionsError> {
        auto offered=quic_client_parameters<AllowPsk,AllowEarly>(client,required);
        if (!offered) return std::unexpected(offered.error()==HandshakePolicyError::missing_transport_parameters ? EncryptedExtensionsError::missing_required : EncryptedExtensionsError::invalid_selection);
        std::span<std::uint8_t const> parameters;
        bool early=false;
        auto result=detail::validate_extensions(client,message,true,&parameters,AllowEarly ? &early : nullptr);
        if (!result) return std::unexpected(result.error());
        if (!result->alpn || !std::ranges::equal(*result->alpn,required)) return std::unexpected(EncryptedExtensionsError::invalid_selection);
        return QuicEncryptedExtensions{std::move(*result),parameters,early};
    }

}
