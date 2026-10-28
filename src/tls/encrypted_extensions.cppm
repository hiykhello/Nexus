export module nexus.tls.encrypted_extensions;
export import nexus.tls.hello;
import std;

export namespace nexus::tls {
    enum class EncryptedExtensionsError { malformed, duplicate, unoffered, unsupported, invalid_selection };
    struct EncryptedExtensions {
        std::optional<std::vector<std::uint8_t>> alpn;
        std::optional<std::uint16_t> peer_record_size_limit;
        std::vector<std::uint16_t> peer_groups;
        bool server_name_acknowledged = false;
    };
    // One complete handshake message and the exact parsed ClientHello. Supports server_name,
    // ALPN, supported_groups and record_size_limit; other extensions are rejected.
    // The caller must enforce the selected record limit and handshake ordering.
    [[nodiscard]] auto validate_encrypted_extensions(ClientHello const& client, std::span<std::uint8_t const> message)
        -> std::expected<EncryptedExtensions,EncryptedExtensionsError>;
}
