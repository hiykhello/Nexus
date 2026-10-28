export module nexus.tls.server_hello;
export import nexus.tls.hello;
export import nexus.tls.key_share;
import std;

export namespace nexus::tls {
    enum class ServerHelloError { truncated, invalid_length, invalid_version, invalid_session_id, invalid_compression,
        duplicate_extension, invalid_extension, unsupported, retry, session_mismatch, cipher_mismatch, group_mismatch };
    struct ServerHello {
        std::uint16_t legacy_version = 0x0303;
        std::array<std::uint8_t,32> random{};
        std::vector<std::uint8_t> session_id_echo;
        std::uint16_t cipher_suite = 0;
        std::uint8_t compression_method = 0;
        std::vector<Extension> extensions;
        auto operator==(ServerHello const&) const -> bool = default;
        [[nodiscard]] static auto parse(std::span<std::uint8_t const> body) -> std::expected<ServerHello,ServerHelloError>;
        [[nodiscard]] auto encode() const -> std::expected<std::vector<std::uint8_t>,ServerHelloError>;
        [[nodiscard]] auto is_retry() const noexcept -> bool;
        // Validates the supported non-PSK X25519 TLS 1.3 subset against the actual offer.
        // X25519 agreement must additionally reject low-order public keys.
        [[nodiscard]] auto validate_x25519(ClientHello const& client) const -> std::expected<KeyShareEntry,ServerHelloError>;
        [[nodiscard]] auto validate_x25519_mlkem768(ClientHello const& client) const -> std::expected<KeyShareEntry,ServerHelloError>;
        // Validate before sending ClientHello2. An empty result means a cookie-only retry.
        [[nodiscard]] auto validate_retry_request(ClientHello const& first) const -> std::expected<std::optional<std::uint16_t>,ServerHelloError>;
        // The replacement must contain a fresh key for the requested group; omit it for cookie-only retries.
        [[nodiscard]] auto retry_client_hello(ClientHello const& first, std::optional<KeyShareEntry> replacement) const -> std::expected<ClientHello,ServerHelloError>;
        // Validates the no-PSK retry subset, including ClientHello2 and the final ServerHello.
        [[nodiscard]] auto validate_retry(ClientHello const& first, ClientHello const& second,
            ServerHello const& final_hello) const -> std::expected<KeyShareEntry,ServerHelloError>;
    private:
        [[nodiscard]] auto validate_group(ClientHello const& client, std::uint16_t group, std::size_t client_size, std::size_t server_size) const -> std::expected<KeyShareEntry,ServerHelloError>;
    };
}
