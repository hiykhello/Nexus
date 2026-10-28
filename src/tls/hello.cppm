export module nexus.tls.hello;
import std;

export namespace nexus::tls {
    enum class HelloError { truncated, invalid_length, invalid_version, invalid_random, invalid_session_id,
                             invalid_cipher_suites, invalid_compression, invalid_extensions, duplicate_extension,
                             unsupported, message_too_large };
    struct Extension {
        std::uint16_t type = 0;
        std::vector<std::uint8_t> data;
        auto operator==(Extension const&) const -> bool = default;
    };
    struct ClientHello {
        std::uint16_t legacy_version = 0x0303;
        std::array<std::uint8_t,32> random{};
        std::vector<std::uint8_t> session_id;
        std::vector<std::uint16_t> cipher_suites;
        std::vector<std::uint8_t> compression_methods;
        std::vector<Extension> extensions;
        auto operator==(ClientHello const&) const -> bool = default;

        [[nodiscard]] static auto parse(std::span<std::uint8_t const> body,
                                         std::size_t max_body_size = 1u << 20)
            -> std::expected<ClientHello, HelloError>;
        [[nodiscard]] auto encode(std::size_t max_body_size = 1u << 20) const
            -> std::expected<std::vector<std::uint8_t>, HelloError>;
        // Applies the same size and structural checks as encode without allocating.
        [[nodiscard]] auto validate_encoding(std::size_t max_body_size = 1u << 20) const -> std::expected<void, HelloError>;
        // Checks the TLS 1.3 ClientHello invariants this layer owns; it does not negotiate policy.
        [[nodiscard]] auto validate_tls13() const -> std::expected<void, HelloError>;
        [[nodiscard]] auto extension(std::uint16_t type) const noexcept -> Extension const*;
    };
}
