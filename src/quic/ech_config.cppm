export module quic.ech_config;
import std;

export namespace quic {
    struct EchConfig {
        std::uint8_t id;
        std::uint8_t maximum_name_length;
        std::uint16_t aead;
        std::array<std::uint8_t,32> public_key;
        std::string public_name;
        std::vector<std::uint8_t> wire;
    };

    enum class EchConfigError { malformed, unsupported };
    [[nodiscard]] auto select_ech_config(std::span<const std::uint8_t> list)
        -> std::expected<EchConfig, EchConfigError>;
    [[nodiscard]] auto read_ech_config(std::string_view path) -> std::expected<EchConfig, std::string>;
}
