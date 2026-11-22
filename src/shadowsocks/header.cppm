export module shadowsocks.header;
import std;
export namespace shadowsocks {
    enum class HeaderError { invalid_length, invalid_type, invalid_timestamp, invalid_salt, invalid_address, invalid_padding };
    struct FixedHeader { std::uint64_t timestamp; std::uint16_t length; };
    struct RequestHeader { std::vector<std::uint8_t> address; std::vector<std::uint8_t> payload; };
    // The address is one complete SOCKS5 ATYP/address/port encoding.
    [[nodiscard]] auto make_request_header(std::span<std::uint8_t const> address,
        std::span<std::uint8_t const> padding, std::span<std::uint8_t const> payload)
        -> std::expected<std::vector<std::uint8_t>,HeaderError>;
    [[nodiscard]] auto parse_request_header(std::span<std::uint8_t const> bytes)
        -> std::expected<RequestHeader,HeaderError>;
    [[nodiscard]] auto make_fixed_header(bool response, std::uint64_t timestamp, std::uint16_t length,
        std::span<std::uint8_t const> request_salt = {}) -> std::expected<std::vector<std::uint8_t>,HeaderError>;
    // now is the current Unix timestamp in seconds; the inclusive tolerance is 30 seconds.
    [[nodiscard]] auto parse_fixed_header(std::span<std::uint8_t const> bytes, bool response, std::uint64_t now,
        std::span<std::uint8_t const> request_salt = {}) -> std::expected<FixedHeader,HeaderError>;
}
