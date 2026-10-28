export module nexus.socks5;
import std;

export namespace nexus::socks5 {
    enum class Status {
        incomplete, accepted, invalid_version, invalid_reserved,
        no_acceptable_method, unsupported_command, unsupported_address, invalid_address
    };

    struct Greeting {
        Status status = Status::incomplete;
        std::size_t consumed = 0;
    };

    struct Request {
        Status status = Status::incomplete;
        std::size_t consumed = 0;
        std::uint8_t address_type = 0;
        std::array<std::uint8_t, 255> address{};
        std::uint8_t address_length = 0;
        std::uint16_t port = 0;
    };

    // Parse one frame without retaining or modifying the input. Trailing
    // bytes belong to the next frame or the relayed application stream.
    [[nodiscard]] auto parse_greeting(std::span<std::uint8_t const> input, std::uint8_t method = 0) noexcept -> Greeting;
    [[nodiscard]] auto parse_request(std::span<std::uint8_t const> input) noexcept -> Request;
}
