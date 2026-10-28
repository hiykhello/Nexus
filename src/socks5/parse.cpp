module nexus.socks5;
import std;

namespace nexus::socks5 {
    auto parse_greeting(std::span<std::uint8_t const> input, std::uint8_t method) noexcept -> Greeting {
        if (input.empty()) return {};
        if (input[0] != 5) return {Status::invalid_version, 1};
        if (input.size() < 2) return {};
        auto const length = std::size_t{2} + input[1];
        if (input.size() < length) return {};
        auto const methods = input.subspan(2, input[1]);
        auto const found = std::find(methods.begin(), methods.end(), method) != methods.end();
        return {found ? Status::accepted : Status::no_acceptable_method, length};
    }

    auto parse_request(std::span<std::uint8_t const> input) noexcept -> Request {
        Request result;
        if (input.empty()) return result;
        if (input[0] != 5) {
            result.status = Status::invalid_version;
            result.consumed = 1;
            return result;
        }
        if (input.size() < 4) return result;
        result.consumed = 4;
        if (input[2] != 0) {
            result.status = Status::invalid_reserved;
            return result;
        }
        if (input[1] != 1) {
            result.status = Status::unsupported_command;
            return result;
        }
        result.address_type = input[3];
        std::size_t offset = 4;
        std::size_t address_length = 0;
        switch (result.address_type) {
        case 1: address_length = 4; break;
        case 4: address_length = 16; break;
        case 3:
            if (input.size() < 5) return {};
            address_length = input[4];
            offset = 5;
            if (address_length == 0) {
                result.status = Status::invalid_address;
                result.consumed = 5;
                return result;
            }
            break;
        default:
            result.status = Status::unsupported_address;
            return result;
        }
        auto const length = offset + address_length + 2;
        if (input.size() < length) return {};
        std::copy_n(input.begin() + offset, address_length, result.address.begin());
        result.address_length = static_cast<std::uint8_t>(address_length);
        result.port = static_cast<std::uint16_t>((std::uint16_t{input[length - 2]} << 8) | input[length - 1]);
        result.status = Status::accepted;
        result.consumed = length;
        return result;
    }
}
