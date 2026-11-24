export module encoding.hex;
import std;

export namespace encoding {
    [[nodiscard]] constexpr auto hex_value(char c) noexcept -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    }

    [[nodiscard]] inline auto hex_encode(std::span<std::uint8_t const> bytes) -> std::string {
        static constexpr char kHex[] = "0123456789abcdef";
        std::string out;
        out.reserve(bytes.size() * 2);
        for (std::uint8_t b : bytes) {
            out.push_back(kHex[(b >> 4) & 0xfu]);
            out.push_back(kHex[b & 0xfu]);
        }
        return out;
    }

    [[nodiscard]] constexpr auto hex_decode(std::string_view hex, std::span<std::uint8_t> out) noexcept -> bool {
        if (hex.size() != out.size() * 2) return false;
        for (std::size_t i = 0; i < out.size(); ++i) {
            int hi = hex_value(hex[i * 2]);
            int lo = hex_value(hex[i * 2 + 1]);
            if (hi < 0 || lo < 0) return false;
            out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
        }
        return true;
    }
}
