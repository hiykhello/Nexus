export module encoding.base64;
import std;

export namespace encoding {
    namespace base64_detail {
        inline constexpr std::string_view kStdAlphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        inline constexpr std::string_view kUrlAlphabet =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        [[nodiscard]] constexpr auto std_digit(char c) noexcept -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return -1;
        }
    }

    [[nodiscard]] inline auto decode_base64_exact(std::span<char const> input, std::span<std::uint8_t> output) noexcept -> bool {
        if (input.size() != ((output.size() + 2) / 3) * 4) return false;
        std::size_t out = 0;
        for (std::size_t i = 0; i < input.size(); i += 4) {
            int a = base64_detail::std_digit(input[i]);
            int b = base64_detail::std_digit(input[i + 1]);
            int c = input[i + 2] == '=' ? -1 : base64_detail::std_digit(input[i + 2]);
            int d = input[i + 3] == '=' ? -1 : base64_detail::std_digit(input[i + 3]);
            auto remaining = output.size() - out;
            if (a < 0 || b < 0 || (remaining > 1 && c < 0) || (remaining > 2 && d < 0) ||
                (remaining == 1 && (input[i + 2] != '=' || input[i + 3] != '=' || (b & 15))) ||
                (remaining == 2 && (input[i + 3] != '=' || (c & 3)))) return false;
            output[out++] = static_cast<std::uint8_t>((a << 2) | (b >> 4));
            if (remaining > 1) output[out++] = static_cast<std::uint8_t>((b << 4) | (c >> 2));
            if (remaining > 2) output[out++] = static_cast<std::uint8_t>((c << 6) | d);
        }
        return true;
    }

    [[nodiscard]] inline auto encode_base64(std::span<std::uint8_t const> input, bool url_safe = false, bool pad = true) -> std::string {
        auto const alpha = url_safe ? base64_detail::kUrlAlphabet : base64_detail::kStdAlphabet;
        std::string out;
        out.reserve(((input.size() + 2) / 3) * 4);
        for (std::size_t i = 0; i < input.size(); i += 3) {
            std::uint32_t v = static_cast<std::uint32_t>(input[i]) << 16;
            if (i + 1 < input.size()) v |= static_cast<std::uint32_t>(input[i + 1]) << 8;
            if (i + 2 < input.size()) v |= static_cast<std::uint32_t>(input[i + 2]);
            out.push_back(alpha[(v >> 18) & 0x3fu]);
            out.push_back(alpha[(v >> 12) & 0x3fu]);
            if (i + 1 < input.size()) out.push_back(alpha[(v >> 6) & 0x3fu]);
            else if (pad) out.push_back('=');
            if (i + 2 < input.size()) out.push_back(alpha[v & 0x3fu]);
            else if (pad) out.push_back('=');
        }
        return out;
    }

    [[nodiscard]] inline auto encode_base64url(std::span<std::uint8_t const> input, bool pad = false) -> std::string {
        return encode_base64(input, true, pad);
    }

    // Strict RFC 4648 standard Base64 decode (non-empty, multiple of 4, canonical padding bits).
    [[nodiscard]] inline auto decode_base64_strict(std::string_view in, std::vector<std::uint8_t>& out) -> bool {
        if (in.empty() || in.size() % 4 != 0) return false;
        std::size_t pad = 0;
        if (in.back() == '=') ++pad;
        if (in.size() >= 2 && in[in.size() - 2] == '=') ++pad;
        if (pad > 0 && in.back() != '=') return false;
        out.reserve(out.size() + (in.size() / 4) * 3 - pad);
        for (std::size_t i = 0; i < in.size(); i += 4) {
            bool last = (i + 4 == in.size());
            int a = base64_detail::std_digit(in[i]);
            int b = base64_detail::std_digit(in[i + 1]);
            int c = (last && in[i + 2] == '=') ? -2 : base64_detail::std_digit(in[i + 2]);
            int d = (last && in[i + 3] == '=') ? -2 : base64_detail::std_digit(in[i + 3]);
            if (a < 0 || b < 0 || c == -1 || d == -1) return false;
            if (c == -2 && d != -2) return false;
            if (last && pad == 1 && (c & 3) != 0) return false;
            if (last && pad == 2 && (b & 15) != 0) return false;
            out.push_back(static_cast<std::uint8_t>((a << 2) | (b >> 4)));
            if (c >= 0) out.push_back(static_cast<std::uint8_t>(((b & 15) << 4) | (c >> 2)));
            if (d >= 0) out.push_back(static_cast<std::uint8_t>(((c & 3) << 6) | d));
        }
        return true;
    }

    // PEM / OpenSSH Base64 decode: ignores ASCII whitespace, rejects characters after '=', enforces zero tail bits.
    [[nodiscard]] inline auto decode_base64_pem(std::string_view text) -> std::optional<std::vector<std::uint8_t>> {
        std::vector<std::uint8_t> out;
        out.reserve((text.size() / 4) * 3);
        std::uint32_t acc = 0;
        int bits = 0;
        bool pad_seen = false;
        for (unsigned char c : text) {
            if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
            if (c == '=') { pad_seen = true; continue; }
            if (pad_seen) return std::nullopt;
            int val = base64_detail::std_digit(static_cast<char>(c));
            if (val < 0) return std::nullopt;
            acc = (acc << 6) | static_cast<std::uint32_t>(val);
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push_back(static_cast<std::uint8_t>((acc >> bits) & 0xffu));
            }
        }
        if (bits >= 6 || (bits > 0 && (acc & ((1u << bits) - 1u)) != 0)) return std::nullopt;
        return out;
    }

    // Flexible subscription/URI Base64 decode: accepts standard and URL-safe alphabets, ignores whitespace and '='.
    [[nodiscard]] inline auto decode_base64_flexible(std::string_view in) -> std::optional<std::string> {
        std::string out;
        out.reserve((in.size() / 4) * 3);
        std::uint32_t acc = 0;
        int bits = 0;
        for (char ch : in) {
            if (ch == '=' || std::isspace(static_cast<unsigned char>(ch))) continue;
            char m = ch == '-' ? '+' : (ch == '_' ? '/' : ch);
            int val = base64_detail::std_digit(m);
            if (val < 0) return std::nullopt;
            acc = (acc << 6) | static_cast<std::uint32_t>(val);
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.push_back(static_cast<char>((acc >> bits) & 0xffu));
            }
        }
        return out;
    }
}
