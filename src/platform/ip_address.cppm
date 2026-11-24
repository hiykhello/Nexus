export module platform.ip_address;
import std;
import encoding.hex;

export namespace platform {
    struct IpAddress {
        std::array<std::uint8_t, 16> bytes{};
        std::uint8_t size = 0;
        [[nodiscard]] constexpr auto view() const noexcept -> std::span<std::uint8_t const> {
            return std::span(bytes).first(size);
        }
        [[nodiscard]] constexpr auto operator==(IpAddress const& o) const noexcept -> bool {
            return size == o.size && std::ranges::equal(view(), o.view());
        }
    };

    [[nodiscard]] constexpr auto host_to_net16(std::uint16_t v) noexcept -> std::uint16_t {
        if constexpr (std::endian::native == std::endian::little) return std::byteswap(v);
        else return v;
    }
    [[nodiscard]] constexpr auto net_to_host16(std::uint16_t v) noexcept -> std::uint16_t {
        return host_to_net16(v);
    }
    [[nodiscard]] constexpr auto host_to_net32(std::uint32_t v) noexcept -> std::uint32_t {
        if constexpr (std::endian::native == std::endian::little) return std::byteswap(v);
        else return v;
    }
    [[nodiscard]] constexpr auto net_to_host32(std::uint32_t v) noexcept -> std::uint32_t {
        return host_to_net32(v);
    }

    namespace ip_detail {
        [[nodiscard]] constexpr auto hex_digit(char c) noexcept -> int {
            return encoding::hex_value(c);
        }

        [[nodiscard]] constexpr auto parse_ipv4(std::string_view text, std::uint8_t* out) noexcept -> bool {
            std::size_t pos = 0;
            for (std::size_t octet = 0; octet < 4; ++octet) {
                if (octet > 0) {
                    if (pos >= text.size() || text[pos] != '.') return false;
                    ++pos;
                }
                if (pos >= text.size() || text[pos] < '0' || text[pos] > '9') return false;
                if (text[pos] == '0' && pos + 1 < text.size() && text[pos + 1] >= '0' && text[pos + 1] <= '9') {
                    return false;
                }
                unsigned value = 0;
                std::size_t digits = 0;
                while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
                    if (++digits > 3) return false;
                    value = value * 10u + static_cast<unsigned>(text[pos++] - '0');
                }
                if (value > 255u) return false;
                out[octet] = static_cast<std::uint8_t>(value);
            }
            return pos == text.size();
        }

        [[nodiscard]] constexpr auto parse_ipv6(std::string_view text, std::uint8_t* out) noexcept -> bool {
            if (text.size() < 2 || text.size() > 45) return false;
            std::array<std::uint16_t, 8> words{};
            std::size_t count = 0;
            int compress_at = -1;
            std::size_t pos = 0;

            if (text[0] == ':') {
                if (text[1] != ':') return false;
                compress_at = 0;
                pos = 2;
                if (pos == text.size()) {
                    std::ranges::fill_n(out, 16, std::uint8_t{0});
                    return true;
                }
                if (text[pos] == ':') return false;
            }

            while (pos < text.size()) {
                auto tail = text.substr(pos);
                if (tail.find(':') == std::string_view::npos && tail.find('.') != std::string_view::npos) {
                    if (count > 6) return false;
                    std::uint8_t v4[4]{};
                    if (!parse_ipv4(tail, v4)) return false;
                    words[count++] = static_cast<std::uint16_t>((static_cast<unsigned>(v4[0]) << 8) | v4[1]);
                    words[count++] = static_cast<std::uint16_t>((static_cast<unsigned>(v4[2]) << 8) | v4[3]);
                    pos = text.size();
                    break;
                }
                if (count >= 8) return false;
                unsigned value = 0;
                std::size_t digits = 0;
                while (pos < text.size()) {
                    int d = hex_digit(text[pos]);
                    if (d < 0) break;
                    if (++digits > 4) return false;
                    value = (value << 4) | static_cast<unsigned>(d);
                    ++pos;
                }
                if (digits == 0) return false;
                words[count++] = static_cast<std::uint16_t>(value);
                if (pos == text.size()) break;
                if (text[pos] != ':') return false;
                ++pos;
                if (pos == text.size()) return false;
                if (text[pos] == ':') {
                    if (compress_at >= 0) return false;
                    compress_at = static_cast<int>(count);
                    ++pos;
                    if (pos == text.size()) break;
                    if (text[pos] == ':') return false;
                }
            }

            if (compress_at < 0) {
                if (count != 8) return false;
            } else {
                if (count >= 8) return false;
                auto tail_count = count - static_cast<std::size_t>(compress_at);
                auto gap = 8u - count;
                for (std::size_t i = tail_count; i > 0; --i) {
                    words[static_cast<std::size_t>(compress_at) + gap + i - 1] =
                        words[static_cast<std::size_t>(compress_at) + i - 1];
                }
                for (std::size_t i = 0; i < gap; ++i) {
                    words[static_cast<std::size_t>(compress_at) + i] = 0;
                }
            }

            for (std::size_t i = 0; i < 8; ++i) {
                out[i * 2] = static_cast<std::uint8_t>(words[i] >> 8);
                out[i * 2 + 1] = static_cast<std::uint8_t>(words[i] & 0xffu);
            }
            return true;
        }

        inline auto append_decimal(std::string& out, std::uint8_t value) -> void {
            if (value >= 100) out.push_back(static_cast<char>('0' + value / 100));
            if (value >= 10) out.push_back(static_cast<char>('0' + (value / 10) % 10));
            out.push_back(static_cast<char>('0' + value % 10));
        }

        inline auto append_hex16(std::string& out, std::uint16_t value) -> void {
            static constexpr char kHex[] = "0123456789abcdef";
            bool started = false;
            for (int shift = 12; shift >= 0; shift -= 4) {
                auto nibble = static_cast<unsigned>((value >> shift) & 0xfu);
                if (nibble || started || shift == 0) {
                    out.push_back(kHex[nibble]);
                    started = true;
                }
            }
        }
    }

    // Pure C++26 numeric IPv4/IPv6 parser (cross-platform, zero libc symbols).
    [[nodiscard]] constexpr auto parse_ip_address(std::string_view text) noexcept -> std::optional<IpAddress> {
        if (text.empty() || text.size() > 45 || text.find('\0') != text.npos) return {};
        IpAddress result;
        if (text.find(':') != text.npos) {
            if (!ip_detail::parse_ipv6(text, result.bytes.data())) return {};
            result.size = 16;
        } else {
            if (!ip_detail::parse_ipv4(text, result.bytes.data())) return {};
            result.size = 4;
        }
        return result;
    }

    [[nodiscard]] inline auto format_ipv4(std::span<std::uint8_t const, 4> bytes) -> std::string {
        std::string out;
        out.reserve(15);
        for (std::size_t i = 0; i < 4; ++i) {
            if (i > 0) out.push_back('.');
            ip_detail::append_decimal(out, bytes[i]);
        }
        return out;
    }

    // RFC 5952 + POSIX inet_ntop(AF_INET6) canonical formatter.
    [[nodiscard]] inline auto format_ipv6(std::span<std::uint8_t const, 16> bytes) -> std::string {
        std::array<std::uint16_t, 8> words{};
        for (std::size_t i = 0; i < 8; ++i) {
            words[i] = static_cast<std::uint16_t>((static_cast<unsigned>(bytes[i * 2]) << 8) | bytes[i * 2 + 1]);
        }

        // Longest run of >= 2 consecutive zeros (leftmost wins ties, RFC 5952 §4.2.3).
        int best_base = -1, best_len = 0;
        int cur_base = -1, cur_len = 0;
        for (int i = 0; i < 8; ++i) {
            if (words[static_cast<std::size_t>(i)] == 0) {
                if (cur_base < 0) { cur_base = i; cur_len = 1; }
                else ++cur_len;
            } else {
                if (cur_base >= 0) {
                    if (cur_len > best_len) { best_base = cur_base; best_len = cur_len; }
                    cur_base = -1; cur_len = 0;
                }
            }
        }
        if (cur_base >= 0 && cur_len > best_len) { best_base = cur_base; best_len = cur_len; }
        if (best_len < 2) { best_base = -1; best_len = 0; }

        bool embedded_v4 = best_base == 0 &&
            (best_len == 6 || (best_len == 5 && words[5] == 0xffffu));

        std::string out;
        out.reserve(39);
        for (int i = 0; i < 8; ++i) {
            if (best_base >= 0 && i >= best_base && i < best_base + best_len) {
                if (i == best_base) out.push_back(':');
                continue;
            }
            if (i != 0) out.push_back(':');
            if (i == 6 && embedded_v4) {
                out += format_ipv4(bytes.subspan<12, 4>());
                break;
            }
            ip_detail::append_hex16(out, words[static_cast<std::size_t>(i)]);
        }
        if (best_base >= 0 && best_base + best_len == 8) out.push_back(':');
        return out;
    }

    [[nodiscard]] inline auto format_ip_address(std::span<std::uint8_t const> bytes) -> std::optional<std::string> {
        if (bytes.size() == 4) return format_ipv4(bytes.first<4>());
        if (bytes.size() == 16) return format_ipv6(bytes.first<16>());
        return {};
    }

    struct HostPortView {
        std::string_view host;
        std::uint16_t port = 0;
    };

    [[nodiscard]] inline auto split_host_port(std::string_view spec, bool strict = false) noexcept
        -> std::optional<HostPortView> {
        if (spec.empty()) return std::nullopt;
        std::string_view host, port_text;
        if (spec.front() == '[') {
            auto close = spec.find(']');
            if (close == std::string_view::npos || close <= 1 ||
                close + 1 >= spec.size() || spec[close + 1] != ':')
                return std::nullopt;
            host = spec.substr(1, close - 1);
            if (strict && (!host.contains(':') || host.contains('['))) return std::nullopt;
            port_text = spec.substr(close + 2);
        } else {
            auto colon = spec.rfind(':');
            if (colon == std::string_view::npos || colon == 0) return std::nullopt;
            if (strict && (spec.find(':') != colon || spec.contains('[') || spec.contains(']')))
                return std::nullopt;
            host = spec.substr(0, colon);
            port_text = spec.substr(colon + 1);
        }
        if (host.empty() || port_text.empty() || port_text.size() > 5 ||
            (strict && port_text.front() == '0'))
            return std::nullopt;
        for (unsigned char c : port_text)
            if (c < '0' || c > '9') return std::nullopt;
        unsigned port = 0;
        auto [end, ec] = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
        if (ec != std::errc{} || end != port_text.data() + port_text.size() || !port || port > 65535u)
            return std::nullopt;
        return HostPortView{host, static_cast<std::uint16_t>(port)};
    }
}
