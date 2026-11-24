export module encoding.endian;
import std;

export namespace encoding {
    [[nodiscard]] inline constexpr auto read_be16(std::span<std::uint8_t const, 2> in) noexcept -> std::uint16_t {
        return static_cast<std::uint16_t>((static_cast<std::uint16_t>(in[0]) << 8) | in[1]);
    }

    [[nodiscard]] inline constexpr auto read_be32(std::span<std::uint8_t const, 4> in) noexcept -> std::uint32_t {
        return (static_cast<std::uint32_t>(in[0]) << 24) | (static_cast<std::uint32_t>(in[1]) << 16) |
               (static_cast<std::uint32_t>(in[2]) << 8) | static_cast<std::uint32_t>(in[3]);
    }

    [[nodiscard]] inline constexpr auto read_be64(std::span<std::uint8_t const, 8> in) noexcept -> std::uint64_t {
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < 8; ++i) v = (v << 8) | in[i];
        return v;
    }

    inline constexpr auto write_be16(std::span<std::uint8_t, 2> out, std::uint16_t v) noexcept -> void {
        out[0] = static_cast<std::uint8_t>((v >> 8) & 0xffu);
        out[1] = static_cast<std::uint8_t>(v & 0xffu);
    }

    inline constexpr auto write_be32(std::span<std::uint8_t, 4> out, std::uint32_t v) noexcept -> void {
        out[0] = static_cast<std::uint8_t>((v >> 24) & 0xffu);
        out[1] = static_cast<std::uint8_t>((v >> 16) & 0xffu);
        out[2] = static_cast<std::uint8_t>((v >> 8) & 0xffu);
        out[3] = static_cast<std::uint8_t>(v & 0xffu);
    }

    inline constexpr auto write_be64(std::span<std::uint8_t, 8> out, std::uint64_t v) noexcept -> void {
        for (std::size_t i = 0; i < 8; ++i) out[i] = static_cast<std::uint8_t>((v >> ((7 - i) * 8)) & 0xffu);
    }

    inline auto append_be16(std::vector<std::uint8_t>& out, std::uint16_t v) -> void {
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xffu));
        out.push_back(static_cast<std::uint8_t>(v & 0xffu));
    }

    inline auto append_be32(std::vector<std::uint8_t>& out, std::uint32_t v) -> void {
        out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xffu));
        out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xffu));
        out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xffu));
        out.push_back(static_cast<std::uint8_t>(v & 0xffu));
    }

    inline auto append_be64(std::vector<std::uint8_t>& out, std::uint64_t v) -> void {
        for (int shift = 56; shift >= 0; shift -= 8)
            out.push_back(static_cast<std::uint8_t>((v >> shift) & 0xffu));
    }

    [[nodiscard]] inline constexpr auto read_le16(std::span<std::uint8_t const, 2> in) noexcept -> std::uint16_t {
        return static_cast<std::uint16_t>(in[0]) | (static_cast<std::uint16_t>(in[1]) << 8);
    }

    [[nodiscard]] inline constexpr auto read_le32(std::span<std::uint8_t const, 4> in) noexcept -> std::uint32_t {
        return static_cast<std::uint32_t>(in[0]) | (static_cast<std::uint32_t>(in[1]) << 8) |
               (static_cast<std::uint32_t>(in[2]) << 16) | (static_cast<std::uint32_t>(in[3]) << 24);
    }

    [[nodiscard]] inline constexpr auto read_le64(std::span<std::uint8_t const, 8> in) noexcept -> std::uint64_t {
        std::uint64_t v = 0;
        for (std::size_t i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(in[i]) << (8 * i);
        return v;
    }

    inline constexpr auto write_le16(std::span<std::uint8_t, 2> out, std::uint16_t v) noexcept -> void {
        out[0] = static_cast<std::uint8_t>(v & 0xffu);
        out[1] = static_cast<std::uint8_t>((v >> 8) & 0xffu);
    }

    inline constexpr auto write_le32(std::span<std::uint8_t, 4> out, std::uint32_t v) noexcept -> void {
        out[0] = static_cast<std::uint8_t>(v & 0xffu);
        out[1] = static_cast<std::uint8_t>((v >> 8) & 0xffu);
        out[2] = static_cast<std::uint8_t>((v >> 16) & 0xffu);
        out[3] = static_cast<std::uint8_t>((v >> 24) & 0xffu);
    }

    inline constexpr auto write_le64(std::span<std::uint8_t, 8> out, std::uint64_t v) noexcept -> void {
        for (std::size_t i = 0; i < 8; ++i) out[i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xffu);
    }
}
