// Wire header and flow-control codecs for xtaci/sagernet smux v1 & v2 (little-endian).
export module mux.smux_wire;
import std;
import encoding.endian;

export namespace mux::smux {
    inline constexpr std::uint8_t version_1 = 1;
    inline constexpr std::uint8_t version_2 = 2;
    inline constexpr std::size_t header_size = 8;
    inline constexpr std::size_t upd_payload_size = 8;
    inline constexpr std::size_t default_max_frame_size = 32768;
    inline constexpr std::uint32_t initial_peer_window = 262144;

    enum class Command : std::uint8_t {
        syn = 0,
        fin = 1,
        psh = 2,
        nop = 3,
        upd = 4,
    };

    struct FrameHeader {
        std::uint8_t version = version_2;
        Command cmd = Command::nop;
        std::uint16_t length = 0;
        std::uint32_t stream_id = 0;
        auto operator==(FrameHeader const&) const -> bool = default;
    };

    struct UpdPayload {
        std::uint32_t consumed = 0;
        std::uint32_t window = initial_peer_window;
        auto operator==(UpdPayload const&) const -> bool = default;
    };

    [[nodiscard]] inline constexpr auto read_le16(std::span<std::uint8_t const, 2> in) noexcept -> std::uint16_t {
        return encoding::read_le16(in);
    }

    [[nodiscard]] inline constexpr auto read_le32(std::span<std::uint8_t const, 4> in) noexcept -> std::uint32_t {
        return encoding::read_le32(in);
    }

    inline constexpr auto write_le16(std::span<std::uint8_t, 2> out, std::uint16_t v) noexcept -> void {
        encoding::write_le16(out, v);
    }

    inline constexpr auto write_le32(std::span<std::uint8_t, 4> out, std::uint32_t v) noexcept -> void {
        encoding::write_le32(out, v);
    }

    [[nodiscard]] inline constexpr auto encode_header(FrameHeader const& hdr) noexcept
        -> std::array<std::uint8_t, header_size> {
        std::array<std::uint8_t, header_size> out{};
        out[0] = hdr.version;
        out[1] = static_cast<std::uint8_t>(hdr.cmd);
        write_le16(std::span<std::uint8_t, 2>(out.data() + 2, 2), hdr.length);
        write_le32(std::span<std::uint8_t, 4>(out.data() + 4, 4), hdr.stream_id);
        return out;
    }

    [[nodiscard]] inline auto decode_header(std::span<std::uint8_t const, header_size> wire)
        -> std::expected<FrameHeader, std::string> {
        std::uint8_t ver = wire[0];
        if (ver != version_1 && ver != version_2)
            return std::unexpected("unsupported smux version");
        std::uint8_t cmd_raw = wire[1];
        if (cmd_raw > static_cast<std::uint8_t>(Command::upd))
            return std::unexpected("unknown smux command");
        auto cmd = static_cast<Command>(cmd_raw);
        auto len = read_le16(std::span<std::uint8_t const, 2>(wire.data() + 2, 2));
        auto sid = read_le32(std::span<std::uint8_t const, 4>(wire.data() + 4, 4));
        if (cmd == Command::upd) {
            if (ver != version_2)
                return std::unexpected("smux cmdUPD requires protocol version 2");
            if (len != upd_payload_size)
                return std::unexpected("invalid smux cmdUPD payload length");
        } else if (cmd == Command::syn || cmd == Command::fin || cmd == Command::nop) {
            if (len != 0)
                return std::unexpected("unexpected payload in smux control frame");
        }
        return FrameHeader{ver, cmd, len, sid};
    }

    [[nodiscard]] inline constexpr auto encode_upd(UpdPayload const& upd) noexcept
        -> std::array<std::uint8_t, upd_payload_size> {
        std::array<std::uint8_t, upd_payload_size> out{};
        write_le32(std::span<std::uint8_t, 4>(out.data(), 4), upd.consumed);
        write_le32(std::span<std::uint8_t, 4>(out.data() + 4, 4), upd.window);
        return out;
    }

    [[nodiscard]] inline constexpr auto decode_upd(std::span<std::uint8_t const, upd_payload_size> wire) noexcept
        -> UpdPayload {
        return UpdPayload{
            read_le32(std::span<std::uint8_t const, 4>(wire.data(), 4)),
            read_le32(std::span<std::uint8_t const, 4>(wire.data() + 4, 4)),
        };
    }
}
