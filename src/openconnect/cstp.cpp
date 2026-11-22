module openconnect.cstp;
import std;

namespace openconnect {
    namespace {
        [[nodiscard]] auto valid_cstp_type(std::uint8_t t) noexcept -> std::optional<CstpType> {
            switch (t) {
            case 0x00: return CstpType::data;
            case 0x03: return CstpType::dpd_req;
            case 0x04: return CstpType::dpd_resp;
            case 0x05: return CstpType::disconnect;
            case 0x07: return CstpType::keepalive;
            case 0x08: return CstpType::compressed;
            default: return std::nullopt;
            }
        }
    }

    auto encode_cstp_frame(CstpType type, std::span<std::uint8_t const> payload)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (payload.size() > 65535) return std::unexpected("CSTP frame payload exceeds 64KiB");
        std::vector<std::uint8_t> out(8 + payload.size());
        out[0] = 'S';
        out[1] = 'T';
        out[2] = 'F';
        out[3] = 0x01;
        out[4] = static_cast<std::uint8_t>((payload.size() >> 8) & 0xff);
        out[5] = static_cast<std::uint8_t>(payload.size() & 0xff);
        out[6] = static_cast<std::uint8_t>(type);
        out[7] = 0x00;
        std::ranges::copy(payload, out.begin() + 8);
        return out;
    }

    auto decode_cstp_frame(std::span<std::uint8_t const> buffer)
        -> std::expected<std::pair<CstpFrame, std::size_t>, std::string> {
        if (buffer.size() < 8) return std::unexpected("incomplete");
        if (buffer[0] != 'S' || buffer[1] != 'T' || buffer[2] != 'F' || buffer[3] != 0x01) {
            return std::unexpected("invalid CSTP magic header");
        }
        std::size_t const len = (static_cast<std::size_t>(buffer[4]) << 8) | buffer[5];
        auto type = valid_cstp_type(buffer[6]);
        if (!type) return std::unexpected("unknown CSTP frame type");
        if (buffer.size() < 8 + len) return std::unexpected("incomplete");
        CstpFrame frame{
            .type = *type,
            .payload = std::vector<std::uint8_t>(buffer.begin() + 8, buffer.begin() + static_cast<std::ptrdiff_t>(8 + len)),
        };
        return std::pair{std::move(frame), 8 + len};
    }

    auto Session::on_connected(bool has_dtls_session) noexcept -> void {
        state_ = State::connected;
        dtls_active_ = has_dtls_session;
        ++generation_;
    }

    auto Session::handle_frame(CstpFrame const& frame) -> std::optional<CstpFrame> {
        ++rx_frames_;
        if (frame.type == CstpType::dpd_req) {
            ++tx_frames_;
            return CstpFrame{.type = CstpType::dpd_resp, .payload = frame.payload};
        }
        if (frame.type == CstpType::disconnect) {
            dtls_active_ = false;
            state_ = State::reconnecting;
        }
        return std::nullopt;
    }

    auto Session::make_dpd_req() -> CstpFrame {
        ++tx_frames_;
        return CstpFrame{.type = CstpType::dpd_req, .payload = {}};
    }

    auto Session::make_keepalive() -> CstpFrame {
        ++tx_frames_;
        return CstpFrame{.type = CstpType::keepalive, .payload = {}};
    }

    auto Session::trigger_reconnect() noexcept -> void {
        dtls_active_ = false;
        state_ = State::reconnecting;
    }
}
