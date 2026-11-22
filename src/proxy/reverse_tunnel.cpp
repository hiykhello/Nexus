module proxy.reverse_tunnel;
import std;

namespace proxy::reverse_tunnel {
    namespace {
        [[nodiscard]] auto constant_time_equal(std::string_view a, std::string_view b) noexcept -> bool {
            std::uint8_t diff = a.size() == b.size() ? 0 : 1;
            std::size_t const n = std::min(a.size(), b.size());
            for (std::size_t i = 0; i < n; ++i) {
                diff |= static_cast<std::uint8_t>(a[i]) ^ static_cast<std::uint8_t>(b[i]);
            }
            return diff == 0 && !a.empty();
        }

        [[nodiscard]] auto valid_kind(std::uint8_t k) noexcept -> std::optional<FrameKind> {
            return (k >= 1 && k <= 8) ? std::optional{static_cast<FrameKind>(k)} : std::nullopt;
        }
    }

    auto encode_frame(Frame const& f) -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (f.payload.size() > max_frame_payload) return std::unexpected("reverse-tunnel payload exceeds 64KiB");
        std::vector<std::uint8_t> out(12 + f.payload.size());
        out[0] = static_cast<std::uint8_t>((protocol_magic >> 8) & 0xff);
        out[1] = static_cast<std::uint8_t>(protocol_magic & 0xff);
        out[2] = protocol_version;
        out[3] = static_cast<std::uint8_t>(f.kind);
        out[4] = static_cast<std::uint8_t>((f.stream_id >> 24) & 0xff);
        out[5] = static_cast<std::uint8_t>((f.stream_id >> 16) & 0xff);
        out[6] = static_cast<std::uint8_t>((f.stream_id >> 8) & 0xff);
        out[7] = static_cast<std::uint8_t>(f.stream_id & 0xff);
        auto const len = static_cast<std::uint32_t>(f.payload.size());
        out[8] = static_cast<std::uint8_t>((len >> 24) & 0xff);
        out[9] = static_cast<std::uint8_t>((len >> 16) & 0xff);
        out[10] = static_cast<std::uint8_t>((len >> 8) & 0xff);
        out[11] = static_cast<std::uint8_t>(len & 0xff);
        std::ranges::copy(f.payload, out.begin() + 12);
        return out;
    }

    auto decode_frame(std::span<std::uint8_t const> wire)
        -> std::expected<std::pair<Frame, std::size_t>, std::string> {
        if (wire.size() < 12) return std::unexpected("incomplete");
        std::uint16_t const magic = static_cast<std::uint16_t>((static_cast<std::uint16_t>(wire[0]) << 8) | wire[1]);
        if (magic != protocol_magic || wire[2] != protocol_version) {
            return std::unexpected("invalid reverse-tunnel header");
        }
        auto kind = valid_kind(wire[3]);
        if (!kind) return std::unexpected("invalid reverse-tunnel frame kind");
        std::uint32_t const sid = (static_cast<std::uint32_t>(wire[4]) << 24) |
                                  (static_cast<std::uint32_t>(wire[5]) << 16) |
                                  (static_cast<std::uint32_t>(wire[6]) << 8) | wire[7];
        std::uint32_t const len = (static_cast<std::uint32_t>(wire[8]) << 24) |
                                  (static_cast<std::uint32_t>(wire[9]) << 16) |
                                  (static_cast<std::uint32_t>(wire[10]) << 8) | wire[11];
        if (len > max_frame_payload) return std::unexpected("reverse-tunnel frame too large");
        if (wire.size() < 12 + len) return std::unexpected("incomplete");
        Frame f{
            .kind = *kind,
            .stream_id = sid,
            .payload = std::vector<std::uint8_t>(wire.begin() + 12, wire.begin() + static_cast<std::ptrdiff_t>(12 + len)),
        };
        return std::pair{std::move(f), 12 + len};
    }

    auto TunnelSession::handle_register(std::string_view presented_token, std::int64_t now_ms) -> Frame {
        bool ok = constant_time_equal(expected_token_, presented_token);
        registered_ = ok;
        if (ok) {
            last_heartbeat_ms_ = now_ms;
            ++generation_;
        }
        return Frame{.kind = FrameKind::register_ack, .stream_id = 0, .payload = {static_cast<std::uint8_t>(ok ? 1 : 0)}};
    }

    auto TunnelSession::open_stream(std::uint32_t stream_id) -> std::expected<Frame, std::string> {
        if (!registered_) return std::unexpected("session not registered");
        if (stream_id == 0 || streams_.contains(stream_id)) return std::unexpected("invalid or duplicate stream_id");
        if (streams_.size() >= max_streams_) return std::unexpected("reverse-tunnel max_streams reached");
        streams_.emplace(stream_id, StreamState{.id = stream_id});
        return Frame{.kind = FrameKind::open_stream, .stream_id = stream_id};
    }

    auto TunnelSession::on_data(std::uint32_t stream_id, std::size_t bytes) -> std::expected<void, std::string> {
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) return std::unexpected("unknown stream");
        it->second.bytes_relayed += bytes;
        return {};
    }

    auto TunnelSession::close_local(std::uint32_t stream_id) -> std::expected<Frame, std::string> {
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) return std::unexpected("unknown stream");
        it->second.local_fin = true;
        if (it->second.remote_fin) streams_.erase(it);
        return Frame{.kind = FrameKind::half_close, .stream_id = stream_id};
    }

    auto TunnelSession::on_remote_half_close(std::uint32_t stream_id) -> std::expected<bool, std::string> {
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) return std::unexpected("unknown stream");
        it->second.remote_fin = true;
        bool both_closed = it->second.local_fin && it->second.remote_fin;
        if (both_closed) streams_.erase(it);
        return both_closed;
    }

    auto TunnelSession::on_heartbeat(std::int64_t now_ms) noexcept -> Frame {
        last_heartbeat_ms_ = now_ms;
        return Frame{.kind = FrameKind::pong, .stream_id = 0};
    }

    auto TunnelSession::heartbeat_expired(std::int64_t now_ms, std::chrono::milliseconds timeout) const noexcept -> bool {
        return registered_ && (now_ms - last_heartbeat_ms_ > timeout.count());
    }

    auto TunnelSession::reset_all_for_reconnect() noexcept -> void {
        registered_ = false;
        streams_.clear();
    }
}
