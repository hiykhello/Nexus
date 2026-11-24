module openvpn.control;
import std;
import crypto;
import encoding.hex;

namespace openvpn {
    auto ControlChannel::retire_acks(ControlPacket const& pkt) -> void {
        if (pkt.acks.empty() || !handshake_started_ || pkt.session_id != remote_sid_ ||
            pkt.remote_session_id != local_sid_) return;
        for (auto ack : pkt.acks) {
            std::erase_if(unacked_, [ack](auto const& u) { return u.pkt.packet_id == ack; });
        }
    }

    auto ControlChannel::begin_client_reset(std::uint64_t now_ms) -> ControlPacket {
        ControlPacket pkt{
            .opcode = Opcode::control_hard_reset_client_v2,
            .key_id = 0,
            .session_id = local_sid_,
            .packet_id = 0,
        };
        if (unacked_.size() < 64) unacked_.push_back({pkt, now_ms});
        return pkt;
    }

    auto ControlChannel::make_server_reset(std::uint64_t now_ms) -> ControlPacket {
        ControlPacket pkt{
            .opcode = Opcode::control_hard_reset_server_v2,
            .key_id = 0,
            .session_id = local_sid_,
            .acks = std::exchange(pending_acks_, {}),
            .remote_session_id = remote_sid_,
            .packet_id = 0,
        };
        if (unacked_.size() < 64) unacked_.push_back({pkt, now_ms});
        return pkt;
    }

    auto ControlChannel::on_packet(ControlPacket const& pkt, std::uint64_t now_ms)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        (void)now_ms;
        if (pkt.session_id == 0) return std::unexpected("invalid zero OpenVPN session_id");
        auto record_ack = [&](std::uint32_t pid) {
            if (std::ranges::contains(pending_acks_, pid)) return;
            if (pending_acks_.size() >= 255) pending_acks_.erase(pending_acks_.begin());
            pending_acks_.push_back(pid);
        };
        if (pkt.opcode == Opcode::ack_v1) {
            retire_acks(pkt);
            return std::vector<std::uint8_t>{};
        }

        if (!server_role_ && pkt.opcode == Opcode::control_hard_reset_server_v2) {
            if (!handshake_started_) {
                remote_sid_ = pkt.session_id;
                handshake_started_ = true;
            } else if (pkt.session_id != remote_sid_) {
                return std::unexpected("OpenVPN server session_id mismatch");
            }
            retire_acks(pkt);
            if (pkt.packet_id) record_ack(*pkt.packet_id);
            return std::vector<std::uint8_t>{};
        }

        if (server_role_ && pkt.opcode == Opcode::control_hard_reset_client_v2) {
            if (!handshake_started_) {
                remote_sid_ = pkt.session_id;
                handshake_started_ = true;
            } else if (pkt.session_id != remote_sid_) {
                return std::unexpected("OpenVPN client session_id mismatch");
            }
            retire_acks(pkt);
            if (pkt.packet_id) record_ack(*pkt.packet_id);
            return std::vector<std::uint8_t>{};
        }

        if (pkt.opcode == Opcode::control_v1) {
            if (!handshake_started_ || pkt.session_id != remote_sid_ || !pkt.packet_id)
                return std::unexpected("unexpected OpenVPN P_CONTROL_V1 packet");
            retire_acks(pkt);
            record_ack(*pkt.packet_id);
            std::uint32_t pid = *pkt.packet_id;
            if (pid >= expected_rx_pid_) {
                if (pid != expected_rx_pid_ && rx_reorder_.size() >= 32 && !rx_reorder_.contains(pid))
                    return std::unexpected("OpenVPN control reorder buffer full");
                rx_reorder_.try_emplace(pid, pkt.payload);
            }
            std::vector<std::uint8_t> delivered;
            for (auto it = rx_reorder_.find(expected_rx_pid_); it != rx_reorder_.end();
                 it = rx_reorder_.find(expected_rx_pid_)) {
                delivered.insert(delivered.end(), it->second.begin(), it->second.end());
                rx_reorder_.erase(it);
                ++expected_rx_pid_;
            }
            return delivered;
        }
        return std::vector<std::uint8_t>{};
    }

    auto ControlChannel::enqueue_tls_bytes(std::span<std::uint8_t const> data, std::uint64_t now_ms)
        -> std::vector<ControlPacket> {
        std::vector<ControlPacket> out;
        if (data.empty() || data.size() > 64u * 1000u) return out;
        std::size_t const chunks = (data.size() + 999u) / 1000u;
        if (unacked_.size() > 64u - chunks) return out;
        std::size_t off = 0;
        while (off < data.size()) {
            std::size_t chunk = std::min<std::size_t>(data.size() - off, 1000);
            ControlPacket pkt{
                .opcode = Opcode::control_v1,
                .key_id = 0,
                .session_id = local_sid_,
                .acks = std::exchange(pending_acks_, {}),
                .remote_session_id = remote_sid_,
                .packet_id = next_tx_pid_++,
                .payload = std::vector<std::uint8_t>(data.begin() + static_cast<std::ptrdiff_t>(off),
                                                     data.begin() + static_cast<std::ptrdiff_t>(off + chunk)),
            };
            unacked_.push_back({pkt, now_ms});
            out.push_back(std::move(pkt));
            off += chunk;
        }
        return out;
    }

    auto ControlChannel::take_ack() -> std::optional<ControlPacket> {
        if (pending_acks_.empty() || remote_sid_ == 0) return std::nullopt;
        return ControlPacket{
            .opcode = Opcode::ack_v1,
            .key_id = 0,
            .session_id = local_sid_,
            .acks = std::exchange(pending_acks_, {}),
            .remote_session_id = remote_sid_,
        };
    }

    auto ControlChannel::retransmit_due(std::uint64_t now_ms, std::uint64_t rto_ms) -> std::vector<ControlPacket> {
        std::vector<ControlPacket> out;
        for (auto& u : unacked_) {
            if (now_ms >= u.last_sent_ms && now_ms - u.last_sent_ms >= rto_ms) {
                if (!pending_acks_.empty() && remote_sid_ != 0) {
                    u.pkt.acks = std::exchange(pending_acks_, {});
                    u.pkt.remote_session_id = remote_sid_;
                }
                u.last_sent_ms = now_ms;
                out.push_back(u.pkt);
            }
        }
        return out;
    }

    auto parse_static_key_v1(std::string_view pem) -> std::expected<std::array<std::uint8_t, 256>, std::string> {
        constexpr std::string_view begin_mark = "-----BEGIN OpenVPN Static key V1-----";
        constexpr std::string_view end_mark = "-----END OpenVPN Static key V1-----";
        auto bpos = pem.find(begin_mark);
        if (bpos == std::string_view::npos) return std::unexpected("missing OpenVPN Static key V1 begin marker");
        bpos += begin_mark.size();
        auto epos = pem.find(end_mark, bpos);
        if (epos == std::string_view::npos) return std::unexpected("missing OpenVPN Static key V1 end marker");
        std::string hex;
        struct HexWipe {
            std::string& s;
            ~HexWipe() { if (!s.empty()) crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(s.data()), s.size())); }
        } hex_wipe{hex};
        hex.reserve(512);
        for (char c : pem.substr(bpos, epos - bpos)) {
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;
            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) hex.push_back(c);
            else return std::unexpected("invalid hex character in OpenVPN Static key V1");
        }
        if (hex.size() != 512) return std::unexpected("OpenVPN Static key V1 must be 512 hex chars");
        std::array<std::uint8_t, 256> out{};
        if (!encoding::hex_decode(hex, out))
            return std::unexpected("invalid hex character in OpenVPN Static key V1");
        return out;
    }
}
