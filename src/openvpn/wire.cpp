module openvpn.wire;
import std;
import crypto;

namespace openvpn {
    namespace {
        auto write_be32(std::vector<std::uint8_t>& out, std::uint32_t v) -> void {
            out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xff));
            out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xff));
            out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
            out.push_back(static_cast<std::uint8_t>(v & 0xff));
        }

        auto write_be64(std::vector<std::uint8_t>& out, std::uint64_t v) -> void {
            for (int shift = 56; shift >= 0; shift -= 8) {
                out.push_back(static_cast<std::uint8_t>((v >> shift) & 0xff));
            }
        }

        [[nodiscard]] auto read_be32(std::span<std::uint8_t const> s) noexcept -> std::uint32_t {
            return (static_cast<std::uint32_t>(s[0]) << 24) |
                   (static_cast<std::uint32_t>(s[1]) << 16) |
                   (static_cast<std::uint32_t>(s[2]) << 8) |
                   static_cast<std::uint32_t>(s[3]);
        }

        [[nodiscard]] auto read_be64(std::span<std::uint8_t const> s) noexcept -> std::uint64_t {
            std::uint64_t v = 0;
            for (std::size_t i = 0; i < 8; ++i) v = (v << 8) | s[i];
            return v;
        }

        [[nodiscard]] auto valid_control_opcode(std::uint8_t raw) noexcept -> std::optional<Opcode> {
            switch (raw) {
            case 4: return Opcode::control_v1;
            case 5: return Opcode::ack_v1;
            case 7: return Opcode::control_hard_reset_client_v2;
            case 8: return Opcode::control_hard_reset_server_v2;
            default: return std::nullopt;
            }
        }
    }

    auto ReplayWindow::check_and_accept(std::uint32_t packet_id) noexcept -> bool {
        if (packet_id == 0) return false;
        if (!initialized_) {
            initialized_ = true;
            highest_ = packet_id;
            bitmap_ = 1ull;
            return true;
        }
        if (packet_id > highest_) {
            auto diff = packet_id - highest_;
            bitmap_ = (diff >= 64) ? 1ull : ((bitmap_ << diff) | 1ull);
            highest_ = packet_id;
            return true;
        }
        auto diff = highest_ - packet_id;
        if (diff >= 64) return false;
        auto mask = 1ull << diff;
        if ((bitmap_ & mask) != 0) return false;
        bitmap_ |= mask;
        return true;
    }

    auto encode_control_packet(ControlPacket const& pkt) -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (pkt.opcode == Opcode::data_v2) return std::unexpected("data_v2 cannot use control encoder");
        if (pkt.key_id > 7) return std::unexpected("invalid OpenVPN key_id");
        if (pkt.acks.size() > 255) return std::unexpected("too many OpenVPN ACKs");
        if (pkt.opcode != Opcode::ack_v1 && !pkt.packet_id.has_value()) {
            return std::unexpected("control packet requires packet_id");
        }
        std::vector<std::uint8_t> out;
        out.reserve(16 + pkt.acks.size() * 4 + pkt.payload.size());
        auto const header = static_cast<std::uint8_t>((static_cast<std::uint8_t>(pkt.opcode) << 3) | (pkt.key_id & 0x07));
        out.push_back(header);
        write_be64(out, pkt.session_id);
        out.push_back(static_cast<std::uint8_t>(pkt.acks.size()));
        for (auto ack : pkt.acks) write_be32(out, ack);
        if (!pkt.acks.empty()) write_be64(out, pkt.remote_session_id);
        if (pkt.opcode != Opcode::ack_v1) {
            write_be32(out, *pkt.packet_id);
            out.insert(out.end(), pkt.payload.begin(), pkt.payload.end());
        }
        return out;
    }

    auto decode_control_packet(std::span<std::uint8_t const> wire) -> std::expected<ControlPacket, std::string> {
        if (wire.size() < 10) return std::unexpected("truncated OpenVPN packet");
        auto const raw_op = static_cast<std::uint8_t>((wire[0] >> 3) & 0x1f);
        auto op = valid_control_opcode(raw_op);
        if (!op) return std::unexpected("unsupported OpenVPN control opcode");

        ControlPacket pkt;
        pkt.opcode = *op;
        pkt.key_id = static_cast<std::uint8_t>(wire[0] & 0x07);
        pkt.session_id = read_be64(wire.subspan(1, 8));
        std::size_t const ack_count = wire[9];
        std::size_t off = 10;
        if (wire.size() < off + ack_count * 4 + (ack_count > 0 ? 8 : 0)) {
            return std::unexpected("truncated OpenVPN ACK block");
        }
        pkt.acks.reserve(ack_count);
        for (std::size_t i = 0; i < ack_count; ++i) {
            pkt.acks.push_back(read_be32(wire.subspan(off, 4)));
            off += 4;
        }
        if (ack_count > 0) {
            pkt.remote_session_id = read_be64(wire.subspan(off, 8));
            off += 8;
        }
        if (*op == Opcode::ack_v1) {
            if (off != wire.size()) return std::unexpected("unexpected trailing bytes in ack_v1");
            return pkt;
        }
        if (wire.size() < off + 4) return std::unexpected("missing control message packet_id");
        pkt.packet_id = read_be32(wire.subspan(off, 4));
        off += 4;
        pkt.payload.assign(wire.begin() + static_cast<std::ptrdiff_t>(off), wire.end());
        return pkt;
    }

    auto derive_data_keys(std::span<std::uint8_t const> master_secret,
                          std::span<std::uint8_t const> client_random,
                          std::span<std::uint8_t const> server_random,
                          bool server_role) -> std::expected<KeyMaterial, std::string> {
        if (master_secret.empty() || client_random.empty() || server_random.empty()) {
            return std::unexpected("empty key derivation input");
        }
        std::vector<std::uint8_t> salt;
        salt.reserve(client_random.size() + server_random.size());
        salt.insert(salt.end(), client_random.begin(), client_random.end());
        salt.insert(salt.end(), server_random.begin(), server_random.end());
        auto prk = crypto::hkdf_extract(crypto::Hash::sha256, salt, master_secret);
        if (!prk) return std::unexpected("hkdf_extract failed");
        constexpr std::string_view kInfo = "Nexus OpenVPN v2 data keys";
        auto expanded = crypto::hkdf_expand(
            crypto::Hash::sha256, *prk,
            std::span(reinterpret_cast<std::uint8_t const*>(kInfo.data()), kInfo.size()), 80);
        if (!expanded || expanded->size() != 80) return std::unexpected("hkdf_expand failed");

        KeyMaterial km;
        auto const& b = *expanded;
        if (!server_role) {
            std::copy_n(b.begin(), 32, km.tx_key.begin());
            std::copy_n(b.begin() + 32, 32, km.rx_key.begin());
            std::copy_n(b.begin() + 64, 8, km.tx_iv.begin());
            std::copy_n(b.begin() + 72, 8, km.rx_iv.begin());
        } else {
            std::copy_n(b.begin(), 32, km.rx_key.begin());
            std::copy_n(b.begin() + 32, 32, km.tx_key.begin());
            std::copy_n(b.begin() + 64, 8, km.rx_iv.begin());
            std::copy_n(b.begin() + 72, 8, km.tx_iv.begin());
        }
        return km;
    }
}
