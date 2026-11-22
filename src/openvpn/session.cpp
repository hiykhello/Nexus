module openvpn.session;
import std;
import crypto;
import crypto.aead_context;

namespace openvpn {
    namespace {
        [[nodiscard]] auto to_crypto_aead(Cipher c) noexcept -> crypto::Aead {
            return c == Cipher::chacha20_poly1305 ? crypto::Aead::chacha20_poly1305 : crypto::Aead::aes_256_gcm;
        }

        auto make_nonce(std::uint32_t pid, std::span<std::uint8_t const, 8> iv) noexcept -> std::array<std::uint8_t, 12> {
            std::array<std::uint8_t, 12> nonce{};
            nonce[0] = static_cast<std::uint8_t>((pid >> 24) & 0xff);
            nonce[1] = static_cast<std::uint8_t>((pid >> 16) & 0xff);
            nonce[2] = static_cast<std::uint8_t>((pid >> 8) & 0xff);
            nonce[3] = static_cast<std::uint8_t>(pid & 0xff);
            std::ranges::copy(iv, nonce.begin() + 4);
            return nonce;
        }
    }

    auto DataChannel::init(Cipher cipher, KeyMaterial const& keys,
                           std::uint32_t peer_id, std::uint8_t key_id) -> std::expected<void, std::string> {
        if (key_id > 7 || (peer_id & 0xff000000u) != 0) {
            return std::unexpected("invalid OpenVPN key_id or 24-bit peer_id");
        }
        auto const alg = to_crypto_aead(cipher);
        if (!tx_aead_.reset(alg, keys.tx_key) || !rx_aead_.reset(alg, keys.rx_key)) {
            ready_ = false;
            return std::unexpected("failed to initialize OpenVPN AEAD contexts");
        }
        cipher_ = cipher;
        peer_id_ = peer_id;
        key_id_ = key_id;
        tx_iv_ = keys.tx_iv;
        rx_iv_ = keys.rx_iv;
        rx_replay_.reset();
        tx_packet_id_ = 0;
        ready_ = true;
        return {};
    }

    auto DataChannel::seal_data_v2(std::span<std::uint8_t const> plaintext)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (!ready_) return std::unexpected("OpenVPN data channel not initialized");
        std::uint32_t const pid = ++tx_packet_id_;
        if (pid == 0) return std::unexpected("OpenVPN packet_id wrapped; rekey required");

        std::vector<std::uint8_t> out(8 + plaintext.size() + 16);
        out[0] = static_cast<std::uint8_t>((static_cast<std::uint8_t>(Opcode::data_v2) << 3) | (key_id_ & 0x07));
        out[1] = static_cast<std::uint8_t>((peer_id_ >> 16) & 0xff);
        out[2] = static_cast<std::uint8_t>((peer_id_ >> 8) & 0xff);
        out[3] = static_cast<std::uint8_t>(peer_id_ & 0xff);
        out[4] = static_cast<std::uint8_t>((pid >> 24) & 0xff);
        out[5] = static_cast<std::uint8_t>((pid >> 16) & 0xff);
        out[6] = static_cast<std::uint8_t>((pid >> 8) & 0xff);
        out[7] = static_cast<std::uint8_t>(pid & 0xff);

        auto nonce = make_nonce(pid, tx_iv_);
        auto aad = std::span(out).first(8);
        auto written = tx_aead_.seal_to(std::span(out).subspan(8), nonce, plaintext, aad);
        if (!written) return std::unexpected("OpenVPN AEAD seal failed");
        out.resize(8 + *written);
        return out;
    }

    auto DataChannel::open_data_v2(std::span<std::uint8_t const> frame)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (!ready_) return std::unexpected("OpenVPN data channel not initialized");
        if (frame.size() < 8 + 16) return std::unexpected("truncated OpenVPN P_DATA_V2 frame");
        auto const op = static_cast<std::uint8_t>((frame[0] >> 3) & 0x1f);
        auto const kid = static_cast<std::uint8_t>(frame[0] & 0x07);
        std::uint32_t const pid_peer = (static_cast<std::uint32_t>(frame[1]) << 16) |
                                       (static_cast<std::uint32_t>(frame[2]) << 8) |
                                       static_cast<std::uint32_t>(frame[3]);
        if (op != static_cast<std::uint8_t>(Opcode::data_v2) || kid != key_id_ || pid_peer != peer_id_) {
            return std::unexpected("OpenVPN P_DATA_V2 header mismatch");
        }
        std::uint32_t const pkt_id = (static_cast<std::uint32_t>(frame[4]) << 24) |
                                     (static_cast<std::uint32_t>(frame[5]) << 16) |
                                     (static_cast<std::uint32_t>(frame[6]) << 8) |
                                     static_cast<std::uint32_t>(frame[7]);
        auto nonce = make_nonce(pkt_id, rx_iv_);
        auto aad = frame.first(8);
        auto ct = frame.subspan(8);
        std::vector<std::uint8_t> plain(ct.size() - 16);
        auto n = rx_aead_.open_to(plain, nonce, ct, aad);
        if (!n) return std::unexpected("OpenVPN AEAD authentication failed");
        if (!rx_replay_.check_and_accept(pkt_id)) {
            return std::unexpected("OpenVPN replayed packet_id rejected");
        }
        plain.resize(*n);
        return plain;
    }

    auto SessionStateMachine::begin_connect() -> std::expected<ControlPacket, std::string> {
        if (config_.remote_host.empty() || config_.remote_port == 0) {
            return std::unexpected("invalid OpenVPN remote endpoint");
        }
        state_ = SessionState::hard_reset_sent;
        remote_session_id_ = 0;
        next_control_pid_ = 0;
        pending_acks_.clear();
        ++generation_;
        return ControlPacket{
            .opcode = Opcode::control_hard_reset_client_v2,
            .key_id = 0,
            .session_id = local_session_id_,
            .packet_id = 0,
        };
    }

    auto SessionStateMachine::on_control_packet(ControlPacket const& pkt) -> std::expected<void, std::string> {
        if (pkt.opcode == Opcode::control_hard_reset_server_v2) {
            if (state_ != SessionState::hard_reset_sent && state_ != SessionState::reconnecting) {
                return std::unexpected("unexpected server hard reset");
            }
            remote_session_id_ = pkt.session_id;
            state_ = SessionState::tls_handshake;
        } else if (pkt.opcode == Opcode::control_v1) {
            if (remote_session_id_ != 0 && pkt.session_id != remote_session_id_) {
                return std::unexpected("remote session_id mismatch");
            }
        }
        if (pkt.packet_id.has_value()) {
            pending_acks_.push_back(*pkt.packet_id);
        }
        return {};
    }

    auto SessionStateMachine::make_control_message(std::vector<std::uint8_t> tls_bytes)
        -> std::expected<ControlPacket, std::string> {
        if (state_ != SessionState::tls_handshake && state_ != SessionState::established) {
            return std::unexpected("cannot send control TLS payload before handshake");
        }
        ControlPacket pkt{
            .opcode = Opcode::control_v1,
            .key_id = 0,
            .session_id = local_session_id_,
            .acks = std::exchange(pending_acks_, {}),
            .remote_session_id = remote_session_id_,
            .packet_id = ++next_control_pid_,
            .payload = std::move(tls_bytes),
        };
        return pkt;
    }

    auto SessionStateMachine::make_ack() -> std::optional<ControlPacket> {
        if (pending_acks_.empty() || remote_session_id_ == 0) return std::nullopt;
        return ControlPacket{
            .opcode = Opcode::ack_v1,
            .key_id = 0,
            .session_id = local_session_id_,
            .acks = std::exchange(pending_acks_, {}),
            .remote_session_id = remote_session_id_,
        };
    }

    auto SessionStateMachine::trigger_reconnect(std::uint64_t new_local_sid) -> ControlPacket {
        local_session_id_ = new_local_sid;
        remote_session_id_ = 0;
        next_control_pid_ = 0;
        pending_acks_.clear();
        state_ = SessionState::reconnecting;
        ++generation_;
        return ControlPacket{
            .opcode = Opcode::control_hard_reset_client_v2,
            .key_id = 0,
            .session_id = local_session_id_,
            .packet_id = 0,
        };
    }
}
