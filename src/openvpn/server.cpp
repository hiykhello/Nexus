module openvpn.server;
import std;
import crypto;
import openvpn.types;
import openvpn.wire;
import openvpn.control;
import openvpn.session;
import openvpn.tls_crypt;

namespace openvpn {
    ServerSession::~ServerSession() { close(); }

    auto ServerSession::init(ServerOptions options, std::uint64_t server_session_id)
        -> std::expected<void, std::string> {
        close();
        if (options.peer_id > 0xffffffu) return std::unexpected("OpenVPN server peer-id out of range");
        if (options.require_client_cert && options.client_ca_pem.empty())
            return std::unexpected("OpenVPN server require_client_cert requires client_ca_pem");
        if (options.tls_auth_mode != TlsAuthMode::none) {
            auto parsed = parse_static_key_v1(options.static_key_pem);
            if (!options.static_key_pem.empty()) {
                crypto::cleanse(std::span<std::uint8_t>(
                    reinterpret_cast<std::uint8_t*>(options.static_key_pem.data()), options.static_key_pem.size()));
                options.static_key_pem.clear();
            }
            if (!parsed) return std::unexpected(parsed.error());
            struct KeyWipe { std::array<std::uint8_t, 256>& k; ~KeyWipe() { crypto::cleanse(k); } } wipe{*parsed};
            if (options.tls_auth_mode == TlsAuthMode::tls_auth) {
                if (!tls_auth_.init(*parsed, options.key_direction, true, options.tls_auth_sha1))
                    return std::unexpected("failed to init server tls-auth codec");
            } else {
                if (!tls_crypt_.init(*parsed, true))
                    return std::unexpected("failed to init server tls-crypt codec");
            }
        } else if (!options.static_key_pem.empty()) {
            crypto::cleanse(std::span<std::uint8_t>(
                reinterpret_cast<std::uint8_t*>(options.static_key_pem.data()), options.static_key_pem.size()));
            options.static_key_pem.clear();
        }
        if (server_session_id == 0) {
            std::array<std::uint8_t, 8> rnd{};
            if (!crypto::random_bytes(rnd)) return std::unexpected("RNG failure generating server session ID");
            for (auto b : rnd) server_session_id = (server_session_id << 8) | b;
            if (server_session_id == 0) server_session_id = 1;
        }
        options_ = std::move(options);
        if (!options_.push_config.peer_id) options_.push_config.peer_id = options_.peer_id;
        if (!options_.push_config.cipher) options_.push_config.cipher = options_.cipher;
        server_session_id_ = server_session_id;
        control_.emplace(server_session_id_, true);
        state_ = ServerState::awaiting_reset;
        return {};
    }

    auto ServerSession::wrap_control(std::span<std::uint8_t const> plain)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (options_.tls_auth_mode == TlsAuthMode::tls_auth) return tls_auth_.wrap(plain, current_timestamp_s_);
        if (options_.tls_auth_mode == TlsAuthMode::tls_crypt) return tls_crypt_.wrap(plain, current_timestamp_s_);
        return std::vector<std::uint8_t>(plain.begin(), plain.end());
    }

    auto ServerSession::unwrap_control(std::span<std::uint8_t const> wire)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (options_.tls_auth_mode == TlsAuthMode::tls_auth) return tls_auth_.unwrap(wire);
        if (options_.tls_auth_mode == TlsAuthMode::tls_crypt) return tls_crypt_.unwrap(wire);
        return std::vector<std::uint8_t>(wire.begin(), wire.end());
    }

    auto ServerSession::encode_and_wrap(ControlPacket const& pkt)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        auto raw = encode_control_packet(pkt);
        if (!raw) return std::unexpected(raw.error());
        return wrap_control(*raw);
    }

    auto ServerSession::verify_client_certificate(std::span<std::uint8_t const> leaf_der,
                                                  std::span<crypto::Bytes const> chain_der,
                                                  std::int64_t unix_time_s)
        -> std::expected<void, std::string> {
        if (state_ == ServerState::closed) return std::unexpected("session closed");
        if (leaf_der.empty()) return std::unexpected("empty mTLS client certificate");
        if (options_.client_ca_pem.empty())
            return std::unexpected("OpenVPN server mTLS verification requires client_ca_pem");
        auto ca_span = std::span<std::uint8_t const>(
            reinterpret_cast<std::uint8_t const*>(options_.client_ca_pem.data()),
            options_.client_ca_pem.size());
        if (auto v = verify_mtls_peer_chain(leaf_der, chain_der, ca_span, unix_time_s); !v)
            return std::unexpected(v.error());
        client_cert_der_.assign(leaf_der.begin(), leaf_der.end());
        client_cert_verified_ = true;
        return {};
    }

    auto ServerSession::on_tls_established() -> std::expected<void, std::string> {
        if (state_ == ServerState::closed) return std::unexpected("session closed");
        if (options_.require_client_cert && !client_cert_verified_)
            return std::unexpected("client mTLS certificate required but not verified");
        tls_ready_ = true;
        if (state_ == ServerState::tls_handshake) state_ = ServerState::awaiting_key_method2;
        return {};
    }

    auto ServerSession::on_wire_packet(std::span<std::uint8_t const> wire, std::uint64_t now_ms,
                                       std::uint32_t unix_time_s)
        -> std::expected<ServerStepOutput, std::string> {
        if (state_ == ServerState::closed || !control_) return std::unexpected("OpenVPN server session closed");
        if (wire.empty()) return std::unexpected("empty OpenVPN packet");
        if (current_timestamp_s_ == 0) {
            current_timestamp_s_ = unix_time_s > 0 ? unix_time_s : static_cast<std::uint32_t>(now_ms / 1000u);
        }

        ServerStepOutput out;
        auto opcode = static_cast<Opcode>(wire[0] >> 3);
        if (opcode == Opcode::data_v2) {
            if (state_ != ServerState::established || !data_ || !data_->ready())
                return std::unexpected("received P_DATA_V2 before session established");
            auto plain = data_->open_data_v2(wire);
            if (!plain) return std::unexpected(plain.error());
            if (plain->size() == ping_magic.size() &&
                std::equal(plain->begin(), plain->end(), ping_magic.begin())) {
                out.keepalive_received = true;
            } else if (!plain->empty()) {
                out.ip_packets.push_back(std::move(*plain));
            }
            return out;
        }

        auto plain_ctrl = unwrap_control(wire);
        if (!plain_ctrl) return std::unexpected(plain_ctrl.error());
        auto pkt = decode_control_packet(*plain_ctrl);
        if (!pkt) return std::unexpected(pkt.error());

        if (state_ == ServerState::awaiting_reset) {
            if (pkt->opcode != Opcode::control_hard_reset_client_v2)
                return std::unexpected("expected P_CONTROL_HARD_RESET_CLIENT_V2");
            auto chunk = control_->on_packet(*pkt, now_ms);
            if (!chunk) return std::unexpected(chunk.error());
            // Emit P_CONTROL_HARD_RESET_SERVER_V2 acknowledging client packet 0.
            auto srv_reset = control_->make_server_reset(now_ms);
            auto wrapped = encode_and_wrap(srv_reset);
            if (!wrapped) return std::unexpected(wrapped.error());
            out.wire_packets.push_back(std::move(*wrapped));
            state_ = ServerState::tls_handshake;
            return out;
        }

        auto chunk = control_->on_packet(*pkt, now_ms);
        if (!chunk) return std::unexpected(chunk.error());
        if (!chunk->empty()) out.tls_rx_bytes = std::move(*chunk);
        if (auto ack = control_->take_ack()) {
            auto wrapped = encode_and_wrap(*ack);
            if (!wrapped) return std::unexpected(wrapped.error());
            out.wire_packets.push_back(std::move(*wrapped));
        }
        return out;
    }

    auto ServerSession::enqueue_tls_tx(std::span<std::uint8_t const> tls_bytes, std::uint64_t now_ms,
                                       std::uint32_t unix_time_s)
        -> std::expected<std::vector<std::vector<std::uint8_t>>, std::string> {
        if (state_ == ServerState::closed || !control_) return std::unexpected("session closed");
        if (current_timestamp_s_ == 0 && unix_time_s > 0) current_timestamp_s_ = unix_time_s;
        auto pkts = control_->enqueue_tls_bytes(tls_bytes, now_ms);
        std::vector<std::vector<std::uint8_t>> out;
        out.reserve(pkts.size());
        for (auto const& p : pkts) {
            auto w = encode_and_wrap(p);
            if (!w) return std::unexpected(w.error());
            out.push_back(std::move(*w));
        }
        return out;
    }

    auto ServerSession::handle_key_method2(std::span<std::uint8_t const> payload, ServerStepOutput& out)
        -> std::expected<void, std::string> {
        auto cli = decode_key_method2_client(payload);
        if (!cli) return std::unexpected(cli.error());
        if (options_.auth_callback &&
            !options_.auth_callback(cli->username, cli->password, client_cert_der_)) {
            return std::unexpected("OpenVPN client authentication rejected");
        }
        authenticated_user_ = cli->username;

        KeyMethod2Server srv{};
        if (!crypto::random_bytes(srv.random1) || !crypto::random_bytes(srv.random2))
            return std::unexpected("RNG failure generating server key-method-2 randoms");
        srv.options = options_.server_options;
        auto srv_wire = encode_key_method2_server(srv);
        if (!srv_wire) return std::unexpected(srv_wire.error());

        auto km = derive_key_method2_keys(cli->pre_master, cli->random1, srv.random1,
                                          cli->random2, srv.random2,
                                          control_->remote_session_id(), control_->local_session_id(), true);
        if (!km) return std::unexpected(km.error());
        struct KmWipe {
            KeyMaterial& m;
            ~KmWipe() {
                crypto::cleanse(m.tx_key); crypto::cleanse(m.rx_key);
                crypto::cleanse(m.tx_iv); crypto::cleanse(m.rx_iv);
            }
        } km_wipe{*km};

        data_.emplace();
        if (!data_->init(options_.cipher, *km, options_.peer_id, 0)) {
            data_.reset();
            return std::unexpected("failed to initialize OpenVPN server DataChannel");
        }
        out.tls_tx_plaintext.insert(out.tls_tx_plaintext.end(), srv_wire->begin(), srv_wire->end());
        state_ = ServerState::awaiting_push_request;
        return {};
    }

    auto ServerSession::handle_push_request(ServerStepOutput& out) -> std::expected<void, std::string> {
        auto reply = encode_push_reply(options_.push_config);
        reply.push_back('\0');
        out.tls_tx_plaintext.insert(out.tls_tx_plaintext.end(),
            reinterpret_cast<std::uint8_t const*>(reply.data()),
            reinterpret_cast<std::uint8_t const*>(reply.data() + reply.size()));
        state_ = ServerState::established;
        return {};
    }

    auto ServerSession::on_tls_plaintext(std::span<std::uint8_t const> plaintext)
        -> std::expected<ServerStepOutput, std::string> {
        if (state_ == ServerState::closed || !tls_ready_)
            return std::unexpected("TLS control channel not ready");
        std::size_t const cap = (state_ == ServerState::awaiting_key_method2) ? 16384u : 4096u;
        if (plaintext.size() > cap || app_rx_buf_.size() > cap - plaintext.size()) {
            crypto::cleanse(app_rx_buf_);
            app_rx_buf_.clear();
            return std::unexpected("OpenVPN control plaintext exceeds buffer limit");
        }
        app_rx_buf_.insert(app_rx_buf_.end(), plaintext.begin(), plaintext.end());
        ServerStepOutput out;
        if (state_ == ServerState::awaiting_key_method2) {
            if (app_rx_buf_.size() < 119) return out;
            auto res = handle_key_method2(app_rx_buf_, out);
            crypto::cleanse(app_rx_buf_);
            app_rx_buf_.clear();
            if (!res) return std::unexpected(res.error());
            return out;
        }
        if (state_ == ServerState::awaiting_push_request || state_ == ServerState::established) {
            std::string_view sv(reinterpret_cast<char const*>(app_rx_buf_.data()), app_rx_buf_.size());
            if (sv.starts_with("PUSH_REQUEST")) {
                auto res = handle_push_request(out);
                crypto::cleanse(app_rx_buf_);
                app_rx_buf_.clear();
                if (!res) return std::unexpected(res.error());
            }
        }
        return out;
    }

    auto ServerSession::poll_retransmit(std::uint64_t now_ms, std::uint64_t rto_ms, std::uint32_t unix_time_s)
        -> std::expected<std::vector<std::vector<std::uint8_t>>, std::string> {
        if (state_ == ServerState::closed || !control_) return std::unexpected("session closed");
        if (current_timestamp_s_ == 0 && unix_time_s > 0) current_timestamp_s_ = unix_time_s;
        auto due = control_->retransmit_due(now_ms, rto_ms);
        std::vector<std::vector<std::uint8_t>> out;
        out.reserve(due.size());
        for (auto const& p : due) {
            auto w = encode_and_wrap(p);
            if (!w) return std::unexpected(w.error());
            out.push_back(std::move(*w));
        }
        return out;
    }

    auto ServerSession::seal_ip_packet(std::span<std::uint8_t const> ip_packet)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (state_ != ServerState::established || !data_ || !data_->ready())
            return std::unexpected("OpenVPN server session not established");
        return data_->seal_data_v2(ip_packet);
    }

    auto ServerSession::seal_keepalive() -> std::expected<std::vector<std::uint8_t>, std::string> {
        return seal_ip_packet(ping_magic);
    }

    auto ServerSession::close() noexcept -> void {
        state_ = ServerState::closed;
        data_.reset();
        control_.reset();
        crypto::cleanse(app_rx_buf_);
        app_rx_buf_.clear();
        if (!options_.static_key_pem.empty()) {
            crypto::cleanse(std::span<std::uint8_t>(
                reinterpret_cast<std::uint8_t*>(options_.static_key_pem.data()), options_.static_key_pem.size()));
            options_.static_key_pem.clear();
        }
        client_cert_der_.clear();
        client_cert_verified_ = false;
        tls_ready_ = false;
        current_timestamp_s_ = 0;
        authenticated_user_.clear();
    }
}
