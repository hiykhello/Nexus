export module ssh.session;
import std;
import crypto;
export import ssh.wire;
export import ssh.crypto;
import capy;
import corosio;

export namespace ssh {
    using Clock = std::chrono::steady_clock;
    using Deadline = std::optional<Clock::time_point>;

    template<class Stream>
    class Session {
        enum class RekeyState { idle, sent_kexinit, in_progress };

        Stream& stream_;
        PacketCipher tx_, rx_;
        std::uint32_t send_seq_ = 0, recv_seq_ = 0;
        RekeyTracker rekey_{};
        std::array<std::uint8_t, 32> session_id_{};
        std::string server_banner_, cipher_list_;
        std::vector<std::array<std::uint8_t, 32>> host_key_sha256_;
        RxBuffer rx_buf_{};
        std::vector<std::uint8_t> rekey_ic_;
        std::array<ChannelSlot, kMaxChannels> channels_{};
        capy::async_mutex tx_mutex_;
        capy::async_event changed_, ctrl_ev_, ka_stop_, opened_, rekey_ev_;
        std::uint32_t keepalive_ms_ = 30000, pending_request_failures_ = 0;
        Clock::time_point rekey_started_at_{};
        RekeyState rekey_state_ = RekeyState::idle;
        bool closed_ = false, running_ = false, authed_ = false, strict_kex_ = false, want_local_rekey_ = false;
        std::size_t active_channels_ = 0;
        std::chrono::milliseconds close_reclaim_timeout_{5000};

        auto wait_event(capy::async_event& ev, Deadline dl) -> capy::task<bool> {
            auto op = ev.wait();
            auto [err] = dl ? co_await corosio::timeout(std::move(op), *dl) : co_await std::move(op);
            co_return !err && !closed_ && (!dl || Clock::now() < *dl);
        }
        auto read_more(Clock::time_point dl) -> capy::task<bool> {
            rx_buf_.compact();
            std::array<std::uint8_t, 16640> tmp{};
            auto r = co_await stream_.read(tmp, dl);
            if (!r || *r == 0 || closed_) co_return false;
            rx_buf_.append(std::span(tmp).first(*r));
            co_return true;
        }
        auto read_exact(std::span<std::uint8_t> out, Clock::time_point dl) -> capy::task<bool> {
            while (!out.empty()) {
                if (auto n = rx_buf_.take(out); n > 0) { out = out.subspan(n); continue; }
                if (!co_await read_more(dl)) co_return false;
            }
            co_return true;
        }
        auto read_banner(Clock::time_point dl) -> capy::task<std::optional<std::string>> {
            for (int line_no = 0; line_no < 64; ++line_no) {
                std::string line;
                while (line.size() < 256) {
                    if (rx_buf_.available() == 0 && !co_await read_more(dl)) co_return std::nullopt;
                    char c = static_cast<char>(rx_buf_.pop_byte());
                    if (c == '\n') {
                        if (!line.empty() && line.back() == '\r') line.pop_back();
                        if (line.starts_with("SSH-2.0-") || line.starts_with("SSH-1.99-")) co_return line;
                        if (line.starts_with("SSH-")) co_return std::nullopt;
                        break;
                    }
                    line.push_back(c);
                }
                if (line.size() >= 256) co_return std::nullopt;
            }
            co_return std::nullopt;
        }
        auto recv_packet(Clock::time_point dl) -> capy::task<std::optional<std::vector<std::uint8_t>>> {
            if (rx_.kind() != CipherKind::none && rekey_.rx_hard_exceeded()) { cancel(); co_return std::nullopt; }
            std::array<std::uint8_t, 4> hdr{};
            if (!co_await read_exact(hdr, dl)) co_return std::nullopt;
            auto pkt_len = rx_.decrypt_length(recv_seq_, hdr);
            if (!pkt_len) co_return std::nullopt;
            std::vector<std::uint8_t> rest(*pkt_len + rx_.tag_bytes());
            if (!co_await read_exact(rest, dl)) co_return std::nullopt;
            auto body = rx_.decrypt_body(recv_seq_++, hdr, rest);
            if (!body) co_return std::nullopt;
            if (rx_.kind() != CipherKind::none) { ++rekey_.rx_pkts; rekey_.rx_bytes += *pkt_len; }
            co_return std::move(*body);
        }
        auto send_packet_unlocked(std::span<std::uint8_t const> payload, Clock::time_point dl, bool reset_seq = false)
            -> capy::task<bool> {
            if (closed_) co_return false;
            if (tx_.kind() != CipherKind::none && rekey_.tx_hard_exceeded(payload.size())) { cancel(); co_return false; }
            struct SendGuard { Session& s; bool ok = false; ~SendGuard() { if (!ok) s.cancel(); } } guard{*this};
            auto wire = tx_.encrypt(send_seq_++, payload);
            if (!wire) co_return false;
            if (tx_.kind() != CipherKind::none) { ++rekey_.tx_pkts; rekey_.tx_bytes += payload.size(); }
            if (reset_seq && strict_kex_) send_seq_ = 0;
            guard.ok = co_await stream_.send(*wire, dl);
            co_return guard.ok;
        }
        auto send_kex_packet(std::span<std::uint8_t const> payload, Clock::time_point dl, bool reset_seq = false)
            -> capy::task<bool> {
            if (closed_) co_return false;
            auto [err, lk] = co_await corosio::timeout(tx_mutex_.scoped_lock(), dl);
            if (err || closed_) co_return false;
            co_return co_await send_packet_unlocked(payload, dl, reset_seq);
        }
        auto begin_local_rekey_locked(Clock::time_point dl) -> capy::task<bool> {
            auto ic = build_client_kexinit(cipher_list_, false);
            if (!ic) { cancel(); co_return false; }
            rekey_ic_ = std::move(*ic);
            rekey_state_ = RekeyState::sent_kexinit;
            rekey_started_at_ = Clock::now();
            want_local_rekey_ = false;
            ctrl_ev_.set();
            co_return co_await send_packet_unlocked(rekey_ic_, std::min(dl, rekey_started_at_ + rekey_.timeout));
        }
        auto initiate_local_rekey(Clock::time_point dl) -> capy::task<bool> {
            if (closed_ || rekey_state_ != RekeyState::idle) co_return true;
            auto [err, lk] = co_await corosio::timeout(tx_mutex_.scoped_lock(), dl);
            if (err || closed_) co_return false;
            if (rekey_state_ != RekeyState::idle) co_return true;
            co_return co_await begin_local_rekey_locked(dl);
        }
        auto send_packet(std::span<std::uint8_t const> payload, Clock::time_point dl) -> capy::task<bool> {
            while (!closed_) {
                if (rekey_state_ != RekeyState::idle) {
                    rekey_ev_.clear();
                    if (rekey_state_ != RekeyState::idle && !co_await wait_event(rekey_ev_, dl)) co_return false;
                    continue;
                }
                auto [err, lk] = co_await corosio::timeout(tx_mutex_.scoped_lock(), dl);
                if (err || closed_) co_return false;
                if (rekey_state_ != RekeyState::idle) continue;
                if (rekey_.should_trigger_tx(authed_ && tx_.kind() != CipherKind::none, payload.size(), Clock::now())) {
                    if (!co_await begin_local_rekey_locked(dl)) co_return false;
                    continue;
                }
                co_return co_await send_packet_unlocked(payload, dl);
            }
            co_return false;
        }
        auto recv_kex_packet(Clock::time_point dl, bool& skip_guessed_kex, bool strict_initial)
            -> capy::task<std::optional<std::vector<std::uint8_t>>> {
            for (;;) {
                auto p = co_await recv_packet(dl);
                if (!p || p->empty() || closed_) co_return std::nullopt;
                auto m = (*p)[0];
                if (!strict_initial && (m == kMsgIgnore || m == kMsgDebug || m == kMsgUnimplemented)) continue;
                if (skip_guessed_kex && m >= 30 && m <= 49) { skip_guessed_kex = false; continue; }
                co_return std::move(*p);
            }
        }
        auto perform_kex(bool is_initial, std::span<std::uint8_t const> server_kexinit, Clock::time_point dl)
            -> capy::task<bool> {
            if (!is_initial) {
                if (rekey_state_ == RekeyState::in_progress) co_return false;
                bool const need_send_ic = (rekey_state_ == RekeyState::idle);
                rekey_state_ = RekeyState::in_progress;
                want_local_rekey_ = false;
                if (rekey_started_at_ == Clock::time_point{}) rekey_started_at_ = Clock::now();
                ctrl_ev_.set();
                if (need_send_ic) {
                    auto ic = build_client_kexinit(cipher_list_, false);
                    if (!ic) co_return false;
                    rekey_ic_ = std::move(*ic);
                    if (!co_await send_kex_packet(rekey_ic_, dl)) co_return false;
                }
            }
            auto neg = negotiate_client_kex(cipher_list_, server_kexinit);
            if (!neg) co_return false;
            if (is_initial) strict_kex_ = neg->strict_kex;
            auto eph = crypto::X25519Private::generate();
            if (!eph) co_return false;
            auto qc = eph->public_key();
            if (!qc) co_return false;
            Writer ke; ke.byte(kMsgKexEcdhInit).string(*qc);
            if (!(is_initial ? co_await send_packet_unlocked(ke.buf, dl) : co_await send_kex_packet(ke.buf, dl)))
                co_return false;
            bool skip_guess = neg->skip_guessed_kex;
            auto kr = co_await recv_kex_packet(dl, skip_guess, is_initial && strict_kex_);
            if (!kr || kr->empty() || (*kr)[0] != kMsgKexEcdhReply) co_return false;
            std::span<std::uint8_t const> sid = is_initial
                ? std::span<std::uint8_t const>{} : std::span<std::uint8_t const>(session_id_);
            auto keys = finish_ecdh_kex(kClientVersion, server_banner_, rekey_ic_, server_kexinit, *qc, *eph,
                                        *kr, host_key_sha256_, sid, neg->c_cs, neg->c_sc);
            if (!keys) co_return false;
            if (is_initial) session_id_ = keys->exchange_hash;
            std::array<std::uint8_t, 1> nk{kMsgNewKeys};
            if (is_initial) {
                if (!co_await send_packet_unlocked(nk, dl, true) || !tx_.activate(keys->c_cs, keys->k_cs, keys->iv_cs)) co_return false;
            } else {
                auto [err, lk] = co_await corosio::timeout(tx_mutex_.scoped_lock(), dl);
                if (err || closed_ || !co_await send_packet_unlocked(nk, dl, false) || !tx_.activate(keys->c_cs, keys->k_cs, keys->iv_cs)) co_return false;
            }
            rekey_.reset_tx();
            bool no_skip = false;
            auto snk = co_await recv_kex_packet(dl, no_skip, is_initial && strict_kex_);
            if (!snk || snk->size() != 1 || (*snk)[0] != kMsgNewKeys) co_return false;
            if (is_initial && strict_kex_) recv_seq_ = 0;
            if (!rx_.activate(keys->c_sc, keys->k_sc, keys->iv_sc)) co_return false;
            rekey_.reset_rx(); rekey_ic_.clear(); rekey_.last_rekey = Clock::now(); rekey_started_at_ = Clock::time_point{};
            if (!is_initial) { rekey_state_ = RekeyState::idle; ++rekey_.count; rekey_ev_.set(); ctrl_ev_.set(); }
            co_return true;
        }
        auto send_channel_eof_close(std::uint8_t msg, std::uint32_t peer_id, Clock::time_point dl) -> capy::task<bool> {
            Writer w; w.byte(msg).u32(peer_id);
            co_return co_await send_packet(w.buf, dl);
        }
        auto wait_auth_reply(Clock::time_point dl, bool allow_banner) -> capy::task<std::optional<std::uint8_t>> {
            for (;;) {
                auto p = co_await recv_packet(dl);
                if (!p || p->empty()) co_return std::nullopt;
                auto m = (*p)[0];
                if (m == kMsgIgnore || m == kMsgDebug || m == kMsgExtInfo || (allow_banner && m == kMsgUserauthBanner))
                    continue;
                co_return m;
            }
        }
        auto handle_channel_packet(std::uint8_t msg, Reader& r) -> bool {
            auto id = r.u32();
            if (!id || *id >= kMaxChannels || !channels_[*id].in_use) return true;
            auto sig = apply_channel_packet(channels_[*id], msg, r);
            if (!sig.valid) return false;
            if (sig.opened) opened_.set();
            if (sig.changed) changed_.set();
            if (sig.ctrl) ctrl_ev_.set();
            return true;
        }
        auto read_loop() -> capy::task<capy::results<>> {
            struct Guard { Session& s; ~Guard() { s.running_ = false; s.cancel(); } } g{*this};
            while (!closed_) {
                auto pkt = co_await recv_packet(Clock::now() + std::chrono::hours(24));
                if (!pkt || pkt->empty() || closed_) break;
                Reader r{*pkt};
                auto msg = *r.byte();
                if (msg == kMsgKexInit) {
                    if (!co_await perform_kex(false, *pkt, Clock::now() + rekey_.timeout)) break;
                    continue;
                }
                if (msg == kMsgDisconnect || msg == kMsgNewKeys) break;
                if (msg == kMsgGlobalRequest) {
                    auto req = r.text();
                    auto want = r.boolean();
                    if (req && want && *want) { ++pending_request_failures_; ctrl_ev_.set(); }
                } else if (msg >= kMsgChannelOpenConfirm && msg <= kMsgChannelClose) {
                    if (!handle_channel_packet(msg, r)) break;
                }
                if (rekey_state_ == RekeyState::idle &&
                    rekey_.should_trigger_rx(authed_ && rx_.kind() != CipherKind::none, Clock::now())) {
                    want_local_rekey_ = true;
                    ctrl_ev_.set();
                }
            }
            co_return capy::results<>{};
        }
        auto control_loop() -> capy::task<capy::results<>> {
            while (!closed_) {
                ctrl_ev_.clear();
                bool did_work = false;
                auto now = Clock::now();
                Deadline next_reclaim;
                auto clamp_due = [&](Clock::time_point due) noexcept {
                    next_reclaim = next_reclaim ? std::min(*next_reclaim, due) : due;
                };
                if (rekey_state_ != RekeyState::idle) {
                    if (rekey_started_at_ != Clock::time_point{}) {
                        if (now - rekey_started_at_ >= rekey_.timeout) { cancel(); break; }
                        clamp_due(rekey_started_at_ + rekey_.timeout);
                    }
                } else {
                    if (rekey_.should_trigger_tx(authed_ && tx_.kind() != CipherKind::none, 0, now))
                        want_local_rekey_ = true;
                    else if (auto due = rekey_.next_time_due()) clamp_due(*due);
                    if (want_local_rekey_) {
                        want_local_rekey_ = false;
                        did_work = true;
                        if (!co_await initiate_local_rekey(now + rekey_.timeout)) { cancel(); break; }
                    }
                    while (pending_request_failures_ > 0 && !closed_ && rekey_state_ == RekeyState::idle) {
                        --pending_request_failures_;
                        did_work = true;
                        Writer fw; fw.byte(kMsgRequestFailure);
                        if (!co_await send_packet(fw.buf, Clock::now() + std::chrono::seconds(5))) { cancel(); break; }
                    }
                }
                for (std::size_t i = 0; i < kMaxChannels && !closed_; ++i) {
                    auto& ch = channels_[i];
                    if (!ch.in_use) continue;
                    if (rekey_state_ == RekeyState::idle && ch.open_ok && ch.local_consumed >= kWindowAdjustThreshold &&
                        !ch.local_close && !ch.remote_close && !ch.released) {
                        did_work = true;
                        auto add = std::exchange(ch.local_consumed, 0);
                        ch.local_window += add;
                        Writer w; w.byte(kMsgChannelWindowAdjust).u32(ch.peer_id).u32(add);
                        if (!co_await send_packet(w.buf, Clock::now() + std::chrono::seconds(5))) { cancel(); break; }
                    }
                    if (rekey_state_ == RekeyState::idle && (ch.want_close || ch.released) && ch.open_ok && !ch.local_close) {
                        did_work = true; ch.local_close = true; ch.want_close = false;
                        if (ch.released && ch.released_at == Clock::time_point{}) ch.released_at = Clock::now();
                        if (!co_await send_channel_eof_close(kMsgChannelClose, ch.peer_id, Clock::now() + std::chrono::seconds(5))) { cancel(); break; }
                    }
                    bool const wait_close = ch.released && ch.local_close && !ch.remote_close && ch.open_ok;
                    bool const wait_open = ch.released && ch.opening;
                    bool const timed_out = (wait_close || wait_open) && ch.released_at != Clock::time_point{} &&
                        (now - ch.released_at >= close_reclaim_timeout_);
                    if (wait_open && timed_out) { cancel(); break; }
                    if (ch.released && (!ch.opening || closed_) && (ch.local_close || ch.open_fail || !ch.open_ok) &&
                        (ch.remote_close || ch.open_fail || !ch.open_ok || timed_out)) {
                        did_work = true; ch = ChannelSlot{}; --active_channels_; changed_.set();
                    } else if ((wait_close || wait_open) && ch.released_at != Clock::time_point{}) {
                        clamp_due(ch.released_at + close_reclaim_timeout_);
                    }
                }
                if (!did_work && !closed_) (void)co_await wait_event(ctrl_ev_, next_reclaim);
            }
            co_return capy::results<>{};
        }
        auto keepalive_loop() -> capy::task<capy::results<>> {
            while (!closed_ && keepalive_ms_ > 0) {
                ka_stop_.clear();
                auto [err] = co_await corosio::timeout(ka_stop_.wait(), Clock::now() + std::chrono::milliseconds(keepalive_ms_));
                if (closed_ || !err) break;
                Writer w; w.byte(kMsgGlobalRequest).string("keepalive@openssh.com").boolean(true);
                if (!co_await send_packet(w.buf, Clock::now() + std::chrono::seconds(10))) { cancel(); break; }
            }
            co_return capy::results<>{};
        }
    public:
        explicit Session(Stream& stream) noexcept : stream_(stream) {}
        Session(Session const&) = delete;
        auto operator=(Session const&) -> Session& = delete;
        auto usable() const noexcept -> bool { return !closed_ && authed_; }
        auto available() const noexcept -> bool { return usable() && active_channels_ < kMaxChannels; }
        auto rekey_count() const noexcept -> std::uint64_t { return rekey_.count; }
        auto set_close_reclaim_timeout(std::chrono::milliseconds d) noexcept -> void { close_reclaim_timeout_ = d; }
        auto set_rekey_limits(std::uint64_t bytes, std::uint32_t pkts = kMaxEncryptedPackets - 65536u,
                              std::chrono::milliseconds iv = std::chrono::hours(1)) noexcept -> void { rekey_.set_limits(bytes, pkts, iv); }
        auto cancel() noexcept -> void { closed_ = true; ka_stop_.set(); ctrl_ev_.set(); changed_.set(); opened_.set(); rekey_ev_.set(); stream_.cancel(); }

        auto start_client(ClientAuth const& auth, Clock::time_point dl) -> capy::task<bool> {
            keepalive_ms_ = auth.keepalive_interval_ms;
            host_key_sha256_ = auth.host_key_sha256;
            cipher_list_ = auth.preferred_cipher.empty()
                ? "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com" : auth.preferred_cipher;
            std::string banner_wire = std::string(kClientVersion) + "\r\n";
            if (!co_await stream_.send(std::span<std::uint8_t const>(reinterpret_cast<std::uint8_t const*>(banner_wire.data()), banner_wire.size()), dl)) co_return false;
            auto server_banner = co_await read_banner(dl);
            if (!server_banner) co_return false;
            server_banner_ = *server_banner;
            auto ic = build_client_kexinit(cipher_list_, true);
            if (!ic) co_return false;
            rekey_ic_ = std::move(*ic);
            if (!co_await send_packet_unlocked(rekey_ic_, dl)) co_return false;
            auto is_pkt = co_await recv_packet(dl);
            if (!is_pkt || !co_await perform_kex(true, *is_pkt, dl)) co_return false;
            Writer sr; sr.byte(kMsgServiceRequest).string("ssh-userauth");
            if (!co_await send_packet_unlocked(sr.buf, dl)) co_return false;
            auto svc = co_await wait_auth_reply(dl, false);
            if (!svc || *svc != kMsgServiceAccept) co_return false;
            if (auth.private_key) {
                auto req = build_publickey_auth_request(session_id_, auth.user, *auth.private_key);
                if (!req || !co_await send_packet_unlocked(*req, dl)) co_return false;
                auto ar = co_await wait_auth_reply(dl, true);
                if (!ar) co_return false;
                if (*ar == kMsgUserauthSuccess) { authed_ = true; co_return true; }
                if (*ar != kMsgUserauthFailure) co_return false;
            }
            if (auth.password) {
                Writer req;
                struct BufWipe { std::vector<std::uint8_t>& v; ~BufWipe() { crypto::cleanse(v); } } wipe{req.buf};
                req.byte(kMsgUserauthRequest).string(auth.user).string("ssh-connection").string("password").boolean(false).string(*auth.password);
                if (!co_await send_packet_unlocked(req.buf, dl)) co_return false;
                auto ar = co_await wait_auth_reply(dl, true);
                if (ar && *ar == kMsgUserauthSuccess) { authed_ = true; co_return true; }
            }
            co_return false;
        }
        auto run() -> capy::task<capy::results<>> {
            running_ = true;
            if (keepalive_ms_ > 0) (void)co_await capy::when_all(read_loop(), control_loop(), keepalive_loop());
            else (void)co_await capy::when_all(read_loop(), control_loop());
            co_return capy::results<>{};
        }
        auto open_direct_tcpip(std::string_view host, std::uint16_t port, Clock::time_point dl, std::stop_token cancel_tok = {})
            -> capy::task<std::optional<std::uint32_t>> {
            if (!usable() || host.empty() || !port || cancel_tok.stop_requested()) co_return std::nullopt;
            std::optional<std::uint32_t> slot_id;
            for (std::size_t i = 0; i < kMaxChannels; ++i)
                if (!channels_[i].in_use) { slot_id = static_cast<std::uint32_t>(i); break; }
            if (!slot_id) co_return std::nullopt;
            auto& ch = channels_[*slot_id];
            ch = ChannelSlot{}; ch.in_use = ch.opening = true; ++active_channels_;
            struct OpenGuard { Session& s; std::uint32_t id; bool ok = false; ~OpenGuard() { if (!ok) s.release_channel(id); } } og{*this, *slot_id};
            auto open_buf = build_channel_open_direct_tcpip(*slot_id, host, port);
            if (!co_await send_packet(open_buf, dl)) { og.ok = true; ch = ChannelSlot{}; --active_channels_; co_return std::nullopt; }
            std::stop_callback stop_cb(cancel_tok, [this] noexcept { opened_.set(); });
            while (!closed_ && ch.opening && !cancel_tok.stop_requested()) {
                opened_.clear();
                if (!co_await wait_event(opened_, dl)) break;
            }
            if (closed_ || !ch.open_ok || cancel_tok.stop_requested()) {
                if (!ch.open_ok && !ch.opening) { og.ok = true; ch = ChannelSlot{}; --active_channels_; }
                co_return std::nullopt;
            }
            og.ok = true;
            co_return slot_id;
        }
        auto read_channel(std::uint32_t id, std::span<std::uint8_t> out, Clock::time_point dl)
            -> capy::task<std::expected<std::size_t, std::string>> {
            if (id >= kMaxChannels) co_return std::unexpected("invalid SSH channel");
            auto& ch = channels_[id];
            while (!closed_ && !ch.released) {
                if (!ch.rx.empty()) {
                    auto n = std::min(out.size(), ch.rx.size());
                    std::copy_n(ch.rx.begin(), n, out.begin());
                    ch.rx.erase(ch.rx.begin(), ch.rx.begin() + static_cast<std::ptrdiff_t>(n));
                    ch.local_consumed += static_cast<std::uint32_t>(n);
                    if (ch.local_consumed >= kWindowAdjustThreshold) ctrl_ev_.set();
                    co_return n;
                }
                if (ch.remote_eof || ch.remote_close) co_return 0;
                if (!ch.in_use || !ch.open_ok) co_return std::unexpected("SSH channel closed");
                changed_.clear();
                if (!co_await wait_event(changed_, dl)) co_return std::unexpected("SSH channel read failed");
            }
            co_return std::unexpected("SSH session closed");
        }
        auto write_channel(std::uint32_t id, std::span<std::uint8_t const> data, Clock::time_point dl)
            -> capy::task<bool> {
            if (id >= kMaxChannels) co_return false;
            auto& ch = channels_[id];
            while (!data.empty()) {
                if (closed_ || ch.released || !ch.in_use || !ch.open_ok || ch.local_eof || ch.local_close || ch.remote_close) co_return false;
                while (!closed_ && !ch.released && ch.peer_window == 0 && !ch.local_close && !ch.remote_close) {
                    changed_.clear();
                    if (!co_await wait_event(changed_, dl)) co_return false;
                }
                if (closed_ || ch.released || ch.peer_window == 0 || ch.local_close || ch.remote_close) co_return false;
                auto chunk = static_cast<std::uint32_t>(std::min<std::size_t>({data.size(), ch.peer_window, ch.peer_max_packet}));
                ch.peer_window -= chunk;
                Writer w; w.byte(kMsgChannelData).u32(ch.peer_id).string(data.first(chunk));
                if (!co_await send_packet(w.buf, dl)) co_return false;
                data = data.subspan(chunk);
            }
            co_return true;
        }
        auto close_output(std::uint32_t id, Clock::time_point dl) -> capy::task<bool> {
            if (id >= kMaxChannels) co_return false;
            auto& ch = channels_[id];
            if (closed_ || ch.released || !ch.in_use || !ch.open_ok || ch.local_eof || ch.local_close) co_return true;
            ch.local_eof = true;
            if (!co_await send_channel_eof_close(kMsgChannelEof, ch.peer_id, dl)) co_return false;
            if (ch.remote_eof && !ch.local_close) {
                ch.local_close = true;
                (void)co_await send_channel_eof_close(kMsgChannelClose, ch.peer_id, dl);
            }
            co_return true;
        }
        auto release_channel(std::uint32_t id) noexcept -> void {
            if (id >= kMaxChannels) return;
            auto& ch = channels_[id];
            if (!ch.in_use) return;
            ch.released = true; ch.released_at = Clock::now();
            ch.rx.clear(); ch.rx.shrink_to_fit();
            ch.want_close = !ch.local_close;
            changed_.set(); opened_.set(); ctrl_ev_.set();
        }
    };

    template<class Stream>
    class Channel {
        Session<Stream>& session_;
        std::uint32_t id_;
        bool released_ = false;
    public:
        Channel(Session<Stream>& s, std::uint32_t id) noexcept : session_(s), id_(id) {}
        ~Channel() { cancel(); }
        Channel(Channel const&) = delete;
        auto operator=(Channel const&) -> Channel& = delete;
        auto cancel() noexcept -> void { if (!std::exchange(released_, true)) session_.release_channel(id_); }
        auto read(std::span<std::uint8_t> b) -> capy::task<std::expected<std::size_t, std::string>> { co_return co_await session_.read_channel(id_, b, Clock::now() + std::chrono::seconds(300)); }
        auto send(std::span<std::uint8_t const> b) -> capy::task<bool> { co_return co_await session_.write_channel(id_, b, Clock::now() + std::chrono::seconds(300)); }
        auto close_output() -> capy::task<bool> { co_return co_await session_.close_output(id_, Clock::now() + std::chrono::seconds(300)); }
    };
}
