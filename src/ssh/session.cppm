export module ssh.session;
import std;
import crypto;
import ssh.wire;
import ssh.crypto;
import capy;
import corosio;

export namespace ssh {
    using Clock = std::chrono::steady_clock;
    using Deadline = std::optional<Clock::time_point>;

    struct ClientAuth {
        std::string user;
        std::optional<std::string> password;
        std::optional<PrivateKey> private_key;
        std::vector<std::array<std::uint8_t, 32>> host_key_sha256;
        std::string preferred_cipher;
        std::uint32_t keepalive_interval_ms = 30000;
        ClientAuth() = default;
        ClientAuth(ClientAuth&&) noexcept = default;
        auto operator=(ClientAuth&&) noexcept -> ClientAuth& = default;
        ~ClientAuth() {
            if (password && !password->empty())
                crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(password->data()), password->size()));
        }
    };

    inline constexpr std::size_t kMaxChannels = 64;
    inline constexpr std::uint32_t kInitialWindow = 1024u * 1024u, kMaxPacket = 32768u;
    inline constexpr std::uint32_t kWindowAdjustThreshold = 256u * 1024u, kMaxEncryptedPackets = 1u << 30;
    inline constexpr std::uint64_t kMaxEncryptedBytes = 1ull << 30;

    template<class Stream>
    class Session {
        struct ChannelSlot {
            bool in_use = false, opening = false, open_ok = false, open_fail = false;
            bool remote_eof = false, remote_close = false, local_eof = false, local_close = false;
            bool released = false, want_close = false;
            std::uint32_t peer_id = 0;
            std::uint32_t local_window = kInitialWindow, local_consumed = 0;
            std::uint32_t peer_window = 0, peer_max_packet = kMaxPacket;
            std::deque<std::uint8_t> rx;
            Clock::time_point released_at{};
        };

        Stream& stream_;
        PacketCipher tx_, rx_;
        std::uint32_t send_seq_ = 0, recv_seq_ = 0, tx_enc_pkts_ = 0, rx_enc_pkts_ = 0;
        std::uint64_t tx_bytes_ = 0, rx_bytes_ = 0;
        std::array<std::uint8_t, 32> session_id_{};
        std::vector<std::uint8_t> rx_buf_;
        std::size_t rx_off_ = 0;
        std::array<ChannelSlot, kMaxChannels> channels_{};
        capy::async_mutex tx_mutex_;
        capy::async_event changed_, ctrl_ev_, ka_stop_;
        std::uint32_t keepalive_ms_ = 30000;
        bool closed_ = false, running_ = false, authed_ = false, strict_kex_ = false;
        std::size_t active_channels_ = 0;
        std::chrono::milliseconds close_reclaim_timeout_{5000};

        auto wait_event(capy::async_event& ev, Deadline dl) -> capy::task<bool> {
            auto op = ev.wait();
            auto [err] = dl ? co_await corosio::timeout(std::move(op), *dl) : co_await std::move(op);
            co_return !err && !closed_ && (!dl || Clock::now() < *dl);
        }

        auto read_more(Clock::time_point dl) -> capy::task<bool> {
            if (rx_off_ == rx_buf_.size()) { rx_buf_.clear(); rx_off_ = 0; }
            else if (rx_off_ > 4096) {
                rx_buf_.erase(rx_buf_.begin(), rx_buf_.begin() + static_cast<std::ptrdiff_t>(rx_off_));
                rx_off_ = 0;
            }
            std::array<std::uint8_t, 16640> tmp{};
            auto r = co_await stream_.read(tmp, dl);
            if (!r || *r == 0 || closed_) co_return false;
            rx_buf_.insert(rx_buf_.end(), tmp.begin(), tmp.begin() + static_cast<std::ptrdiff_t>(*r));
            co_return true;
        }
        auto read_exact(std::span<std::uint8_t> out, Clock::time_point dl) -> capy::task<bool> {
            while (!out.empty()) {
                if (rx_off_ < rx_buf_.size()) {
                    auto n = std::min(out.size(), rx_buf_.size() - rx_off_);
                    std::copy_n(rx_buf_.data() + rx_off_, n, out.data());
                    rx_off_ += n;
                    out = out.subspan(n);
                    continue;
                }
                if (!co_await read_more(dl)) co_return false;
            }
            co_return true;
        }
        auto read_banner(Clock::time_point dl) -> capy::task<std::optional<std::string>> {
            for (int line_no = 0; line_no < 64; ++line_no) {
                std::string line;
                while (line.size() < 256) {
                    if (rx_off_ == rx_buf_.size() && !co_await read_more(dl)) co_return std::nullopt;
                    char c = static_cast<char>(rx_buf_[rx_off_++]);
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
            if (rx_.kind() != CipherKind::none && (rx_enc_pkts_ >= kMaxEncryptedPackets || rx_bytes_ >= kMaxEncryptedBytes)) {
                cancel(); co_return std::nullopt;
            }
            std::array<std::uint8_t, 4> hdr{};
            if (!co_await read_exact(hdr, dl)) co_return std::nullopt;
            auto pkt_len = rx_.decrypt_length(recv_seq_, hdr);
            if (!pkt_len) co_return std::nullopt;
            std::vector<std::uint8_t> rest(*pkt_len + rx_.tag_bytes());
            if (!co_await read_exact(rest, dl)) co_return std::nullopt;
            auto body = rx_.decrypt_body(recv_seq_++, hdr, rest);
            if (!body) co_return std::nullopt;
            if (rx_.kind() != CipherKind::none) { ++rx_enc_pkts_; rx_bytes_ += *pkt_len; }
            co_return std::move(*body);
        }
        auto send_packet_unlocked(std::span<std::uint8_t const> payload, Clock::time_point dl, bool reset_seq = false)
            -> capy::task<bool> {
            if (closed_) co_return false;
            if (tx_.kind() != CipherKind::none &&
                (tx_enc_pkts_ >= kMaxEncryptedPackets || payload.size() > kMaxEncryptedBytes - tx_bytes_)) {
                cancel(); co_return false;
            }
            struct SendGuard {
                Session& s; bool committed = false;
                ~SendGuard() { if (!committed) s.cancel(); }
            } guard{*this};
            auto wire = tx_.encrypt(send_seq_++, payload);
            if (!wire) co_return false;
            if (tx_.kind() != CipherKind::none) { ++tx_enc_pkts_; tx_bytes_ += payload.size(); }
            if (reset_seq && strict_kex_) send_seq_ = 0;
            bool ok = co_await stream_.send(*wire, dl);
            guard.committed = ok;
            co_return ok;
        }
        auto send_packet(std::span<std::uint8_t const> payload, Clock::time_point dl) -> capy::task<bool> {
            if (closed_) co_return false;
            auto [err, lk] = co_await corosio::timeout(tx_mutex_.scoped_lock(), dl);
            if (err || closed_) co_return false;
            co_return co_await send_packet_unlocked(payload, dl);
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
            if (!id || *id >= kMaxChannels) return true;
            auto& ch = channels_[*id];
            if (!ch.in_use) return true;
            if (msg == kMsgChannelOpenConfirm) {
                auto peer_id = r.u32(), win = r.u32(), maxp = r.u32();
                if (!peer_id || !win || !maxp) return false;
                ch.peer_id = *peer_id; ch.peer_window = *win;
                ch.peer_max_packet = std::clamp(*maxp, std::uint32_t{1024}, kMaxPacket);
                ch.opening = false; ch.open_ok = true; opened_.set();
                if (ch.released) { ch.want_close = true; ctrl_ev_.set(); }
            } else if (msg == kMsgChannelOpenFailure) {
                ch.opening = false; ch.open_fail = true; opened_.set(); ctrl_ev_.set();
            } else if (msg == kMsgChannelWindowAdjust) {
                auto add = r.u32();
                if (!add) return false;
                ch.peer_window = static_cast<std::uint32_t>(std::min<std::uint64_t>(std::uint64_t(ch.peer_window) + *add, 0x7fffffffu));
                changed_.set();
            } else if (msg == kMsgChannelData) {
                auto data = r.string();
                if (!data || data->size() > ch.local_window) return false;
                ch.local_window -= static_cast<std::uint32_t>(data->size());
                ch.rx.insert(ch.rx.end(), data->begin(), data->end());
                changed_.set();
            } else if (msg == kMsgChannelExtData) {
                auto dtype = r.u32();
                auto data = r.string();
                if (!dtype || !data || data->size() > ch.local_window) return false;
                ch.local_window -= static_cast<std::uint32_t>(data->size());
                ch.local_consumed += static_cast<std::uint32_t>(data->size());
                ctrl_ev_.set();
            } else if (msg == kMsgChannelEof) {
                ch.remote_eof = true; changed_.set();
            } else if (msg == kMsgChannelClose) {
                ch.remote_eof = ch.remote_close = true;
                ch.want_close = !ch.local_close && !ch.released;
                changed_.set(); opened_.set(); ctrl_ev_.set();
            }
            return true;
        }
        capy::async_event opened_;
        auto read_loop() -> capy::task<capy::results<>> {
            struct Guard { Session& s; ~Guard() { s.running_ = false; s.cancel(); } } g{*this};
            while (!closed_) {
                auto pkt = co_await recv_packet(Clock::now() + std::chrono::hours(24));
                if (!pkt || pkt->empty() || closed_) break;
                Reader r{*pkt};
                auto msg = *r.byte();
                if (msg == kMsgIgnore || msg == kMsgDebug || msg == kMsgExtInfo ||
                    msg == kMsgRequestSuccess || msg == kMsgRequestFailure || msg == kMsgUnimplemented) continue;
                if (msg == kMsgGlobalRequest) {
                    auto req = r.text();
                    auto want = r.boolean();
                    if (req && want && *want) {
                        Writer fw; fw.byte(kMsgRequestFailure);
                        (void)co_await send_packet(fw.buf, Clock::now() + std::chrono::seconds(5));
                    }
                    continue;
                }
                if (msg == kMsgDisconnect || msg == kMsgKexInit || msg == kMsgNewKeys) break;
                if (msg >= kMsgChannelOpenConfirm && msg <= kMsgChannelClose && !handle_channel_packet(msg, r)) break;
            }
            co_return capy::results<>{};
        }

        auto control_loop() -> capy::task<capy::results<>> {
            while (!closed_) {
                ctrl_ev_.clear();
                bool did_work = false;
                auto now = Clock::now();
                Deadline next_reclaim;
                for (std::size_t i = 0; i < kMaxChannels && !closed_; ++i) {
                    auto& ch = channels_[i];
                    if (!ch.in_use) continue;
                    if (ch.open_ok && ch.local_consumed >= kWindowAdjustThreshold &&
                        !ch.local_close && !ch.remote_close && !ch.released) {
                        did_work = true;
                        auto add = std::exchange(ch.local_consumed, 0);
                        ch.local_window += add;
                        Writer w; w.byte(kMsgChannelWindowAdjust).u32(ch.peer_id).u32(add);
                        if (!co_await send_packet(w.buf, Clock::now() + std::chrono::seconds(5))) { cancel(); break; }
                    }
                    if ((ch.want_close || ch.released) && ch.open_ok && !ch.local_close) {
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
                        auto due = ch.released_at + close_reclaim_timeout_;
                        next_reclaim = next_reclaim ? std::min(*next_reclaim, due) : due;
                    }
                }
                if (!did_work && !closed_) (void)co_await wait_event(ctrl_ev_, next_reclaim);
            }
            co_return capy::results<>{};
        }

        auto keepalive_loop() -> capy::task<capy::results<>> {
            while (!closed_ && keepalive_ms_ > 0) {
                ka_stop_.clear();
                auto deadline = Clock::now() + std::chrono::milliseconds(keepalive_ms_);
                auto [err] = co_await corosio::timeout(ka_stop_.wait(), deadline);
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
        auto set_close_reclaim_timeout(std::chrono::milliseconds d) noexcept -> void { close_reclaim_timeout_ = d; }
        auto cancel() noexcept -> void {
            closed_ = true; ka_stop_.set(); ctrl_ev_.set(); changed_.set(); opened_.set(); stream_.cancel();
        }

        auto start_client(ClientAuth const& auth, Clock::time_point dl) -> capy::task<bool> {
            keepalive_ms_ = auth.keepalive_interval_ms;
            std::string banner_wire = std::string(kClientVersion) + "\r\n";
            if (!co_await stream_.send(std::span<std::uint8_t const>(reinterpret_cast<std::uint8_t const*>(banner_wire.data()), banner_wire.size()), dl)) co_return false;
            auto server_banner = co_await read_banner(dl);
            if (!server_banner) co_return false;
            KexInit ci;
            if (!crypto::random_bytes(ci.cookie)) co_return false;
            ci.kex_algorithms = "curve25519-sha256," + std::string(kStrictClientKex);
            ci.server_host_key_algorithms = "ssh-ed25519,ecdsa-sha2-nistp256";
            std::string ciphers = auth.preferred_cipher.empty() ? "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com" : auth.preferred_cipher;
            ci.enc_c2s = ci.enc_s2c = ciphers;
            ci.mac_c2s = ci.mac_s2c = "hmac-sha2-256,hmac-sha2-512";
            auto ic = encode_kexinit(ci);
            if (!co_await send_packet_unlocked(ic, dl)) co_return false;
            auto is_pkt = co_await recv_packet(dl);
            if (!is_pkt) co_return false;
            auto si = decode_kexinit(*is_pkt);
            if (!si) co_return false;
            strict_kex_ = list_contains(si->kex_algorithms, kStrictServerKex);
            if (!negotiate_algorithm("curve25519-sha256", si->kex_algorithms)) co_return false;
            auto enc_cs = negotiate_algorithm(ciphers, si->enc_c2s), enc_sc = negotiate_algorithm(ciphers, si->enc_s2c);
            auto c_cs = enc_cs ? parse_cipher_kind(*enc_cs) : std::nullopt;
            auto c_sc = enc_sc ? parse_cipher_kind(*enc_sc) : std::nullopt;
            if (!c_cs || !c_sc) co_return false;
            auto eph = crypto::X25519Private::generate();
            if (!eph) co_return false;
            auto qc = eph->public_key();
            if (!qc) co_return false;
            Writer ke; ke.byte(kMsgKexEcdhInit).string(*qc);
            if (!co_await send_packet_unlocked(ke.buf, dl)) co_return false;
            auto kr = co_await recv_packet(dl);
            if (!kr || kr->empty() || (*kr)[0] != kMsgKexEcdhReply) co_return false;
            Reader rr{std::span(*kr).subspan(1)};
            auto ks = rr.string(), qs = rr.string(), sig = rr.string();
            if (!ks || !qs || !sig || !rr.empty() || qs->size() != 32) co_return false;
            auto shared = eph->agree(*qs);
            if (!shared) co_return false;
            auto h = compute_exchange_hash(kClientVersion, *server_banner, ic, *is_pkt, *ks, *qc, *qs, shared->view());
            if (!h || !verify_host_key(*ks, auth.host_key_sha256, *h, *sig)) co_return false;
            session_id_ = *h;
            auto iv_cs = derive_key(shared->view(), *h, 'A', session_id_, cipher_iv_bytes(*c_cs));
            auto iv_sc = derive_key(shared->view(), *h, 'B', session_id_, cipher_iv_bytes(*c_sc));
            auto k_cs = derive_key(shared->view(), *h, 'C', session_id_, cipher_key_bytes(*c_cs));
            auto k_sc = derive_key(shared->view(), *h, 'D', session_id_, cipher_key_bytes(*c_sc));
            struct KeyWipe {
                decltype(iv_cs)& a; decltype(iv_sc)& b; decltype(k_cs)& c; decltype(k_sc)& d;
                ~KeyWipe() { if (a) crypto::cleanse(*a); if (b) crypto::cleanse(*b); if (c) crypto::cleanse(*c); if (d) crypto::cleanse(*d); }
            } key_wipe{iv_cs, iv_sc, k_cs, k_sc};
            if (!iv_cs || !iv_sc || !k_cs || !k_sc) co_return false;
            std::array<std::uint8_t, 1> nk{kMsgNewKeys};
            if (!co_await send_packet_unlocked(nk, dl, true)) co_return false;
            auto snk = co_await recv_packet(dl);
            if (!snk || snk->size() != 1 || (*snk)[0] != kMsgNewKeys) co_return false;
            if (strict_kex_) recv_seq_ = 0;
            if (!tx_.activate(*c_cs, *k_cs, *iv_cs) || !rx_.activate(*c_sc, *k_sc, *iv_sc)) co_return false;
            Writer sr; sr.byte(kMsgServiceRequest).string("ssh-userauth");
            if (!co_await send_packet_unlocked(sr.buf, dl)) co_return false;
            auto svc = co_await wait_auth_reply(dl, false);
            if (!svc || *svc != kMsgServiceAccept) co_return false;
            if (auth.private_key) {
                auto const& pk = *auth.private_key;
                Writer sign_in, req;
                sign_in.string(session_id_).byte(kMsgUserauthRequest).string(auth.user).string("ssh-connection").string("publickey").boolean(true).string(pk.algorithm()).string(pk.public_key_blob());
                auto psig = pk.sign(sign_in.buf);
                if (!psig) co_return false;
                req.byte(kMsgUserauthRequest).string(auth.user).string("ssh-connection").string("publickey").boolean(true).string(pk.algorithm()).string(pk.public_key_blob()).string(*psig);
                if (!co_await send_packet_unlocked(req.buf, dl)) co_return false;
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
            Writer w;
            w.byte(kMsgChannelOpen).string("direct-tcpip").u32(*slot_id).u32(kInitialWindow).u32(kMaxPacket)
                .string(host).u32(port).string("127.0.0.1").u32(0);
            if (!co_await send_packet(w.buf, dl)) { og.ok = true; ch = ChannelSlot{}; --active_channels_; co_return std::nullopt; }
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
                Writer w;
                w.byte(kMsgChannelData).u32(ch.peer_id).string(data.first(chunk));
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
