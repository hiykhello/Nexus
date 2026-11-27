#pragma once

namespace ssh_rekey_test {
    using ssh::Clock;

    inline auto b64_encode(std::span<std::uint8_t const> in) -> std::string {
        static constexpr char kTab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        for (std::size_t i = 0; i < in.size(); i += 3) {
            std::uint32_t v = std::uint32_t(in[i]) << 16;
            if (i + 1 < in.size()) v |= std::uint32_t(in[i + 1]) << 8;
            if (i + 2 < in.size()) v |= std::uint32_t(in[i + 2]);
            out.push_back(kTab[(v >> 18) & 63]);
            out.push_back(kTab[(v >> 12) & 63]);
            out.push_back(i + 1 < in.size() ? kTab[(v >> 6) & 63] : '=');
            out.push_back(i + 2 < in.size() ? kTab[v & 63] : '=');
        }
        return out;
    }

    inline auto make_ed25519_key(std::uint8_t seed_byte) -> ssh::PrivateKey {
        // Test-only Ed25519 keys from public RFC 8032 test vectors.
        static constexpr std::array<std::uint8_t, 32> tv1_seed{
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
            0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
        };
        static constexpr std::array<std::uint8_t, 32> tv1_pub{
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
            0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a
        };
        static constexpr std::array<std::uint8_t, 32> tv2_seed{
            0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
            0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb
        };
        static constexpr std::array<std::uint8_t, 32> tv2_pub{
            0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
            0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c
        };
        auto const& seed = seed_byte == 1 ? tv1_seed : tv2_seed;
        auto const& pub = seed_byte == 1 ? tv1_pub : tv2_pub;
        std::array<std::uint8_t, 64> sk64{};
        std::ranges::copy(seed, sk64.begin());
        std::ranges::copy(pub, sk64.begin() + 32);
        ssh::Writer pub_w, priv_w, root;
        pub_w.string("ssh-ed25519").string(pub);
        priv_w.u32(0x11223344u).u32(0x11223344u).string("ssh-ed25519").string(pub).string(sk64).string("tv");
        while (priv_w.buf.size() % 8 != 0) priv_w.byte(static_cast<std::uint8_t>((priv_w.buf.size() % 8) + 1));
        for (char c : std::string_view("openssh-key-v1\0", 15)) root.byte(static_cast<std::uint8_t>(c));
        root.string("none").string("none").string("").u32(1).string(pub_w.buf).string(priv_w.buf);
        auto pem = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + b64_encode(root.buf) + "\n-----END OPENSSH PRIVATE KEY-----\n";
        return std::move(*ssh::PrivateKey::parse(pem));
    }

    inline auto key_pin(ssh::PrivateKey const& k) -> std::array<std::uint8_t, 32> {
        auto d = crypto::digest(crypto::Hash::sha256, k.public_key_blob());
        std::array<std::uint8_t, 32> out{};
        std::ranges::copy(*d, out.begin());
        return out;
    }

    struct Pipe {
        std::deque<std::uint8_t> buf;
        capy::async_event ev;
        bool closed = false;
    };

    class MemStream {
        Pipe& in_;
        Pipe& out_;
    public:
        MemStream(Pipe& in, Pipe& out) noexcept : in_(in), out_(out) {}
        auto cancel() noexcept -> void { in_.closed = out_.closed = true; in_.ev.set(); out_.ev.set(); }
        auto read(std::span<std::uint8_t> dst, Clock::time_point dl) -> capy::task<std::expected<std::size_t, std::string>> {
            while (in_.buf.empty() && !in_.closed) {
                in_.ev.clear();
                auto [err] = co_await corosio::timeout(in_.ev.wait(), dl);
                if (err) co_return std::unexpected("timeout");
            }
            if (in_.buf.empty()) co_return std::size_t{0};
            auto n = std::min(dst.size(), in_.buf.size());
            std::copy_n(in_.buf.begin(), n, dst.begin());
            in_.buf.erase(in_.buf.begin(), in_.buf.begin() + static_cast<std::ptrdiff_t>(n));
            co_return n;
        }
        auto send(std::span<std::uint8_t const> src, Clock::time_point) -> capy::task<bool> {
            if (out_.closed) co_return false;
            out_.buf.insert(out_.buf.end(), src.begin(), src.end());
            out_.ev.set();
            co_return true;
        }
    };

    struct MockSshServer {
        static constexpr std::string_view kBanner = "SSH-2.0-MockSSH_1.0";
        MemStream& stream;
        ssh::PacketCipher tx, rx;
        std::uint32_t send_seq = 0, recv_seq = 0;
        std::array<std::uint8_t, 32> session_id{};
        std::string client_banner, inflight_before_kex;
        bool strict_kex = false, saw_proto_violation = false;
        int request_failures_seen = 0, rekeys_done = 0;

        auto read_exact(std::span<std::uint8_t> out, Clock::time_point dl) -> capy::task<bool> {
            while (!out.empty()) {
                auto r = co_await stream.read(out, dl);
                if (!r || *r == 0) co_return false;
                out = out.subspan(*r);
            }
            co_return true;
        }
        auto read_banner(Clock::time_point dl) -> capy::task<bool> {
            client_banner.clear();
            std::uint8_t b = 0;
            while (client_banner.size() < 256) {
                if (!co_await read_exact(std::span{&b, 1}, dl)) co_return false;
                if (b == '\n') {
                    if (!client_banner.empty() && client_banner.back() == '\r') client_banner.pop_back();
                    co_return client_banner.starts_with("SSH-2.0-");
                }
                client_banner.push_back(static_cast<char>(b));
            }
            co_return false;
        }
        auto send_pkt(std::span<std::uint8_t const> payload, Clock::time_point dl, bool reset_seq = false) -> capy::task<bool> {
            auto wire = tx.encrypt(send_seq++, payload);
            if (!wire) co_return false;
            if (reset_seq && strict_kex) send_seq = 0;
            co_return co_await stream.send(*wire, dl);
        }
        auto recv_pkt(Clock::time_point dl) -> capy::task<std::optional<std::vector<std::uint8_t>>> {
            std::array<std::uint8_t, 4> hdr{};
            if (!co_await read_exact(hdr, dl)) co_return std::nullopt;
            auto len = rx.decrypt_length(recv_seq, hdr);
            if (!len) co_return std::nullopt;
            std::vector<std::uint8_t> rest(*len + rx.tag_bytes());
            if (!co_await read_exact(rest, dl)) co_return std::nullopt;
            co_return rx.decrypt_body(recv_seq++, hdr, rest)
                .transform([](auto v) { return std::optional<std::vector<std::uint8_t>>(std::move(v)); })
                .value_or(std::nullopt);
        }
        auto make_kexinit(std::string_view cipher, bool initial) -> std::vector<std::uint8_t> {
            ssh::KexInit ki{};
            (void)crypto::random_bytes(ki.cookie);
            ki.kex_algorithms = initial ? ("curve25519-sha256," + std::string(ssh::kStrictServerKex)) : "curve25519-sha256";
            ki.server_host_key_algorithms = "ssh-ed25519";
            ki.enc_c2s = ki.enc_s2c = std::string(cipher);
            ki.mac_c2s = ki.mac_s2c = "hmac-sha2-256";
            return ssh::encode_kexinit(ki);
        }
        auto do_kex(bool initial, std::optional<std::vector<std::uint8_t>> client_ic,
                    std::optional<std::vector<std::uint8_t>> sent_is, std::string_view cipher,
                    ssh::PrivateKey const& host_key, Clock::time_point dl, bool send_ignore = false) -> capy::task<bool> {
            std::vector<std::uint8_t> is_pkt = sent_is ? std::move(*sent_is) : make_kexinit(cipher, initial);
            if (!sent_is && !co_await send_pkt(is_pkt, dl)) co_return false;
            std::vector<std::uint8_t> ic_pkt;
            if (client_ic) ic_pkt = std::move(*client_ic);
            else {
                for (;;) {
                    auto p = co_await recv_pkt(dl);
                    if (!p || p->empty()) co_return false;
                    if ((*p)[0] == ssh::kMsgKexInit) { ic_pkt = std::move(*p); break; }
                    // Per RFC 4253 §7.1, peer may have in-flight packets before receiving our KEXINIT.
                    if ((*p)[0] == ssh::kMsgChannelData) {
                        ssh::Reader r{std::span(*p).subspan(1)}; (void)r.u32();
                        if (auto d = r.text()) inflight_before_kex.append(*d);
                    }
                }
            }
            auto ci = ssh::decode_kexinit(ic_pkt);
            if (!ci) co_return false;
            if (initial) strict_kex = ssh::list_contains(ci->kex_algorithms, ssh::kStrictClientKex);
            auto ck = ssh::parse_cipher_kind(cipher);
            if (!ck) co_return false;
            auto ke = co_await recv_pkt(dl);
            if (!ke || ke->empty() || (*ke)[0] != ssh::kMsgKexEcdhInit) { saw_proto_violation = true; co_return false; }
            ssh::Reader kr{std::span(*ke).subspan(1)};
            auto qc = kr.string();
            if (!qc || qc->size() != 32) co_return false;
            auto eph = crypto::X25519Private::generate();
            if (!eph) co_return false;
            auto qs = eph->public_key();
            auto shared = eph->agree(*qc);
            if (!qs || !shared) co_return false;
            auto h = ssh::compute_exchange_hash(client_banner, kBanner, ic_pkt, is_pkt, host_key.public_key_blob(), *qc, *qs, shared->view());
            auto sig = h ? host_key.sign(*h) : std::unexpected(std::string("h"));
            if (!h || !sig) co_return false;
            if (initial) session_id = *h;
            if (send_ignore) {
                ssh::Writer ig; ig.byte(ssh::kMsgIgnore).string("rekey-noise");
                if (!co_await send_pkt(ig.buf, dl)) co_return false;
            }
            ssh::Writer reply;
            reply.byte(ssh::kMsgKexEcdhReply).string(host_key.public_key_blob()).string(*qs).string(*sig);
            if (!co_await send_pkt(reply.buf, dl)) co_return false;
            auto iv_cs = ssh::derive_key(shared->view(), *h, 'A', session_id, ssh::cipher_iv_bytes(*ck));
            auto iv_sc = ssh::derive_key(shared->view(), *h, 'B', session_id, ssh::cipher_iv_bytes(*ck));
            auto k_cs = ssh::derive_key(shared->view(), *h, 'C', session_id, ssh::cipher_key_bytes(*ck));
            auto k_sc = ssh::derive_key(shared->view(), *h, 'D', session_id, ssh::cipher_key_bytes(*ck));
            if (!iv_cs || !iv_sc || !k_cs || !k_sc) co_return false;
            std::array<std::uint8_t, 1> nk{ssh::kMsgNewKeys};
            if (!co_await send_pkt(nk, dl, initial) || !tx.activate(*ck, *k_sc, *iv_sc)) co_return false;
            auto cnk = co_await recv_pkt(dl);
            if (!cnk || cnk->size() != 1 || (*cnk)[0] != ssh::kMsgNewKeys) { saw_proto_violation = true; co_return false; }
            if (initial && strict_kex) recv_seq = 0;
            if (!rx.activate(*ck, *k_cs, *iv_cs)) co_return false;
            if (!initial) ++rekeys_done;
            co_return true;
        }
        auto handshake_and_open(ssh::PrivateKey const& host_key, Clock::time_point dl) -> capy::task<std::optional<std::uint32_t>> {
            std::string bw = std::string(kBanner) + "\r\n";
            if (!co_await stream.send(std::span<std::uint8_t const>(reinterpret_cast<std::uint8_t const*>(bw.data()), bw.size()), dl)) co_return std::nullopt;
            if (!co_await read_banner(dl)) co_return std::nullopt;
            if (!co_await do_kex(true, std::nullopt, std::nullopt, "chacha20-poly1305@openssh.com", host_key, dl)) co_return std::nullopt;
            auto sr = co_await recv_pkt(dl);
            if (!sr || sr->empty() || (*sr)[0] != ssh::kMsgServiceRequest) co_return std::nullopt;
            ssh::Writer sa; sa.byte(ssh::kMsgServiceAccept).string("ssh-userauth");
            if (!co_await send_pkt(sa.buf, dl)) co_return std::nullopt;
            auto ua = co_await recv_pkt(dl);
            if (!ua || ua->empty() || (*ua)[0] != ssh::kMsgUserauthRequest) co_return std::nullopt;
            std::array<std::uint8_t, 1> ok{ssh::kMsgUserauthSuccess};
            if (!co_await send_pkt(ok, dl)) co_return std::nullopt;
            auto co_pkt = co_await recv_pkt(dl);
            if (!co_pkt || co_pkt->empty() || (*co_pkt)[0] != ssh::kMsgChannelOpen) co_return std::nullopt;
            ssh::Reader cr{std::span(*co_pkt).subspan(1)}; (void)cr.text();
            auto cid = cr.u32();
            if (!cid) co_return std::nullopt;
            ssh::Writer cf; cf.byte(ssh::kMsgChannelOpenConfirm).u32(*cid).u32(7u).u32(1024u * 1024u).u32(32768u);
            if (!co_await send_pkt(cf.buf, dl)) co_return std::nullopt;
            co_return *cid;
        }
        auto send_ch_data(std::uint32_t cid, std::string_view s, Clock::time_point dl) -> capy::task<bool> {
            ssh::Writer w; w.byte(ssh::kMsgChannelData).u32(cid).string(s);
            co_return co_await send_pkt(w.buf, dl);
        }
    };

    inline auto make_auth(ssh::PrivateKey const& host_key) -> ssh::ClientAuth {
        ssh::ClientAuth auth;
        auth.user = "tester";
        auth.password = "secret";
        auth.host_key_sha256.push_back(key_pin(host_key));
        auth.keepalive_interval_ms = 0;
        return auth;
    }

    inline auto read_str(ssh::Channel<MemStream>& ch, std::size_t want) -> capy::task<std::string> {
        std::string out;
        std::array<std::uint8_t, 256> buf{};
        while (out.size() < want) {
            auto r = co_await ch.read(std::span(buf).first(std::min(buf.size(), want - out.size())));
            if (!r || *r == 0) break;
            out.append(reinterpret_cast<char const*>(buf.data()), *r);
        }
        co_return out;
    }

    inline auto send_str(ssh::Channel<MemStream>& ch, std::string_view s) -> capy::task<bool> {
        co_return co_await ch.send(std::span<std::uint8_t const>(reinterpret_cast<std::uint8_t const*>(s.data()), s.size()));
    }
}
