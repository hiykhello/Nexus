module openconnect.dtls;
import std;
import crypto;
import tls.schedule;

namespace openconnect {
    namespace {
        constexpr std::uint8_t kCtChangeCipherSpec = 20;
        constexpr std::uint8_t kCtHandshake = 22;
        constexpr std::uint8_t kCtApplicationData = 23;
        constexpr std::uint8_t kHsClientHello = 1;
        constexpr std::uint8_t kHsServerHello = 2;
        constexpr std::uint8_t kHsFinished = 20;

        auto append_be16(std::vector<std::uint8_t>& out, std::uint16_t v) -> void {
            out.push_back(static_cast<std::uint8_t>(v >> 8));
            out.push_back(static_cast<std::uint8_t>(v));
        }

        auto append_be24(std::vector<std::uint8_t>& out, std::uint32_t v) -> void {
            out.push_back(static_cast<std::uint8_t>(v >> 16));
            out.push_back(static_cast<std::uint8_t>(v >> 8));
            out.push_back(static_cast<std::uint8_t>(v));
        }

        auto append_be48(std::vector<std::uint8_t>& out, std::uint64_t v) -> void {
            for (int shift = 40; shift >= 0; shift -= 8)
                out.push_back(static_cast<std::uint8_t>(v >> shift));
        }

        auto read_be16(std::span<std::uint8_t const> s, std::size_t off) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((std::uint16_t(s[off]) << 8) | s[off + 1]);
        }

        auto read_be48(std::span<std::uint8_t const> s, std::size_t off) noexcept -> std::uint64_t {
            std::uint64_t v = 0;
            for (std::size_t i = 0; i < 6; ++i) v = (v << 8) | s[off + i];
            return v;
        }

        auto to_aead(DtlsCipher c) noexcept -> crypto::Aead {
            if (c == DtlsCipher::aes_128_gcm) return crypto::Aead::aes_128_gcm;
            if (c == DtlsCipher::chacha20_poly1305) return crypto::Aead::chacha20_poly1305;
            return crypto::Aead::aes_256_gcm;
        }

        auto key_length(DtlsCipher c) noexcept -> std::size_t {
            return c == DtlsCipher::aes_128_gcm ? 16u : 32u;
        }

        auto hash_for(DtlsCipher c) noexcept -> crypto::Hash {
            return c == DtlsCipher::aes_256_gcm ? crypto::Hash::sha384 : crypto::Hash::sha256;
        }

        auto cipher_suite_id(DtlsVersion v, DtlsCipher c) noexcept -> std::uint16_t {
            if (v == DtlsVersion::dtls1_3) {
                if (c == DtlsCipher::aes_128_gcm) return 0x1301u;
                if (c == DtlsCipher::chacha20_poly1305) return 0x1303u;
                return 0x1302u;
            }
            if (c == DtlsCipher::aes_128_gcm) return 0xc02fu;
            if (c == DtlsCipher::chacha20_poly1305) return 0xcca8u;
            return 0xc030u;
        }

        // RFC 5246 Section 5 P_hash TLS 1.2 PRF.
        auto tls12_prf(crypto::Hash hash, std::span<std::uint8_t const> secret,
                       std::string_view label, std::span<std::uint8_t const> seed,
                       std::size_t length) -> std::expected<crypto::Bytes, std::string> {
            crypto::Bytes input(label.begin(), label.end());
            input.insert(input.end(), seed.begin(), seed.end());
            auto a = crypto::hmac(hash, secret, input);
            if (!a) return std::unexpected("DTLS 1.2 PRF HMAC failed");
            crypto::Bytes out, buf;
            out.reserve(length);
            struct Wipe {
                crypto::Bytes& a_ref; crypto::Bytes& b_ref;
                ~Wipe() { crypto::cleanse(a_ref); crypto::cleanse(b_ref); }
            } wipe{*a, buf};
            while (out.size() < length) {
                buf.clear();
                buf.insert(buf.end(), a->begin(), a->end());
                buf.insert(buf.end(), input.begin(), input.end());
                auto block = crypto::hmac(hash, secret, buf);
                if (!block) return std::unexpected("DTLS 1.2 PRF expand failed");
                auto take = std::min(block->size(), length - out.size());
                out.insert(out.end(), block->begin(), block->begin() + static_cast<std::ptrdiff_t>(take));
                crypto::cleanse(*block);
                if (out.size() < length) {
                    auto next_a = crypto::hmac(hash, secret, *a);
                    if (!next_a) return std::unexpected("DTLS 1.2 PRF iterate failed");
                    crypto::cleanse(*a);
                    *a = std::move(*next_a);
                }
            }
            return out;
        }

        auto build_dtls_plaintext_record(std::uint8_t content_type, std::uint16_t wire_ver,
                                         std::uint16_t epoch, std::uint64_t seq,
                                         std::span<std::uint8_t const> payload) -> std::vector<std::uint8_t> {
            std::vector<std::uint8_t> out;
            out.reserve(13 + payload.size());
            out.push_back(content_type);
            append_be16(out, wire_ver);
            append_be16(out, epoch);
            append_be48(out, seq);
            append_be16(out, static_cast<std::uint16_t>(payload.size()));
            out.insert(out.end(), payload.begin(), payload.end());
            return out;
        }

        auto build_dtls_handshake_msg(std::uint8_t msg_type, std::uint16_t msg_seq,
                                      std::span<std::uint8_t const> body) -> std::vector<std::uint8_t> {
            std::vector<std::uint8_t> out;
            out.reserve(12 + body.size());
            out.push_back(msg_type);
            append_be24(out, static_cast<std::uint32_t>(body.size()));
            append_be16(out, msg_seq);
            append_be24(out, 0);
            append_be24(out, static_cast<std::uint32_t>(body.size()));
            out.insert(out.end(), body.begin(), body.end());
            return out;
        }

        auto xor_nonce12(std::span<std::uint8_t const> static_iv, std::uint16_t epoch,
                         std::uint64_t seq) noexcept -> std::array<std::uint8_t, 12> {
            std::array<std::uint8_t, 12> nonce{};
            std::copy_n(static_iv.begin(), 12, nonce.begin());
            nonce[4] ^= static_cast<std::uint8_t>(epoch >> 8);
            nonce[5] ^= static_cast<std::uint8_t>(epoch);
            for (std::size_t i = 0; i < 6; ++i)
                nonce[6 + i] ^= static_cast<std::uint8_t>(seq >> ((5 - i) * 8));
            return nonce;
        }
    }

    DtlsTransport::~DtlsTransport() { reset(); }

    auto DtlsTransport::reset() noexcept -> void {
        crypto::cleanse(master_secret_);
        crypto::cleanse(tx_key_); crypto::cleanse(rx_key_);
        crypto::cleanse(tx_iv_); crypto::cleanse(rx_iv_);
        tx_key_.clear(); rx_key_.clear(); tx_iv_.clear(); rx_iv_.clear();
        handshake_transcript_.clear(); session_id_.clear();
        tx_epoch_ = rx_epoch_ = 0; tx_seq_ = 0;
        rx_replay_.reset(); keys_ready_ = false; state_ = DtlsState::idle;
    }

    auto DtlsTransport::init(DtlsConfig const& config) -> std::expected<void, std::string> {
        reset();
        if (config.version != DtlsVersion::dtls1_2 && config.version != DtlsVersion::dtls1_3)
            return std::unexpected("unsupported DTLS version");
        if (config.session_id.empty() || config.session_id.size() > 32)
            return std::unexpected("invalid DTLS session ID length");
        version_ = config.version;
        cipher_ = config.cipher;
        server_role_ = config.server_role;
        mtu_ = std::clamp<std::uint16_t>(config.mtu, 576, 9000);
        session_id_ = config.session_id;
        master_secret_ = config.master_secret;
        return {};
    }

    auto DtlsTransport::derive_traffic_keys() -> std::expected<void, std::string> {
        auto klen = key_length(cipher_);
        auto hash = hash_for(cipher_);
        if (version_ == DtlsVersion::dtls1_2) {
            std::size_t iv_len = (cipher_ == DtlsCipher::chacha20_poly1305) ? 12u : 4u;
            std::array<std::uint8_t, 64> seed{};
            std::ranges::copy(server_random_, seed.begin());
            std::ranges::copy(client_random_, seed.begin() + 32);
            auto kb = tls12_prf(hash, master_secret_, "key expansion", seed, 2 * (klen + iv_len));
            if (!kb) return std::unexpected(kb.error());
            struct Wipe { crypto::Bytes& b; ~Wipe() { crypto::cleanse(b); } } wipe{*kb};
            auto c_key = std::span<std::uint8_t const>(*kb).subspan(0, klen);
            auto s_key = std::span<std::uint8_t const>(*kb).subspan(klen, klen);
            auto c_iv = std::span<std::uint8_t const>(*kb).subspan(2 * klen, iv_len);
            auto s_iv = std::span<std::uint8_t const>(*kb).subspan(2 * klen + iv_len, iv_len);
            tx_key_.assign(server_role_ ? s_key.begin() : c_key.begin(), server_role_ ? s_key.end() : c_key.end());
            rx_key_.assign(server_role_ ? c_key.begin() : s_key.begin(), server_role_ ? c_key.end() : s_key.end());
            tx_iv_.assign(server_role_ ? s_iv.begin() : c_iv.begin(), server_role_ ? s_iv.end() : c_iv.end());
            rx_iv_.assign(server_role_ ? c_iv.begin() : s_iv.begin(), server_role_ ? c_iv.end() : s_iv.end());
        } else {
            auto th = crypto::digest(hash, handshake_transcript_);
            if (!th) return std::unexpected("DTLS 1.3 transcript digest failed");
            auto prk = crypto::hkdf_extract(hash, {}, master_secret_);
            if (!prk) return std::unexpected("DTLS 1.3 HKDF extract failed");
            struct Wipe { crypto::Bytes& b; ~Wipe() { crypto::cleanse(b); } } wipe{*prk};
            auto c_sec = tls::expand_label(hash, *prk, "c ap traffic", *th, th->size());
            auto s_sec = tls::expand_label(hash, *prk, "s ap traffic", *th, th->size());
            if (!c_sec || !s_sec) return std::unexpected("DTLS 1.3 traffic secret derivation failed");
            auto c_key = tls::expand_label(hash, c_sec->view(), "key", {}, klen);
            auto c_iv = tls::expand_label(hash, c_sec->view(), "iv", {}, 12);
            auto s_key = tls::expand_label(hash, s_sec->view(), "key", {}, klen);
            auto s_iv = tls::expand_label(hash, s_sec->view(), "iv", {}, 12);
            if (!c_key || !c_iv || !s_key || !s_iv) return std::unexpected("DTLS 1.3 key/iv expansion failed");
            tx_key_.assign((server_role_ ? s_key : c_key)->view().begin(), (server_role_ ? s_key : c_key)->view().end());
            rx_key_.assign((server_role_ ? c_key : s_key)->view().begin(), (server_role_ ? c_key : s_key)->view().end());
            tx_iv_.assign((server_role_ ? s_iv : c_iv)->view().begin(), (server_role_ ? s_iv : c_iv)->view().end());
            rx_iv_.assign((server_role_ ? c_iv : s_iv)->view().begin(), (server_role_ ? c_iv : s_iv)->view().end());
        }
        keys_ready_ = true;
        return {};
    }

    auto DtlsTransport::compute_verify_data(bool for_server) const
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        auto hash = hash_for(cipher_);
        auto th = crypto::digest(hash, handshake_transcript_);
        if (!th) return std::unexpected("DTLS transcript hash failed");
        if (version_ == DtlsVersion::dtls1_2)
            return tls12_prf(hash, master_secret_, for_server ? "server finished" : "client finished", *th, 12);
        auto prk = crypto::hkdf_extract(hash, {}, master_secret_);
        if (!prk) return std::unexpected("DTLS 1.3 finished HKDF failed");
        struct Wipe { crypto::Bytes& b; ~Wipe() { crypto::cleanse(b); } } wipe{*prk};
        auto fk = tls::expand_label(hash, *prk, for_server ? "dtls13 s fin" : "dtls13 c fin", {}, th->size());
        if (!fk) return std::unexpected("DTLS 1.3 finished key expansion failed");
        auto mac = crypto::hmac(hash, fk->view(), *th);
        if (!mac) return std::unexpected("DTLS 1.3 finished HMAC failed");
        return std::move(*mac);
    }

    auto DtlsTransport::build_client_hello() -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (server_role_ || state_ != DtlsState::idle) return std::unexpected("DTLS ClientHello invalid state");
        if (!crypto::random_bytes(client_random_)) return std::unexpected("DTLS RNG failure");
        std::vector<std::uint8_t> body;
        append_be16(body, 0xfefdu); // RFC 9147 §5.3: legacy_version is always DTLS 1.2 (0xfefd)
        body.insert(body.end(), client_random_.begin(), client_random_.end());
        body.push_back(static_cast<std::uint8_t>(session_id_.size()));
        body.insert(body.end(), session_id_.begin(), session_id_.end());
        body.push_back(0); // empty cookie
        append_be16(body, 2);
        append_be16(body, cipher_suite_id(version_, cipher_));
        body.push_back(1); body.push_back(0);
        detail::append_supported_versions_ch(body, version_);
        auto hs = build_dtls_handshake_msg(kHsClientHello, 0, body);
        handshake_transcript_.assign(hs.begin(), hs.end());
        state_ = DtlsState::client_hello_sent;
        return build_dtls_plaintext_record(kCtHandshake, 0xfefd, 0, tx_seq_++, hs);
    }

    auto DtlsTransport::seal_record(std::uint8_t content_type, std::span<std::uint8_t const> plaintext)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (!keys_ready_) return std::unexpected("DTLS keys not established");
        if (plaintext.size() > 16384u) return std::unexpected("DTLS plaintext exceeds 16384-byte record limit");
        if (tx_seq_ >= (std::uint64_t{1} << 48) - 1) return std::unexpected("DTLS sequence exhausted");
        std::uint64_t seq = tx_seq_++;
        auto aead = to_aead(cipher_);

        if (version_ == DtlsVersion::dtls1_2) {
            std::array<std::uint8_t, 13> aad{};
            aad[0] = static_cast<std::uint8_t>(tx_epoch_ >> 8);
            aad[1] = static_cast<std::uint8_t>(tx_epoch_);
            for (std::size_t i = 0; i < 6; ++i) aad[2 + i] = static_cast<std::uint8_t>(seq >> ((5 - i) * 8));
            aad[8] = content_type; aad[9] = 0xfe; aad[10] = 0xfd;
            aad[11] = static_cast<std::uint8_t>(plaintext.size() >> 8);
            aad[12] = static_cast<std::uint8_t>(plaintext.size());
            std::array<std::uint8_t, 12> nonce{};
            bool explicit_nonce = (cipher_ != DtlsCipher::chacha20_poly1305);
            if (explicit_nonce) {
                std::copy_n(tx_iv_.begin(), 4, nonce.begin());
                std::copy_n(aad.begin(), 8, nonce.begin() + 4);
            } else {
                nonce = xor_nonce12(tx_iv_, tx_epoch_, seq);
            }
            auto ct = crypto::seal(aead, tx_key_, nonce, plaintext, aad);
            if (!ct) return std::unexpected("DTLS 1.2 AEAD seal failed");
            std::vector<std::uint8_t> frag;
            frag.reserve((explicit_nonce ? 8u : 0u) + ct->size());
            if (explicit_nonce) frag.insert(frag.end(), aad.begin(), aad.begin() + 8);
            frag.insert(frag.end(), ct->begin(), ct->end());
            return build_dtls_plaintext_record(content_type, 0xfefd, tx_epoch_, seq, frag);
        }

        // DTLS 1.3 (RFC 9147) unified short header: [flags:1][seq16:2][len16:2][ciphertext].
        std::vector<std::uint8_t> inner(plaintext.begin(), plaintext.end());
        inner.push_back(content_type);
        std::array<std::uint8_t, 5> hdr{};
        hdr[0] = static_cast<std::uint8_t>(0x2cu | (tx_epoch_ & 0x03u));
        hdr[1] = static_cast<std::uint8_t>(seq >> 8);
        hdr[2] = static_cast<std::uint8_t>(seq);
        auto ct_len = static_cast<std::uint16_t>(inner.size() + 16);
        hdr[3] = static_cast<std::uint8_t>(ct_len >> 8);
        hdr[4] = static_cast<std::uint8_t>(ct_len);
        auto ct = crypto::seal(aead, tx_key_, xor_nonce12(tx_iv_, tx_epoch_, seq), inner, hdr);
        crypto::cleanse(inner);
        if (!ct) return std::unexpected("DTLS 1.3 AEAD seal failed");
        std::vector<std::uint8_t> out;
        out.reserve(hdr.size() + ct->size());
        out.insert(out.end(), hdr.begin(), hdr.end());
        out.insert(out.end(), ct->begin(), ct->end());
        return out;
    }

    auto DtlsTransport::open_record(std::span<std::uint8_t const> datagram)
        -> std::expected<std::pair<std::uint8_t, std::vector<std::uint8_t>>, std::string> {
        if (!keys_ready_) return std::unexpected("DTLS keys not established");
        auto aead = to_aead(cipher_);

        if (version_ == DtlsVersion::dtls1_2) {
            if (datagram.size() < 13) return std::unexpected("truncated DTLS 1.2 record");
            auto ct_type = datagram[0];
            auto epoch = read_be16(datagram, 3);
            auto seq = read_be48(datagram, 5);
            auto frag_len = read_be16(datagram, 11);
            if (epoch != rx_epoch_ || datagram.size() < 13u + frag_len)
                return std::unexpected("invalid DTLS 1.2 epoch or length");
            auto frag = datagram.subspan(13, frag_len);
            bool explicit_nonce = (cipher_ != DtlsCipher::chacha20_poly1305);
            if (frag.size() < (explicit_nonce ? 8u : 0u) + 16u)
                return std::unexpected("truncated DTLS 1.2 ciphertext");
            std::array<std::uint8_t, 12> nonce{};
            std::span<std::uint8_t const> ct = frag;
            if (explicit_nonce) {
                std::copy_n(rx_iv_.begin(), 4, nonce.begin());
                std::copy_n(frag.begin(), 8, nonce.begin() + 4);
                ct = frag.subspan(8);
            } else {
                nonce = xor_nonce12(rx_iv_, epoch, seq);
            }
            std::size_t pt_len = ct.size() - 16u;
            std::array<std::uint8_t, 13> aad{};
            std::copy_n(datagram.begin() + 3, 8, aad.begin());
            aad[8] = ct_type; aad[9] = datagram[1]; aad[10] = datagram[2];
            aad[11] = static_cast<std::uint8_t>(pt_len >> 8);
            aad[12] = static_cast<std::uint8_t>(pt_len);
            auto pt = crypto::open(aead, rx_key_, nonce, ct, aad);
            if (!pt) return std::unexpected("DTLS 1.2 AEAD authentication failed");
            if (!rx_replay_.check_and_record(seq)) {
                crypto::cleanse(*pt);
                return std::unexpected("DTLS 1.2 replay detected");
            }
            return std::pair{ct_type, std::move(*pt)};
        }

        if (datagram.size() < 5 + 17) return std::unexpected("truncated DTLS 1.3 record");
        if ((datagram[0] & 0xfcu) != 0x2cu) return std::unexpected("unsupported DTLS 1.3 short header flags");
        if ((datagram[0] & 0x03u) != (rx_epoch_ & 0x03u)) return std::unexpected("DTLS 1.3 epoch mismatch");
        std::uint64_t seq = rx_replay_.reconstruct_seq16(read_be16(datagram, 1));
        auto ct_len = read_be16(datagram, 3);
        if (datagram.size() < 5u + ct_len || ct_len < 17) return std::unexpected("invalid DTLS 1.3 length");
        auto inner = crypto::open(aead, rx_key_, xor_nonce12(rx_iv_, rx_epoch_, seq),
                                  datagram.subspan(5, ct_len), datagram.first(5));
        if (!inner || inner->empty()) return std::unexpected("DTLS 1.3 AEAD authentication failed");
        if (!rx_replay_.check_and_record(seq)) {
            crypto::cleanse(*inner);
            return std::unexpected("DTLS 1.3 replay detected");
        }
        while (!inner->empty() && inner->back() == 0) inner->pop_back();
        if (inner->empty()) return std::unexpected("DTLS 1.3 missing inner content type");
        auto inner_ct = inner->back();
        inner->pop_back();
        return std::pair{inner_ct, std::move(*inner)};
    }

    auto DtlsTransport::on_handshake_datagram(std::span<std::uint8_t const> datagram)
        -> std::expected<std::vector<std::vector<std::uint8_t>>, std::string> {
        std::vector<std::vector<std::uint8_t>> replies;
        if (server_role_ && state_ == DtlsState::idle) {
            if (datagram.size() < 13 + 12 + 35 || datagram[0] != kCtHandshake)
                return std::unexpected("expected DTLS ClientHello");
            auto frag_len = read_be16(datagram, 11);
            if (datagram.size() < 13u + frag_len) return std::unexpected("truncated DTLS ClientHello");
            auto hs = datagram.subspan(13, frag_len);
            if (hs.size() < 12 + 35 || hs[0] != kHsClientHello) return std::unexpected("invalid DTLS ClientHello");
            auto body = hs.subspan(12);
            auto sid_len = body[34];
            if (body.size() < 35u + sid_len || sid_len != session_id_.size() ||
                !crypto::constant_time_equal(body.subspan(35, sid_len), session_id_))
                return std::unexpected("DTLS session ID mismatch");
            if (auto vok = detail::validate_client_hello_version(body, 35u + sid_len, version_); !vok)
                return std::unexpected(vok.error());
            std::copy_n(body.begin() + 2, 32, client_random_.begin());
            handshake_transcript_.assign(hs.begin(), hs.end());
            if (!crypto::random_bytes(server_random_)) return std::unexpected("DTLS RNG failure");

            std::vector<std::uint8_t> sh_body;
            append_be16(sh_body, 0xfefdu); // RFC 9147 §5.3: legacy_version is always DTLS 1.2 (0xfefd)
            sh_body.insert(sh_body.end(), server_random_.begin(), server_random_.end());
            sh_body.push_back(static_cast<std::uint8_t>(session_id_.size()));
            sh_body.insert(sh_body.end(), session_id_.begin(), session_id_.end());
            append_be16(sh_body, cipher_suite_id(version_, cipher_));
            sh_body.push_back(0);
            detail::append_supported_versions_sh(sh_body, version_);
            auto sh = build_dtls_handshake_msg(kHsServerHello, 0, sh_body);
            handshake_transcript_.insert(handshake_transcript_.end(), sh.begin(), sh.end());
            replies.push_back(build_dtls_plaintext_record(kCtHandshake, 0xfefd, 0, tx_seq_++, sh));

            if (auto derived = derive_traffic_keys(); !derived) return std::unexpected(derived.error());
            if (version_ == DtlsVersion::dtls1_2) {
                std::array<std::uint8_t, 1> ccs{1};
                replies.push_back(build_dtls_plaintext_record(kCtChangeCipherSpec, 0xfefd, 0, tx_seq_++, ccs));
            }
            tx_epoch_ = 1; rx_epoch_ = 1; tx_seq_ = 0; rx_replay_.reset();
            auto sfin_vd = compute_verify_data(true);
            if (!sfin_vd) return std::unexpected(sfin_vd.error());
            auto sfin = build_dtls_handshake_msg(kHsFinished, 1, *sfin_vd);
            auto sfin_rec = seal_record(kCtHandshake, sfin);
            if (!sfin_rec) return std::unexpected(sfin_rec.error());
            handshake_transcript_.insert(handshake_transcript_.end(), sfin.begin(), sfin.end());
            replies.push_back(std::move(*sfin_rec));
            state_ = DtlsState::server_hello_sent;
            return replies;
        }

        if (!server_role_ && state_ == DtlsState::client_hello_sent) {
            if (!keys_ready_) {
                if (datagram.size() < 13 + 12 + 35 || datagram[0] != kCtHandshake)
                    return std::unexpected("expected DTLS ServerHello");
                auto frag_len = read_be16(datagram, 11);
                if (datagram.size() < 13u + frag_len) return std::unexpected("truncated DTLS ServerHello");
                auto hs = datagram.subspan(13, frag_len);
                if (hs.size() < 12 + 35 || hs[0] != kHsServerHello) return std::unexpected("invalid DTLS ServerHello");
                auto body = hs.subspan(12);
                auto sid_len = body[34];
                if (body.size() < 35u + sid_len || sid_len != session_id_.size() ||
                    !crypto::constant_time_equal(body.subspan(35, sid_len), session_id_))
                    return std::unexpected("DTLS ServerHello session ID mismatch");
                if (auto vok = detail::validate_server_hello_version(body, 35u + sid_len, version_); !vok)
                    return std::unexpected(vok.error());
                std::copy_n(body.begin() + 2, 32, server_random_.begin());
                handshake_transcript_.insert(handshake_transcript_.end(), hs.begin(), hs.end());
                if (auto derived = derive_traffic_keys(); !derived) return std::unexpected(derived.error());
                rx_epoch_ = 1; rx_replay_.reset();
                return replies;
            }
            if (version_ == DtlsVersion::dtls1_2 && !datagram.empty() && datagram[0] == kCtChangeCipherSpec)
                return replies;
            auto opened = open_record(datagram);
            if (!opened || opened->first != kCtHandshake || opened->second.size() < 12 || opened->second[0] != kHsFinished)
                return std::unexpected("invalid DTLS Server Finished");
            auto expected_sfin = compute_verify_data(true);
            if (!expected_sfin) return std::unexpected(expected_sfin.error());
            if (!crypto::constant_time_equal(std::span<std::uint8_t const>(opened->second).subspan(12), *expected_sfin))
                return std::unexpected("DTLS Server Finished verification failed");
            handshake_transcript_.insert(handshake_transcript_.end(), opened->second.begin(), opened->second.end());
            if (version_ == DtlsVersion::dtls1_2) {
                std::array<std::uint8_t, 1> ccs{1};
                replies.push_back(build_dtls_plaintext_record(kCtChangeCipherSpec, 0xfefd, 0, tx_seq_++, ccs));
            }
            tx_epoch_ = 1; tx_seq_ = 0;
            auto cfin_vd = compute_verify_data(false);
            if (!cfin_vd) return std::unexpected(cfin_vd.error());
            auto cfin = build_dtls_handshake_msg(kHsFinished, 1, *cfin_vd);
            auto cfin_rec = seal_record(kCtHandshake, cfin);
            if (!cfin_rec) return std::unexpected(cfin_rec.error());
            replies.push_back(std::move(*cfin_rec));
            state_ = DtlsState::established;
            return replies;
        }

        if (server_role_ && state_ == DtlsState::server_hello_sent) {
            if (version_ == DtlsVersion::dtls1_2 && !datagram.empty() && datagram[0] == kCtChangeCipherSpec)
                return replies;
            auto opened = open_record(datagram);
            if (!opened || opened->first != kCtHandshake || opened->second.size() < 12 || opened->second[0] != kHsFinished)
                return std::unexpected("invalid DTLS Client Finished");
            auto expected_cfin = compute_verify_data(false);
            if (!expected_cfin) return std::unexpected(expected_cfin.error());
            if (!crypto::constant_time_equal(std::span<std::uint8_t const>(opened->second).subspan(12), *expected_cfin))
                return std::unexpected("DTLS Client Finished verification failed");
            state_ = DtlsState::established;
            return replies;
        }
        return std::unexpected("unexpected DTLS handshake datagram for current state");
    }

    auto DtlsTransport::seal_tunnel_frame(CstpType type, std::span<std::uint8_t const> payload)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (state_ != DtlsState::established) return std::unexpected("DTLS tunnel not established");
        if (payload.size() > 16383u) return std::unexpected("DTLS payload exceeds 16383-byte limit");
        std::vector<std::uint8_t> plain;
        plain.reserve(1 + payload.size());
        plain.push_back(static_cast<std::uint8_t>(type));
        plain.insert(plain.end(), payload.begin(), payload.end());
        return seal_record(kCtApplicationData, plain);
    }

    auto DtlsTransport::open_tunnel_frame(std::span<std::uint8_t const> datagram)
        -> std::expected<CstpFrame, std::string> {
        if (state_ != DtlsState::established) return std::unexpected("DTLS tunnel not established");
        auto opened = open_record(datagram);
        if (!opened) return std::unexpected(opened.error());
        if (opened->first != kCtApplicationData || opened->second.empty())
            return std::unexpected("expected DTLS application data");
        auto raw_type = opened->second[0];
        if (raw_type != 0x00 && raw_type != 0x03 && raw_type != 0x04 &&
            raw_type != 0x05 && raw_type != 0x07 && raw_type != 0x08)
            return std::unexpected("unknown OpenConnect DTLS frame type");
        return CstpFrame{static_cast<CstpType>(raw_type),
                         std::vector<std::uint8_t>(opened->second.begin() + 1, opened->second.end())};
    }
}
