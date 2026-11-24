module ssh.crypto;
import std;
import crypto;
import encoding.endian;
import ssh.wire;
import boringssl;

extern "C" void BN_clear_free(boringssl::BIGNUM*);

namespace ssh {
    namespace b = ::boringssl;
    namespace {
        using encoding::read_be32;
        using encoding::write_be32;
        auto chacha_nonce(std::uint32_t seqno) noexcept -> std::array<std::uint8_t, 12> {
            std::array<std::uint8_t, 12> n{};
            write_be32(std::span<std::uint8_t, 4>(n.data() + 8, 4), seqno);
            return n;
        }
        auto decode_pem_body(std::string_view pem, std::string_view label) -> std::optional<std::vector<std::uint8_t>> {
            auto begin_marker = std::string("-----BEGIN ") + std::string(label) + "-----";
            auto end_marker = std::string("-----END ") + std::string(label) + "-----";
            auto pos = pem.find(begin_marker);
            if (pos == std::string_view::npos) return {};
            auto body_start = pos + begin_marker.size();
            auto end_pos = pem.find(end_marker, body_start);
            if (end_pos == std::string_view::npos) return {};
            return decode_base64(pem.substr(body_start, end_pos - body_start));
        }
        auto extract_p256_ec_key(std::span<std::uint8_t const> priv, std::span<std::uint8_t const> pub_oct,
                                 std::unique_ptr<b::EC_KEY, decltype(&b::EC_KEY_free)>& out) -> bool {
            out.reset(b::EC_KEY_new_by_curve_name(b::nid_x9_62_prime256v1));
            if (!out) return false;
            std::unique_ptr<b::BIGNUM, decltype(&::BN_clear_free)> d(
                b::BN_bin2bn(priv.data(), priv.size(), nullptr), ::BN_clear_free);
            if (!d || b::EC_KEY_set_private_key(out.get(), d.get()) != 1) return false;
            auto const* grp = b::EC_KEY_get0_group(out.get());
            std::unique_ptr<b::EC_POINT, decltype(&b::EC_POINT_free)> pt(b::EC_POINT_new(grp), b::EC_POINT_free);
            if (!pt || b::EC_POINT_oct2point(grp, pt.get(), pub_oct.data(), pub_oct.size(), nullptr) != 1) return false;
            return b::EC_KEY_set_public_key(out.get(), pt.get()) == 1;
        }
        auto parse_ecdsa_p256_pub_blob(std::span<std::uint8_t const> blob,
                                       std::unique_ptr<b::EC_KEY, decltype(&b::EC_KEY_free)>& out) -> bool {
            Reader r{blob};
            auto alg = r.text();
            auto curve = r.text();
            auto oct = r.string();
            if (!alg || !curve || !oct || !r.empty() || *alg != "ecdsa-sha2-nistp256" || *curve != "nistp256" || oct->size() != 65)
                return false;
            out.reset(b::EC_KEY_new_by_curve_name(b::nid_x9_62_prime256v1));
            if (!out) return false;
            auto const* grp = b::EC_KEY_get0_group(out.get());
            std::unique_ptr<b::EC_POINT, decltype(&b::EC_POINT_free)> pt(b::EC_POINT_new(grp), b::EC_POINT_free);
            if (!pt || b::EC_POINT_oct2point(grp, pt.get(), oct->data(), oct->size(), nullptr) != 1) return false;
            return b::EC_KEY_set_public_key(out.get(), pt.get()) == 1;
        }
        auto bn_bytes(b::BIGNUM const* v) -> std::vector<std::uint8_t> {
            std::vector<std::uint8_t> out(b::BN_num_bytes(v));
            if (!out.empty()) b::BN_bn2bin(v, out.data());
            return out;
        }
    }

    PrivateKey::~PrivateKey() { crypto::cleanse(secret_raw); }

    auto PrivateKey::operator=(PrivateKey&& other) noexcept -> PrivateKey& {
        if (this != &other) {
            crypto::cleanse(secret_raw);
            kind = other.kind;
            pub_blob = std::move(other.pub_blob);
            secret_raw = std::move(other.secret_raw);
        }
        return *this;
    }

    auto PrivateKey::parse(std::string_view pem) -> std::expected<PrivateKey, std::string> {
        if (auto der = decode_pem_body(pem, "OPENSSH PRIVATE KEY")) {
            struct Wipe { std::vector<std::uint8_t>& d; ~Wipe() { crypto::cleanse(d); } } wipe{*der};
            static constexpr std::string_view kMagic{"openssh-key-v1\0", 15};
            Reader r{*der};
            auto magic = r.bytes(kMagic.size());
            if (!magic || !std::ranges::equal(*magic,
                    std::span<std::uint8_t const>(reinterpret_cast<std::uint8_t const*>(kMagic.data()), kMagic.size())))
                return std::unexpected("invalid OpenSSH private key header");
            auto cipher = r.text(), kdf = r.text();
            auto kdf_opts = r.string();
            auto nkeys = r.u32();
            auto pub = r.string(), priv = r.string();
            if (!cipher || !kdf || !kdf_opts || !nkeys || *nkeys != 1 || !pub || !priv)
                return std::unexpected("malformed OpenSSH private key");
            if (*cipher != "none" || *kdf != "none")
                return std::unexpected("encrypted OpenSSH private keys are unsupported");
            Reader pr{*priv};
            auto c1 = pr.u32(), c2 = pr.u32();
            auto ktype = pr.text();
            if (!c1 || !c2 || *c1 != *c2 || !ktype) return std::unexpected("corrupt OpenSSH private key block");
            PrivateKey out;
            if (*ktype == "ssh-ed25519") {
                auto pk = pr.string(), sk = pr.string();
                auto comment = pr.text();
                if (!pk || !sk || !comment || pk->size() != 32 || sk->size() != 64 ||
                    !std::ranges::equal(*pk, sk->subspan(32, 32)))
                    return std::unexpected("invalid OpenSSH Ed25519 private key");
                out.kind = KeyKind::ed25519;
                Writer pw;
                pw.string("ssh-ed25519").string(*pk);
                out.pub_blob = std::move(pw.buf);
                out.secret_raw.assign(sk->begin(), sk->end());
                return out;
            }
            if (*ktype == "ecdsa-sha2-nistp256") {
                auto curve = pr.text();
                auto q = pr.string(), d = pr.mpint();
                auto comment = pr.text();
                if (!curve || !q || !d || !comment || *curve != "nistp256" || q->size() != 65 || d->empty() || d->size() > 32)
                    return std::unexpected("invalid OpenSSH ECDSA P-256 private key");
                out.kind = KeyKind::ecdsa_p256;
                Writer pw;
                pw.string("ecdsa-sha2-nistp256").string("nistp256").string(*q);
                out.pub_blob = std::move(pw.buf);
                out.secret_raw.assign(d->begin(), d->end());
                return out;
            }
            return std::unexpected("unsupported OpenSSH private key type: " + std::string(*ktype));
        }
        std::unique_ptr<b::BIO, decltype(&b::BIO_free)> bio(
            b::BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), b::BIO_free);
        if (!bio) return std::unexpected("out of memory reading PEM");
        std::unique_ptr<b::EVP_PKEY, decltype(&b::EVP_PKEY_free)> pkey(
            b::PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), b::EVP_PKEY_free);
        if (!pkey) return std::unexpected("unsupported or encrypted PEM private key");
        int type = b::EVP_PKEY_id(pkey.get());
        PrivateKey out;
        if (type == b::evp_pkey_ed25519) {
            std::array<std::uint8_t, 32> seed{}, pub{};
            std::size_t slen = 32;
            if (b::EVP_PKEY_get_raw_private_key(pkey.get(), seed.data(), &slen) != 1 || slen != 32) {
                crypto::cleanse(seed);
                return std::unexpected("failed reading Ed25519 raw seed");
            }
            out.kind = KeyKind::ed25519;
            out.secret_raw.resize(64);
            b::ED25519_keypair_from_seed(pub.data(), out.secret_raw.data(), seed.data());
            crypto::cleanse(seed);
            Writer pw;
            pw.string("ssh-ed25519").string(pub);
            out.pub_blob = std::move(pw.buf);
            return out;
        }
        if (type == b::evp_pkey_ec) {
            auto const* ec = b::EVP_PKEY_get0_EC_KEY(pkey.get());
            if (!ec || b::EC_GROUP_get_curve_name(b::EC_KEY_get0_group(ec)) != b::nid_x9_62_prime256v1)
                return std::unexpected("only P-256 ECDSA keys are supported");
            std::array<std::uint8_t, 65> oct{};
            auto len = b::EC_POINT_point2oct(b::EC_KEY_get0_group(ec), b::EC_KEY_get0_public_key(ec),
                b::point_conversion_uncompressed, oct.data(), oct.size(), nullptr);
            if (len != 65) return std::unexpected("failed encoding P-256 public key");
            b::BIGNUM const* d = b::EC_KEY_get0_private_key(ec);
            if (!d) return std::unexpected("missing ECDSA private scalar");
            out.kind = KeyKind::ecdsa_p256;
            out.secret_raw = bn_bytes(d);
            Writer pw;
            pw.string("ecdsa-sha2-nistp256").string("nistp256").string(oct);
            out.pub_blob = std::move(pw.buf);
            return out;
        }
        return std::unexpected("unsupported PEM key algorithm");
    }

    auto PrivateKey::sign(std::span<std::uint8_t const> msg) const -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (kind == KeyKind::ed25519) {
            if (secret_raw.size() != 64) return std::unexpected("invalid Ed25519 key state");
            std::array<std::uint8_t, 64> sig{};
            if (b::ED25519_sign(sig.data(), msg.data(), msg.size(), secret_raw.data()) != 1)
                return std::unexpected("Ed25519 signing failed");
            Writer w;
            w.string("ssh-ed25519").string(sig);
            return std::move(w.buf);
        }
        Reader pr{pub_blob};
        (void)pr.text(); (void)pr.text();
        auto q = pr.string();
        std::unique_ptr<b::EC_KEY, decltype(&b::EC_KEY_free)> ec(nullptr, b::EC_KEY_free);
        if (!q || !extract_p256_ec_key(secret_raw, *q, ec)) return std::unexpected("invalid ECDSA key state");
        auto digest = crypto::digest(crypto::Hash::sha256, msg);
        if (!digest) return std::unexpected("SHA-256 digest failed");
        std::unique_ptr<b::ECDSA_SIG, decltype(&b::ECDSA_SIG_free)> sig(
            b::ECDSA_do_sign(digest->data(), digest->size(), ec.get()), b::ECDSA_SIG_free);
        if (!sig) return std::unexpected("ECDSA signing failed");
        b::BIGNUM const* r = nullptr;
        b::BIGNUM const* s = nullptr;
        b::ECDSA_SIG_get0(sig.get(), &r, &s);
        Writer inner;
        inner.mpint(bn_bytes(r)).mpint(bn_bytes(s));
        Writer outer;
        outer.string("ecdsa-sha2-nistp256").string(inner.buf);
        return std::move(outer.buf);
    }

    auto verify_host_key(std::span<std::uint8_t const> host_key_blob,
                         std::span<std::array<std::uint8_t, 32> const> allowed_pins,
                         std::span<std::uint8_t const> exchange_hash,
                         std::span<std::uint8_t const> sig_blob) -> std::expected<void, std::string> {
        if (allowed_pins.empty()) return std::unexpected("SSH host-key-sha256 pin list is empty");
        auto fp = crypto::digest(crypto::Hash::sha256, host_key_blob);
        if (!fp || fp->size() != 32) return std::unexpected("SHA-256 host key hash failed");
        bool pinned = false;
        for (auto const& pin : allowed_pins)
            if (crypto::constant_time_equal(*fp, pin)) { pinned = true; break; }
        if (!pinned) return std::unexpected("SSH server host key does not match any host-key-sha256 pin");
        Reader sr{sig_blob};
        auto salg = sr.text();
        auto sdata = sr.string();
        if (!salg || !sdata || !sr.empty()) return std::unexpected("malformed SSH signature blob");
        if (*salg == "ssh-ed25519") {
            Reader kr{host_key_blob};
            auto kalg = kr.text();
            auto pk = kr.string();
            if (!kalg || !pk || !kr.empty() || *kalg != "ssh-ed25519" || pk->size() != 32 || sdata->size() != 64)
                return std::unexpected("malformed Ed25519 host key or signature");
            if (b::ED25519_verify(exchange_hash.data(), exchange_hash.size(), sdata->data(), pk->data()) != 1)
                return std::unexpected("SSH Ed25519 host signature verification failed");
            return {};
        }
        if (*salg == "ecdsa-sha2-nistp256") {
            std::unique_ptr<b::EC_KEY, decltype(&b::EC_KEY_free)> ec(nullptr, b::EC_KEY_free);
            if (!parse_ecdsa_p256_pub_blob(host_key_blob, ec))
                return std::unexpected("malformed ECDSA P-256 host key");
            Reader ir{*sdata};
            auto r_b = ir.mpint(), s_b = ir.mpint();
            if (!r_b || !s_b || !ir.empty()) return std::unexpected("malformed ECDSA P-256 signature");
            std::unique_ptr<b::ECDSA_SIG, decltype(&b::ECDSA_SIG_free)> sig(b::ECDSA_SIG_new(), b::ECDSA_SIG_free);
            std::unique_ptr<b::BIGNUM, decltype(&::BN_clear_free)> r_bn(b::BN_bin2bn(r_b->data(), r_b->size(), nullptr), ::BN_clear_free);
            std::unique_ptr<b::BIGNUM, decltype(&::BN_clear_free)> s_bn(b::BN_bin2bn(s_b->data(), s_b->size(), nullptr), ::BN_clear_free);
            if (!sig || !r_bn || !s_bn || b::ECDSA_SIG_set0(sig.get(), r_bn.get(), s_bn.get()) != 1)
                return std::unexpected("invalid ECDSA signature components");
            (void)r_bn.release();
            (void)s_bn.release();
            auto digest = crypto::digest(crypto::Hash::sha256, exchange_hash);
            if (!digest || b::ECDSA_do_verify(digest->data(), digest->size(), sig.get(), ec.get()) != 1)
                return std::unexpected("SSH ECDSA host signature verification failed");
            return {};
        }
        return std::unexpected("unsupported SSH host key algorithm: " + std::string(*salg));
    }

    auto compute_exchange_hash(std::string_view v_c, std::string_view v_s,
                               std::span<std::uint8_t const> i_c, std::span<std::uint8_t const> i_s,
                               std::span<std::uint8_t const> host_key_blob,
                               std::span<std::uint8_t const> q_c, std::span<std::uint8_t const> q_s,
                               std::span<std::uint8_t const> shared_k)
        -> std::expected<std::array<std::uint8_t, 32>, std::string> {
        Writer w;
        w.string(v_c).string(v_s).string(i_c).string(i_s)
            .string(host_key_blob).string(q_c).string(q_s).mpint(shared_k);
        auto d = crypto::digest(crypto::Hash::sha256, w.buf);
        crypto::cleanse(w.buf);
        if (!d || d->size() != 32) return std::unexpected("exchange hash failed");
        std::array<std::uint8_t, 32> out{};
        std::ranges::copy(*d, out.begin());
        return out;
    }

    auto derive_key(std::span<std::uint8_t const> shared_k, std::span<std::uint8_t const> exchange_hash,
                    char letter, std::span<std::uint8_t const> session_id, std::size_t out_len)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (!out_len) return std::vector<std::uint8_t>{};
        Writer prefix;
        prefix.mpint(shared_k).raw(exchange_hash);
        auto k_enc_sz = prefix.buf.size();
        prefix.byte(static_cast<std::uint8_t>(letter)).raw(session_id);
        auto d1 = crypto::digest(crypto::Hash::sha256, prefix.buf);
        crypto::cleanse(prefix.buf);
        if (!d1) return std::unexpected("SSH KDF failed");
        std::vector<std::uint8_t> out = std::move(*d1);
        Writer next;
        next.mpint(shared_k).raw(exchange_hash);
        (void)k_enc_sz;
        while (out.size() < out_len) {
            next.raw(out);
            auto dn = crypto::digest(crypto::Hash::sha256, next.buf);
            crypto::cleanse(std::span(next.buf).subspan(k_enc_sz));
            next.buf.resize(k_enc_sz);
            if (!dn) { crypto::cleanse(next.buf); crypto::cleanse(out); return std::unexpected("SSH KDF expand failed"); }
            out.insert(out.end(), dn->begin(), dn->end());
            crypto::cleanse(*dn);
        }
        crypto::cleanse(next.buf);
        out.resize(out_len);
        return out;
    }

    PacketCipher::~PacketCipher() { crypto::cleanse(key_); crypto::cleanse(iv_); }

    auto PacketCipher::increment_iv() noexcept -> void {
        for (int i = 11; i >= 4; --i)
            if (++iv_[i] != 0) break;
    }

    auto PacketCipher::activate(CipherKind kind, std::span<std::uint8_t const> key, std::span<std::uint8_t const> iv) -> bool {
        if (key.size() != cipher_key_bytes(kind) || iv.size() != cipher_iv_bytes(kind)) return false;
        kind_ = kind;
        crypto::cleanse(key_); crypto::cleanse(iv_);
        std::ranges::copy(key, key_.begin());
        std::ranges::copy(iv, iv_.begin());
        return true;
    }

    auto PacketCipher::encrypt(std::uint32_t seqno, std::span<std::uint8_t const> payload)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (kind_ != CipherKind::none && seqno >= (1u << 30))
            return std::unexpected("SSH packet sequence ceiling reached; rekey required");
        std::size_t block = (kind_ == CipherKind::aes128_gcm || kind_ == CipherKind::aes256_gcm) ? 16u : 8u;
        if (payload.size() > kMaxPacketBytes) return std::unexpected("SSH outbound packet too large");
        std::size_t unpadded = (kind_ == CipherKind::none ? 4u : 0u) + 1u + payload.size();
        std::size_t rem = unpadded % block;
        std::size_t pad_len = rem == 0 ? block : (block - rem);
        if (pad_len < 4) pad_len += block;
        std::size_t raw_pkt_len = 1u + payload.size() + pad_len;
        if (raw_pkt_len > kMaxPacketBytes) return std::unexpected("SSH outbound packet too large");
        std::uint32_t pkt_len = static_cast<std::uint32_t>(raw_pkt_len);

        std::vector<std::uint8_t> plain(4u + pkt_len);
        write_be32(std::span<std::uint8_t, 4>(plain.data(), 4), pkt_len);
        plain[4] = static_cast<std::uint8_t>(pad_len);
        std::ranges::copy(payload, plain.begin() + 5);
        std::vector<std::uint8_t> pad_rnd(pad_len);
        if (!crypto::random_bytes(pad_rnd)) {
            crypto::cleanse(pad_rnd);
            crypto::cleanse(plain);
            return std::unexpected("RNG failed");
        }
        std::ranges::copy(pad_rnd, plain.begin() + 5 + payload.size());
        crypto::cleanse(pad_rnd);

        if (kind_ == CipherKind::none) return plain;

        if (kind_ == CipherKind::aes128_gcm || kind_ == CipherKind::aes256_gcm) {
            auto algo = kind_ == CipherKind::aes128_gcm ? crypto::Aead::aes_128_gcm : crypto::Aead::aes_256_gcm;
            auto kspan = std::span<std::uint8_t const>(key_).first(cipher_key_bytes(kind_));
            auto sealed = crypto::seal(algo, kspan, iv_,
                std::span(plain).subspan(4), std::span(plain).first(4));
            crypto::cleanse(plain);
            if (!sealed) return std::unexpected("SSH AES-GCM encrypt failed");
            increment_iv();
            std::vector<std::uint8_t> out(4 + sealed->size());
            write_be32(std::span<std::uint8_t, 4>(out.data(), 4), pkt_len);
            std::ranges::copy(*sealed, out.begin() + 4);
            return out;
        }

        auto nonce = chacha_nonce(seqno);
        std::array<std::uint8_t, 32> otk_zeros{}, otk{};
        b::CRYPTO_chacha_20(otk.data(), otk_zeros.data(), otk.size(), key_.data(), nonce.data(), 0);
        std::vector<std::uint8_t> out(plain.size() + 16u);
        b::CRYPTO_chacha_20(out.data(), plain.data(), 4, key_.data() + 32, nonce.data(), 0);
        b::CRYPTO_chacha_20(out.data() + 4, plain.data() + 4, pkt_len, key_.data(), nonce.data(), 1);
        crypto::cleanse(plain);
        std::array<std::uint8_t, 16> tag{};
        crypto::poly1305_to(tag, otk, std::span(out).first(4u + pkt_len));
        crypto::cleanse(otk);
        std::ranges::copy(tag, out.begin() + 4u + pkt_len);
        return out;
    }

    auto PacketCipher::decrypt_length(std::uint32_t seqno, std::span<std::uint8_t const, 4> raw_hdr) const
        -> std::expected<std::uint32_t, std::string> {
        std::uint32_t len = 0;
        if (kind_ == CipherKind::chacha20_poly1305) {
            auto nonce = chacha_nonce(seqno);
            std::array<std::uint8_t, 4> plain{};
            b::CRYPTO_chacha_20(plain.data(), raw_hdr.data(), 4, key_.data() + 32, nonce.data(), 0);
            len = read_be32(plain);
        } else {
            len = read_be32(raw_hdr);
        }
        if (len < 8 || len > kMaxPacketBytes) return std::unexpected("invalid SSH packet length");
        return len;
    }

    auto PacketCipher::decrypt_body(std::uint32_t seqno, std::span<std::uint8_t const, 4> raw_hdr,
                                    std::span<std::uint8_t const> rest)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        auto tag_sz = tag_bytes();
        if (rest.size() <= tag_sz) return std::unexpected("truncated SSH packet body");
        auto cipher_body_sz = rest.size() - tag_sz;
        std::vector<std::uint8_t> plain(cipher_body_sz);
        if (kind_ == CipherKind::none) {
            std::ranges::copy(rest, plain.begin());
        } else if (kind_ == CipherKind::aes128_gcm || kind_ == CipherKind::aes256_gcm) {
            auto algo = kind_ == CipherKind::aes128_gcm ? crypto::Aead::aes_128_gcm : crypto::Aead::aes_256_gcm;
            auto kspan = std::span<std::uint8_t const>(key_).first(cipher_key_bytes(kind_));
            auto opened = crypto::open(algo, kspan, iv_, rest, raw_hdr);
            if (!opened) return std::unexpected("SSH AES-GCM authentication failed");
            increment_iv();
            plain = std::move(*opened);
        } else {
            auto nonce = chacha_nonce(seqno);
            std::array<std::uint8_t, 32> otk_zeros{}, otk{};
            b::CRYPTO_chacha_20(otk.data(), otk_zeros.data(), otk.size(), key_.data(), nonce.data(), 0);
            std::array<std::uint8_t, 16> expected_tag{};
            std::vector<std::uint8_t> mac_in(4u + cipher_body_sz);
            std::ranges::copy(raw_hdr, mac_in.begin());
            std::ranges::copy(rest.first(cipher_body_sz), mac_in.begin() + 4);
            crypto::poly1305_to(expected_tag, otk, mac_in);
            crypto::cleanse(otk);
            if (!crypto::constant_time_equal(expected_tag, rest.subspan(cipher_body_sz, 16)))
                return std::unexpected("SSH ChaCha20-Poly1305 authentication failed");
            b::CRYPTO_chacha_20(plain.data(), rest.data(), cipher_body_sz, key_.data(), nonce.data(), 1);
        }
        std::uint8_t pad_len = plain[0];
        if (pad_len < 4 || std::size_t(1u + pad_len) > plain.size()) {
            crypto::cleanse(plain);
            return std::unexpected("invalid SSH packet padding");
        }
        plain.resize(plain.size() - pad_len);
        plain.erase(plain.begin());
        return plain;
    }
}
