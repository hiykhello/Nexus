module;
#include <openssl/x509v3.h>
module openvpn.tls_crypt;
import std;
import boringssl;
import crypto;
import tls.server_credential;

namespace openvpn {
    using namespace boringssl;

    namespace {
        auto write_be32(std::span<std::uint8_t> out, std::size_t off, std::uint32_t v) noexcept -> void {
            out[off] = static_cast<std::uint8_t>(v >> 24);
            out[off + 1] = static_cast<std::uint8_t>(v >> 16);
            out[off + 2] = static_cast<std::uint8_t>(v >> 8);
            out[off + 3] = static_cast<std::uint8_t>(v);
        }

        auto read_be32(std::span<std::uint8_t const> in, std::size_t off) noexcept -> std::uint32_t {
            return (std::uint32_t(in[off]) << 24) | (std::uint32_t(in[off + 1]) << 16) |
                   (std::uint32_t(in[off + 2]) << 8) | std::uint32_t(in[off + 3]);
        }

        auto increment_be128(std::array<std::uint8_t, 16>& ctr) noexcept -> void {
            for (int i = 15; i >= 0; --i) {
                if (++ctr[static_cast<std::size_t>(i)] != 0) break;
            }
        }

        // Pure BoringSSL libcrypto AES-256-CTR stream transform (NIST SP 800-38A / OpenVPN tls-crypt).
        auto aes256_ctr_xor(std::span<std::uint8_t const, 32> key,
                            std::span<std::uint8_t const, 16> iv,
                            std::span<std::uint8_t const> input,
                            std::span<std::uint8_t> output) noexcept -> bool {
            if (input.size() != output.size()) return false;
            AES_KEY aes{};
            if (AES_set_encrypt_key(key.data(), 256, &aes) != 0) return false;
            struct KeyCleanse {
                AES_KEY& k;
                std::array<std::uint8_t, 16> ctr{};
                std::array<std::uint8_t, 16> ks{};
                ~KeyCleanse() {
                    OPENSSL_cleanse(&k, sizeof(k));
                    crypto::cleanse(ctr);
                    crypto::cleanse(ks);
                }
            } state{aes};
            std::ranges::copy(iv, state.ctr.begin());
            std::size_t pos = 0;
            while (pos < input.size()) {
                AES_encrypt(state.ctr.data(), state.ks.data(), &aes);
                increment_be128(state.ctr);
                std::size_t chunk = std::min<std::size_t>(16, input.size() - pos);
                for (std::size_t i = 0; i < chunk; ++i)
                    output[pos + i] = static_cast<std::uint8_t>(input[pos + i] ^ state.ks[i]);
                pos += chunk;
            }
            return true;
        }

        auto hmac_compute(bool use_sha1, std::span<std::uint8_t const> key,
                          std::span<std::uint8_t const> part1,
                          std::span<std::uint8_t const> part2) -> std::expected<crypto::Bytes, std::string> {
            if (use_sha1) {
                auto ctx = crypto::HmacSha1Context::create(key);
                if (!ctx || !ctx->update(part1) || !ctx->update(part2))
                    return std::unexpected("HMAC-SHA1 computation failed");
                auto tag = ctx->snapshot();
                if (!tag) return std::unexpected("HMAC-SHA1 finalize failed");
                return crypto::Bytes(tag->begin(), tag->end());
            }
            crypto::Bytes combined;
            combined.reserve(part1.size() + part2.size());
            combined.insert(combined.end(), part1.begin(), part1.end());
            combined.insert(combined.end(), part2.begin(), part2.end());
            struct Wipe { crypto::Bytes& b; ~Wipe() { crypto::cleanse(b); } } wipe{combined};
            auto tag = crypto::hmac(crypto::Hash::sha256, key, combined);
            if (!tag) return std::unexpected("HMAC-SHA256 computation failed");
            return *tag;
        }
    }

    auto ControlReplayWindow::check_and_record(std::uint32_t packet_id, std::uint32_t timestamp) noexcept -> bool {
        if (packet_id == 0) return false;
        if (!initialized_) {
            initialized_ = true;
            max_time_ = timestamp;
            max_id_ = packet_id;
            bitmap_ = 1;
            return true;
        }
        if (timestamp > max_time_) {
            max_time_ = timestamp;
            if (packet_id > max_id_) {
                auto shift = packet_id - max_id_;
                bitmap_ = (shift >= 64) ? std::uint64_t{1} : ((bitmap_ << shift) | std::uint64_t{1});
            } else {
                bitmap_ = 1;
            }
            max_id_ = packet_id;
            return true;
        }
        if (timestamp < max_time_) return false;
        if (packet_id > max_id_) {
            auto shift = packet_id - max_id_;
            bitmap_ = (shift >= 64) ? std::uint64_t{1} : ((bitmap_ << shift) | std::uint64_t{1});
            max_id_ = packet_id;
            return true;
        }
        auto delta = max_id_ - packet_id;
        if (delta >= 64) return false;
        std::uint64_t bit = std::uint64_t{1} << delta;
        if (bitmap_ & bit) return false;
        bitmap_ |= bit;
        return true;
    }

    TlsAuthCodec::~TlsAuthCodec() {
        crypto::cleanse(tx_key_);
        crypto::cleanse(rx_key_);
        active_ = false;
    }

    TlsAuthCodec::TlsAuthCodec(TlsAuthCodec&& other) noexcept
        : tx_key_(other.tx_key_), rx_key_(other.rx_key_), use_sha1_(other.use_sha1_),
          tx_packet_id_(other.tx_packet_id_), replay_(other.replay_),
          active_(std::exchange(other.active_, false)) {
        crypto::cleanse(other.tx_key_);
        crypto::cleanse(other.rx_key_);
    }

    auto TlsAuthCodec::operator=(TlsAuthCodec&& other) noexcept -> TlsAuthCodec& {
        if (this != &other) {
            crypto::cleanse(tx_key_);
            crypto::cleanse(rx_key_);
            tx_key_ = other.tx_key_;
            rx_key_ = other.rx_key_;
            use_sha1_ = other.use_sha1_;
            tx_packet_id_ = other.tx_packet_id_;
            replay_ = other.replay_;
            active_ = std::exchange(other.active_, false);
            crypto::cleanse(other.tx_key_);
            crypto::cleanse(other.rx_key_);
        }
        return *this;
    }

    auto TlsAuthCodec::init(std::span<std::uint8_t const, 256> static_key,
                            KeyDirection direction, bool server_role, bool use_sha1) noexcept -> bool {
        auto key0_hmac = static_key.subspan<64, 64>();
        auto key1_hmac = static_key.subspan<192, 64>();
        if (direction == KeyDirection::bidirectional) {
            std::ranges::copy(key0_hmac, tx_key_.begin());
            std::ranges::copy(key0_hmac, rx_key_.begin());
        } else {
            bool tx_is_0 = (direction == KeyDirection::client_0) ? !server_role : server_role;
            std::ranges::copy(tx_is_0 ? key0_hmac : key1_hmac, tx_key_.begin());
            std::ranges::copy(tx_is_0 ? key1_hmac : key0_hmac, rx_key_.begin());
        }
        use_sha1_ = use_sha1;
        tx_packet_id_ = 0;
        replay_.reset();
        active_ = true;
        return true;
    }

    auto TlsAuthCodec::wrap(std::span<std::uint8_t const> plain_control,
                            std::uint32_t timestamp) -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (!active_) return std::unexpected("tls-auth codec not initialized");
        if (plain_control.size() < 9) return std::unexpected("control packet too short for tls-auth");
        if (tx_packet_id_ == std::numeric_limits<std::uint32_t>::max())
            return std::unexpected("tls-auth packet id exhausted");
        std::uint32_t pid = ++tx_packet_id_;
        std::array<std::uint8_t, 8> pid_ts{};
        write_be32(pid_ts, 0, pid);
        write_be32(pid_ts, 4, timestamp);

        // OpenVPN tls-auth computes HMAC over [pkt_id:4][timestamp:4][opcode_kid:1][sid:8][rest...].
        auto key_slice = std::span<std::uint8_t const>(tx_key_).first(tag_size());
        auto tag = hmac_compute(use_sha1_, key_slice, pid_ts, plain_control);
        if (!tag) return std::unexpected(tag.error());

        // Wire order: [opcode_kid:1][sid:8][hmac:tag_size][pkt_id:4][timestamp:4][rest...].
        std::vector<std::uint8_t> out;
        out.reserve(plain_control.size() + tag->size() + 8);
        out.insert(out.end(), plain_control.begin(), plain_control.begin() + 9);
        out.insert(out.end(), tag->begin(), tag->end());
        out.insert(out.end(), pid_ts.begin(), pid_ts.end());
        out.insert(out.end(), plain_control.begin() + 9, plain_control.end());
        return out;
    }

    auto TlsAuthCodec::unwrap(std::span<std::uint8_t const> wire_packet)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (!active_) return std::unexpected("tls-auth codec not initialized");
        auto tlen = tag_size();
        if (wire_packet.size() < 9 + tlen + 8)
            return std::unexpected("tls-auth packet too short");

        auto header9 = wire_packet.first(9);
        auto wire_tag = wire_packet.subspan(9, tlen);
        auto pid_ts = wire_packet.subspan(9 + tlen, 8);
        auto rest = wire_packet.subspan(9 + tlen + 8);

        std::vector<std::uint8_t> plain;
        plain.reserve(9 + rest.size());
        plain.insert(plain.end(), header9.begin(), header9.end());
        plain.insert(plain.end(), rest.begin(), rest.end());

        auto key_slice = std::span<std::uint8_t const>(rx_key_).first(tlen);
        auto expected = hmac_compute(use_sha1_, key_slice, pid_ts, plain);
        if (!expected) return std::unexpected(expected.error());
        if (!crypto::constant_time_equal(wire_tag, *expected))
            return std::unexpected("tls-auth HMAC verification failed");

        auto pid = read_be32(pid_ts, 0);
        auto ts = read_be32(pid_ts, 4);
        if (!replay_.check_and_record(pid, ts))
            return std::unexpected("tls-auth replay detected");
        return plain;
    }

    TlsCryptCodec::~TlsCryptCodec() {
        crypto::cleanse(tx_cipher_key_);
        crypto::cleanse(tx_hmac_key_);
        crypto::cleanse(rx_cipher_key_);
        crypto::cleanse(rx_hmac_key_);
        active_ = false;
    }

    TlsCryptCodec::TlsCryptCodec(TlsCryptCodec&& other) noexcept
        : tx_cipher_key_(other.tx_cipher_key_), tx_hmac_key_(other.tx_hmac_key_),
          rx_cipher_key_(other.rx_cipher_key_), rx_hmac_key_(other.rx_hmac_key_),
          tx_packet_id_(other.tx_packet_id_), replay_(other.replay_),
          active_(std::exchange(other.active_, false)) {
        crypto::cleanse(other.tx_cipher_key_);
        crypto::cleanse(other.tx_hmac_key_);
        crypto::cleanse(other.rx_cipher_key_);
        crypto::cleanse(other.rx_hmac_key_);
    }

    auto TlsCryptCodec::operator=(TlsCryptCodec&& other) noexcept -> TlsCryptCodec& {
        if (this != &other) {
            crypto::cleanse(tx_cipher_key_);
            crypto::cleanse(tx_hmac_key_);
            crypto::cleanse(rx_cipher_key_);
            crypto::cleanse(rx_hmac_key_);
            tx_cipher_key_ = other.tx_cipher_key_;
            tx_hmac_key_ = other.tx_hmac_key_;
            rx_cipher_key_ = other.rx_cipher_key_;
            rx_hmac_key_ = other.rx_hmac_key_;
            tx_packet_id_ = other.tx_packet_id_;
            replay_ = other.replay_;
            active_ = std::exchange(other.active_, false);
            crypto::cleanse(other.tx_cipher_key_);
            crypto::cleanse(other.tx_hmac_key_);
            crypto::cleanse(other.rx_cipher_key_);
            crypto::cleanse(other.rx_hmac_key_);
        }
        return *this;
    }

    auto TlsCryptCodec::init(std::span<std::uint8_t const, 256> static_key, bool server_role) noexcept -> bool {
        // OpenVPN tls-crypt key schedule from 256-byte Static Key V1:
        // client->server: cipher = [0..31], hmac = [64..95]
        // server->client: cipher = [128..159], hmac = [192..223]
        auto c2s_cipher = static_key.subspan<0, 32>();
        auto c2s_hmac = static_key.subspan<64, 32>();
        auto s2c_cipher = static_key.subspan<128, 32>();
        auto s2c_hmac = static_key.subspan<192, 32>();
        if (!server_role) {
            std::ranges::copy(c2s_cipher, tx_cipher_key_.begin());
            std::ranges::copy(c2s_hmac, tx_hmac_key_.begin());
            std::ranges::copy(s2c_cipher, rx_cipher_key_.begin());
            std::ranges::copy(s2c_hmac, rx_hmac_key_.begin());
        } else {
            std::ranges::copy(s2c_cipher, tx_cipher_key_.begin());
            std::ranges::copy(s2c_hmac, tx_hmac_key_.begin());
            std::ranges::copy(c2s_cipher, rx_cipher_key_.begin());
            std::ranges::copy(c2s_hmac, rx_hmac_key_.begin());
        }
        tx_packet_id_ = 0;
        replay_.reset();
        active_ = true;
        return true;
    }

    auto TlsCryptCodec::wrap(std::span<std::uint8_t const> plain_control,
                             std::uint32_t timestamp) -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (!active_) return std::unexpected("tls-crypt codec not initialized");
        if (plain_control.size() < 9) return std::unexpected("control packet too short for tls-crypt");
        if (tx_packet_id_ == std::numeric_limits<std::uint32_t>::max())
            return std::unexpected("tls-crypt packet id exhausted");

        std::uint32_t pid = ++tx_packet_id_;
        std::array<std::uint8_t, 17> header{};
        std::copy_n(plain_control.begin(), 9, header.begin());
        write_be32(header, 9, pid);
        write_be32(header, 13, timestamp);
        auto body = plain_control.subspan(9);

        // SIV-like MAC-then-CTR: Tag = HMAC-SHA256(hmac_key, header || body), IV = Tag[0..15].
        auto tag = hmac_compute(false, tx_hmac_key_, header, body);
        if (!tag || tag->size() != 32) return std::unexpected("tls-crypt HMAC failed");

        std::vector<std::uint8_t> out(17 + 32 + body.size());
        std::ranges::copy(header, out.begin());
        std::ranges::copy(*tag, out.begin() + 17);
        auto iv = std::span<std::uint8_t const, 16>(tag->data(), 16);
        auto ct = std::span<std::uint8_t>(out).subspan(17 + 32);
        if (!aes256_ctr_xor(tx_cipher_key_, iv, body, ct))
            return std::unexpected("tls-crypt AES-256-CTR encrypt failed");
        return out;
    }

    auto TlsCryptCodec::unwrap(std::span<std::uint8_t const> wire_packet)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (!active_) return std::unexpected("tls-crypt codec not initialized");
        if (wire_packet.size() < 17 + 32) return std::unexpected("tls-crypt packet too short");

        auto header = wire_packet.first(17);
        auto wire_tag = wire_packet.subspan(17, 32);
        auto ct = wire_packet.subspan(17 + 32);

        std::vector<std::uint8_t> body(ct.size());
        auto iv = std::span<std::uint8_t const, 16>(wire_tag.data(), 16);
        if (!aes256_ctr_xor(rx_cipher_key_, iv, ct, body)) {
            crypto::cleanse(body);
            return std::unexpected("tls-crypt AES-256-CTR decrypt failed");
        }
        auto expected = hmac_compute(false, rx_hmac_key_, header, body);
        if (!expected || !crypto::constant_time_equal(wire_tag, *expected)) {
            crypto::cleanse(body);
            return std::unexpected("tls-crypt authentication failed");
        }
        auto pid = read_be32(header, 9);
        auto ts = read_be32(header, 13);
        if (!replay_.check_and_record(pid, ts)) {
            crypto::cleanse(body);
            return std::unexpected("tls-crypt replay detected");
        }
        std::vector<std::uint8_t> plain;
        plain.reserve(9 + body.size());
        plain.insert(plain.end(), header.begin(), header.begin() + 9);
        plain.insert(plain.end(), body.begin(), body.end());
        crypto::cleanse(body);
        return plain;
    }

    MtlsCredentials::MtlsCredentials(tls::ServerCredential&& cred, std::array<std::uint8_t, 32> fp) noexcept
        : cred_(std::move(cred)), leaf_sha256_(fp) {}

    auto MtlsCredentials::load(std::span<std::uint8_t const> cert_pem_or_der,
                               std::span<std::uint8_t const> key_pem_or_der)
        -> std::expected<MtlsCredentials, std::string> {
        auto cred = tls::ServerCredential::create_file_contents(cert_pem_or_der, key_pem_or_der);
        if (!cred) return std::unexpected("failed to load mTLS certificate/private key");
        auto digest = crypto::digest(crypto::Hash::sha256, cred->certificate());
        if (!digest || digest->size() != 32) return std::unexpected("failed to hash mTLS certificate");
        std::array<std::uint8_t, 32> fp{};
        std::copy_n(digest->begin(), 32, fp.begin());
        return MtlsCredentials(std::move(*cred), fp);
    }

    auto MtlsCredentials::generate_ephemeral_ed25519() -> std::expected<MtlsCredentials, std::string> {
        auto cred = tls::ServerCredential::generate_ed25519();
        if (!cred) return std::unexpected("failed to generate ephemeral Ed25519 mTLS credential");
        auto digest = crypto::digest(crypto::Hash::sha256, cred->certificate());
        if (!digest || digest->size() != 32) return std::unexpected("failed to hash mTLS certificate");
        std::array<std::uint8_t, 32> fp{};
        std::copy_n(digest->begin(), 32, fp.begin());
        return MtlsCredentials(std::move(*cred), fp);
    }

    auto MtlsCredentials::certificate_der() const noexcept -> std::span<std::uint8_t const> {
        return cred_.certificate();
    }

    auto MtlsCredentials::chain_der() const noexcept -> std::span<crypto::Bytes const> {
        return cred_.chain();
    }

    auto MtlsCredentials::signature_schemes() const noexcept -> std::span<std::uint16_t const> {
        return cred_.signature_schemes();
    }

    auto MtlsCredentials::sign_certificate_verify(std::uint16_t scheme, crypto::Hash hash,
                                                  std::span<std::uint8_t const> transcript_hash) const
        -> std::expected<crypto::Bytes, std::string> {
        auto sig = cred_.sign(scheme, hash, transcript_hash);
        if (!sig) return std::unexpected("mTLS CertificateVerify signing failed");
        return std::move(*sig);
    }

    auto verify_mtls_peer_chain(std::span<std::uint8_t const> leaf_der,
                                std::span<crypto::Bytes const> chain_der,
                                std::span<std::uint8_t const> ca_pem_or_der,
                                std::int64_t unix_time_s) -> std::expected<void, std::string> {
        if (leaf_der.empty() || ca_pem_or_der.empty())
            return std::unexpected("empty mTLS certificate or CA anchor");
        struct X509Del { auto operator()(X509* p) const noexcept -> void { X509_free(p); } };
        struct BioDel { auto operator()(BIO* p) const noexcept -> void { BIO_free(p); } };
        struct StoreDel { auto operator()(X509_STORE* p) const noexcept -> void { X509_STORE_free(p); } };
        struct CtxDel { auto operator()(X509_STORE_CTX* p) const noexcept -> void { X509_STORE_CTX_free(p); } };
        struct StackDel { auto operator()(X509Stack* p) const noexcept -> void { sk_X509_free(p); } };
        auto parse_der_x509 = [](std::span<std::uint8_t const> der) -> X509* {
            auto const* p = der.data();
            X509* x = d2i_X509(nullptr, &p, static_cast<long>(der.size()));
            if (x && p != der.data() + der.size()) { X509_free(x); return nullptr; }
            return x;
        };
        std::unique_ptr<X509, X509Del> leaf(parse_der_x509(leaf_der));
        if (!leaf) return std::unexpected("invalid DER client certificate");

        std::unique_ptr<X509_STORE, StoreDel> store(X509_STORE_new());
        if (!store) return std::unexpected("X509_STORE allocation failed");
        std::size_t added = 0;
        if (auto* bio = BIO_new_mem_buf(ca_pem_or_der.data(), static_cast<int>(ca_pem_or_der.size()))) {
            std::unique_ptr<BIO, BioDel> bio_guard(bio);
            while (auto* ca = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr)) {
                std::unique_ptr<X509, X509Del> ca_guard(ca);
                if (X509_STORE_add_cert(store.get(), ca) == 1) ++added;
            }
            ERR_clear_error();
        }
        if (added == 0) {
            if (auto* ca = parse_der_x509(ca_pem_or_der)) {
                std::unique_ptr<X509, X509Del> ca_guard(ca);
                if (X509_STORE_add_cert(store.get(), ca) == 1) ++added;
            }
        }
        if (added == 0) return std::unexpected("no valid CA certificates in trust anchor");

        std::unique_ptr<X509Stack, StackDel> untrusted(sk_X509_new_null());
        std::vector<std::unique_ptr<X509, X509Del>> chain_holders;
        for (auto const& c : chain_der) {
            auto* x = parse_der_x509(c);
            if (!x) return std::unexpected("invalid intermediate DER certificate");
            chain_holders.emplace_back(x);
            sk_X509_push(untrusted.get(), x);
        }
        std::unique_ptr<X509_STORE_CTX, CtxDel> ctx(X509_STORE_CTX_new());
        if (!ctx || X509_STORE_CTX_init(ctx.get(), store.get(), leaf.get(), untrusted.get()) != 1)
            return std::unexpected("X509_STORE_CTX initialization failed");
        auto* param = X509_STORE_CTX_get0_param(ctx.get());
        if (X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_SSL_CLIENT) != 1)
            return std::unexpected("failed to set SSL_CLIENT verification purpose");
        X509_VERIFY_PARAM_set_time_posix(param, unix_time_s);
        X509_VERIFY_PARAM_set_depth(param, 8);
        if (X509_verify_cert(ctx.get()) != 1)
            return std::unexpected("mTLS client certificate chain verification failed");
        return {};
    }
}
