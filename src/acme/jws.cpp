module;
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/stack.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

module acme.jws;
import std;

namespace acme {
    namespace {
        template<class T, auto FreeFn>
        struct SslPtr {
            T* ptr = nullptr;
            explicit SslPtr(T* p = nullptr) noexcept : ptr(p) {}
            SslPtr(SslPtr const&) = delete;
            auto operator=(SslPtr const&) -> SslPtr& = delete;
            SslPtr(SslPtr&& o) noexcept : ptr(std::exchange(o.ptr, nullptr)) {}
            ~SslPtr() { if (ptr) FreeFn(ptr); }
            auto get() const noexcept -> T* { return ptr; }
            explicit operator bool() const noexcept { return ptr != nullptr; }
        };

        auto bio_to_string(BIO* bio) -> std::string {
            BUF_MEM* mem = nullptr;
            BIO_get_mem_ptr(bio, &mem);
            if (!mem || !mem->data || !mem->length) return {};
            return std::string(mem->data, mem->length);
        }

        auto ec_coords(EC_KEY const* ec, std::array<std::uint8_t, 32>& x, std::array<std::uint8_t, 32>& y) -> bool {
            auto const* group = EC_KEY_get0_group(ec);
            auto const* pub = EC_KEY_get0_public_key(ec);
            if (!group || !pub || EC_GROUP_get_curve_name(group) != NID_X9_62_prime256v1) return false;
            SslPtr<BIGNUM, BN_free> bx(BN_new()), by(BN_new());
            if (!bx || !by || !EC_POINT_get_affine_coordinates_GFp(group, pub, bx.get(), by.get(), nullptr)) return false;
            return BN_bn2bin_padded(x.data(), x.size(), bx.get()) && BN_bn2bin_padded(y.data(), y.size(), by.get());
        }

        auto make_p256_evp() -> SslPtr<EVP_PKEY, EVP_PKEY_free> {
            SslPtr<EC_KEY, EC_KEY_free> ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
            if (!ec || !EC_KEY_generate_key(ec.get())) return SslPtr<EVP_PKEY, EVP_PKEY_free>{};
            SslPtr<EVP_PKEY, EVP_PKEY_free> pkey(EVP_PKEY_new());
            if (!pkey || !EVP_PKEY_assign_EC_KEY(pkey.get(), ec.ptr)) return SslPtr<EVP_PKEY, EVP_PKEY_free>{};
            ec.ptr = nullptr;
            return pkey;
        }

        auto key_to_pem(EVP_PKEY* pkey) -> std::expected<std::string, std::string> {
            SslPtr<BIO, BIO_free> bio(BIO_new(BIO_s_mem()));
            if (!bio || !PEM_write_bio_PKCS8PrivateKey(bio.get(), pkey, nullptr, nullptr, 0, nullptr, nullptr))
                return std::unexpected("failed to serialize EC private key");
            return bio_to_string(bio.get());
        }
    }

    auto base64url_encode(std::span<std::uint8_t const> bytes) -> std::string {
        static constexpr char kTab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        std::string out;
        out.reserve(((bytes.size() + 2) / 3) * 4);
        for (std::size_t i = 0; i < bytes.size(); i += 3) {
            std::uint32_t v = static_cast<std::uint32_t>(bytes[i]) << 16;
            if (i + 1 < bytes.size()) v |= static_cast<std::uint32_t>(bytes[i + 1]) << 8;
            if (i + 2 < bytes.size()) v |= static_cast<std::uint32_t>(bytes[i + 2]);
            out.push_back(kTab[(v >> 18) & 63]);
            out.push_back(kTab[(v >> 12) & 63]);
            if (i + 1 < bytes.size()) out.push_back(kTab[(v >> 6) & 63]);
            if (i + 2 < bytes.size()) out.push_back(kTab[v & 63]);
        }
        return out;
    }

    auto sha256_bytes(std::span<std::uint8_t const> bytes) -> std::expected<std::array<std::uint8_t, 32>, std::string> {
        std::array<std::uint8_t, 32> out{};
        if (!SHA256(bytes.data(), bytes.size(), out.data())) return std::unexpected("SHA256 failed");
        return out;
    }

    auto EcAccountKey::generate_p256() -> std::expected<EcAccountKey, std::string> {
        auto pkey = make_p256_evp();
        if (!pkey) return std::unexpected("P-256 keygen failed");
        auto pem = key_to_pem(pkey.get());
        if (!pem) return std::unexpected(pem.error());
        std::array<std::uint8_t, 32> x{}, y{};
        if (!ec_coords(EVP_PKEY_get0_EC_KEY(pkey.get()), x, y)) return std::unexpected("invalid EC coords");
        return EcAccountKey(std::move(*pem), x, y);
    }

    auto EcAccountKey::from_pem(std::string_view pem) -> std::expected<EcAccountKey, std::string> {
        SslPtr<BIO, BIO_free> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
        if (!bio) return std::unexpected("BIO alloc failed");
        SslPtr<EVP_PKEY, EVP_PKEY_free> pkey(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
        if (!pkey || EVP_PKEY_id(pkey.get()) != EVP_PKEY_EC) return std::unexpected("not an EC private key");
        std::array<std::uint8_t, 32> x{}, y{};
        if (!ec_coords(EVP_PKEY_get0_EC_KEY(pkey.get()), x, y)) return std::unexpected("not a P-256 key");
        return EcAccountKey(std::string(pem), x, y);
    }

    auto EcAccountKey::jwk_json() const -> std::string {
        return std::format("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
                           base64url_encode(x_), base64url_encode(y_));
    }

    auto EcAccountKey::jwk_thumbprint() const -> std::expected<std::string, std::string> {
        auto jwk = jwk_json();
        auto hash = sha256_bytes(std::span(reinterpret_cast<std::uint8_t const*>(jwk.data()), jwk.size()));
        if (!hash) return std::unexpected(hash.error());
        return base64url_encode(*hash);
    }

    auto EcAccountKey::key_authorization(std::string_view token) const -> std::expected<std::string, std::string> {
        auto thumb = jwk_thumbprint();
        if (!thumb) return std::unexpected(thumb.error());
        return std::format("{}.{}", token, *thumb);
    }

    auto EcAccountKey::dns01_txt_value(std::string_view token) const -> std::expected<std::string, std::string> {
        auto digest = tls_alpn01_digest(token);
        if (!digest) return std::unexpected(digest.error());
        return base64url_encode(*digest);
    }

    auto EcAccountKey::tls_alpn01_digest(std::string_view token) const -> std::expected<std::array<std::uint8_t, 32>, std::string> {
        auto ka = key_authorization(token);
        if (!ka) return std::unexpected(ka.error());
        return sha256_bytes(std::span(reinterpret_cast<std::uint8_t const*>(ka->data()), ka->size()));
    }

    auto EcAccountKey::sign_es256_raw(std::span<std::uint8_t const> msg) const -> std::expected<std::array<std::uint8_t, 64>, std::string> {
        auto digest = sha256_bytes(msg);
        if (!digest) return std::unexpected(digest.error());
        SslPtr<BIO, BIO_free> bio(BIO_new_mem_buf(private_pem_.data(), static_cast<int>(private_pem_.size())));
        SslPtr<EVP_PKEY, EVP_PKEY_free> pkey(bio ? PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr) : nullptr);
        EC_KEY* ec = pkey ? EVP_PKEY_get0_EC_KEY(pkey.get()) : nullptr;
        if (!ec) return std::unexpected("failed to reload signing key");
        SslPtr<ECDSA_SIG, ECDSA_SIG_free> sig(ECDSA_do_sign(digest->data(), static_cast<int>(digest->size()), ec));
        if (!sig) return std::unexpected("ECDSA_do_sign failed");
        BIGNUM const* r = nullptr;
        BIGNUM const* s = nullptr;
        ECDSA_SIG_get0(sig.get(), &r, &s);
        std::array<std::uint8_t, 64> raw{};
        if (!BN_bn2bin_padded(raw.data(), 32, r) || !BN_bn2bin_padded(raw.data() + 32, 32, s))
            return std::unexpected("ES256 signature encoding failed");
        return raw;
    }

    auto sign_jws(EcAccountKey const& key, std::string_view url, std::string_view nonce,
                  std::string_view payload_json, std::string_view kid) -> std::expected<std::string, std::string> {
        std::string protected_json = kid.empty()
            ? std::format("{{\"alg\":\"ES256\",\"jwk\":{},\"nonce\":\"{}\",\"url\":\"{}\"}}", key.jwk_json(), nonce, url)
            : std::format("{{\"alg\":\"ES256\",\"kid\":\"{}\",\"nonce\":\"{}\",\"url\":\"{}\"}}", kid, nonce, url);
        auto prot_b64 = base64url_encode(std::span(reinterpret_cast<std::uint8_t const*>(protected_json.data()), protected_json.size()));
        auto pay_b64 = base64url_encode(std::span(reinterpret_cast<std::uint8_t const*>(payload_json.data()), payload_json.size()));
        auto signing_input = prot_b64 + "." + pay_b64;
        auto sig = key.sign_es256_raw(std::span(reinterpret_cast<std::uint8_t const*>(signing_input.data()), signing_input.size()));
        if (!sig) return std::unexpected(sig.error());
        return std::format("{{\"protected\":\"{}\",\"payload\":\"{}\",\"signature\":\"{}\"}}",
                           prot_b64, pay_b64, base64url_encode(*sig));
    }

    auto generate_csr_p256(std::span<std::string const> domains) -> std::expected<GeneratedCsr, std::string> {
        if (domains.empty()) return std::unexpected("ACME CSR requires at least one domain");
        auto pkey = make_p256_evp();
        if (!pkey) return std::unexpected("leaf keygen failed");
        auto pem = key_to_pem(pkey.get());
        if (!pem) return std::unexpected(pem.error());

        SslPtr<X509_REQ, X509_REQ_free> req(X509_REQ_new());
        if (!req || !X509_REQ_set_version(req.get(), 0) || !X509_REQ_set_pubkey(req.get(), pkey.get()))
            return std::unexpected("X509_REQ init failed");
        X509_NAME* name = X509_REQ_get_subject_name(req.get());
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<unsigned char const*>(domains[0].data()), static_cast<int>(domains[0].size()), -1, 0);

        std::string san;
        for (std::size_t i = 0; i < domains.size(); ++i) {
            if (i > 0) san += ',';
            san += "DNS:" + domains[i];
        }
        SslPtr<X509_EXTENSION, X509_EXTENSION_free> ext(
            X509V3_EXT_nconf_nid(nullptr, nullptr, NID_subject_alt_name, san.c_str()));
        auto sk_free = [](STACK_OF(X509_EXTENSION)* s) { sk_X509_EXTENSION_pop_free(s, X509_EXTENSION_free); };
        std::unique_ptr<STACK_OF(X509_EXTENSION), decltype(sk_free)> exts(sk_X509_EXTENSION_new_null(), sk_free);
        if (!ext || !exts || !sk_X509_EXTENSION_push(exts.get(), ext.ptr))
            return std::unexpected("SAN extension build failed");
        ext.ptr = nullptr;
        if (!X509_REQ_add_extensions(req.get(), exts.get()) || !X509_REQ_sign(req.get(), pkey.get(), EVP_sha256()))
            return std::unexpected("CSR signing failed");

        int len = i2d_X509_REQ(req.get(), nullptr);
        if (len <= 0) return std::unexpected("CSR DER encode failed");
        std::vector<std::uint8_t> der(static_cast<std::size_t>(len));
        unsigned char* p = der.data();
        if (i2d_X509_REQ(req.get(), &p) != len) return std::unexpected("CSR DER write failed");
        return GeneratedCsr{base64url_encode(der), std::move(*pem)};
    }

    auto generate_alpn01_cert(std::string_view domain, std::array<std::uint8_t, 32> const& acme_digest)
        -> std::expected<AlpnValidationCert, std::string> {
        auto pkey = make_p256_evp();
        if (!pkey) return std::unexpected("ALPN cert keygen failed");
        auto kpem = key_to_pem(pkey.get());
        if (!kpem) return std::unexpected(kpem.error());

        SslPtr<X509, X509_free> x(X509_new());
        if (!x) return std::unexpected("X509_new failed");
        X509_set_version(x.get(), 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x.get()), 1);
        X509_gmtime_adj(X509_getm_notBefore(x.get()), 0);
        X509_gmtime_adj(X509_getm_notAfter(x.get()), 7 * 86400);
        X509_set_pubkey(x.get(), pkey.get());
        X509_NAME* sub = X509_get_subject_name(x.get());
        X509_NAME_add_entry_by_txt(sub, "CN", MBSTRING_ASC,
            reinterpret_cast<unsigned char const*>(domain.data()), static_cast<int>(domain.size()), -1, 0);
        X509_set_issuer_name(x.get(), sub);

        std::string san = "DNS:" + std::string(domain);
        SslPtr<X509_EXTENSION, X509_EXTENSION_free> san_ext(X509V3_EXT_nconf_nid(nullptr, nullptr, NID_subject_alt_name, san.c_str()));
        if (!san_ext || !X509_add_ext(x.get(), san_ext.get(), -1)) return std::unexpected("ALPN SAN add failed");

        // RFC 8737 §3: id-pe-acmeIdentifier (1.3.6.1.5.5.7.1.31), critical, DER OCTET STRING of 32-byte digest.
        std::array<std::uint8_t, 34> der_oct{};
        der_oct[0] = 0x04;
        der_oct[1] = 0x20;
        std::ranges::copy(acme_digest, der_oct.begin() + 2);
        SslPtr<ASN1_OBJECT, ASN1_OBJECT_free> oid(OBJ_txt2obj("1.3.6.1.5.5.7.1.31", 1));
        SslPtr<ASN1_OCTET_STRING, ASN1_OCTET_STRING_free> oct(ASN1_OCTET_STRING_new());
        if (!oid || !oct || !ASN1_OCTET_STRING_set(oct.get(), der_oct.data(), static_cast<int>(der_oct.size())))
            return std::unexpected("ALPN extension value failed");
        SslPtr<X509_EXTENSION, X509_EXTENSION_free> acme_ext(X509_EXTENSION_create_by_OBJ(nullptr, oid.get(), 1, oct.get()));
        if (!acme_ext || !X509_add_ext(x.get(), acme_ext.get(), -1) || !X509_sign(x.get(), pkey.get(), EVP_sha256()))
            return std::unexpected("ALPN cert sign failed");

        SslPtr<BIO, BIO_free> bio(BIO_new(BIO_s_mem()));
        if (!bio || !PEM_write_bio_X509(bio.get(), x.get())) return std::unexpected("ALPN cert PEM write failed");
        return AlpnValidationCert{bio_to_string(bio.get()), std::move(*kpem)};
    }

    auto parse_cert_validity(std::string_view cert_pem) -> std::expected<CertValidity, std::string> {
        SslPtr<BIO, BIO_free> bio(BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size())));
        SslPtr<X509, X509_free> x(bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr) : nullptr);
        if (!x) return std::unexpected("invalid X509 PEM certificate");
        int64_t nb = 0, na = 0;
        if (!ASN1_TIME_to_posix(X509_get0_notBefore(x.get()), &nb) ||
            !ASN1_TIME_to_posix(X509_get0_notAfter(x.get()), &na))
            return std::unexpected("failed to decode certificate validity");
        return CertValidity{static_cast<std::int64_t>(nb), static_cast<std::int64_t>(na)};
    }
}
