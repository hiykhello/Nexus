module;
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

module cli.gen_tools;
import std;
import crypto;
import encoding.base64;

namespace cli {
    namespace {
        template<class T, auto FreeFn>
        struct SslPtr {
            T* ptr = nullptr;
            explicit SslPtr(T* p = nullptr) noexcept : ptr(p) {}
            SslPtr(SslPtr const&) = delete;
            auto operator=(SslPtr const&) -> SslPtr& = delete;
            ~SslPtr() { if (ptr) FreeFn(ptr); }
            auto get() const noexcept -> T* { return ptr; }
            explicit operator bool() const noexcept { return ptr != nullptr; }
        };

        using encoding::encode_base64;

        auto bio_to_string(BIO* bio) -> std::string {
            BUF_MEM* mem = nullptr;
            BIO_get_mem_ptr(bio, &mem);
            if (!mem || !mem->data || !mem->length) return {};
            return std::string(mem->data, mem->length);
        }

        auto put_u16(std::vector<std::uint8_t>& out, std::uint16_t v) -> void {
            out.push_back(static_cast<std::uint8_t>(v >> 8));
            out.push_back(static_cast<std::uint8_t>(v & 0xff));
        }

        auto generate_clamped_x25519(std::array<std::uint8_t, 32>& priv, std::array<std::uint8_t, 32>& pub)
            -> std::expected<void, std::string> {
            for (int attempt = 0; attempt < 8; ++attempt) {
                if (!crypto::random_bytes(priv)) return std::unexpected("random_bytes failed");
                priv[0] &= 248;
                priv[31] &= 127;
                priv[31] |= 64;
                auto key = crypto::X25519Private::from_bytes(priv);
                if (!key) continue;
                auto p = key->public_key();
                if (!p) continue;
                pub = *p;
                return {};
            }
            return std::unexpected("failed generating X25519 keypair");
        }
    }

    auto generate_uuid() -> std::expected<std::string, std::string> {
        std::array<std::uint8_t, 16> b{};
        if (!crypto::random_bytes(b)) return std::unexpected("random_bytes failed");
        b[6] = static_cast<std::uint8_t>((b[6] & 0x0fu) | 0x40u);
        b[8] = static_cast<std::uint8_t>((b[8] & 0x3fu) | 0x80u);
        return std::format(
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    }

    auto generate_x25519_keypair(bool url_safe) -> std::expected<std::pair<std::string, std::string>, std::string> {
        std::array<std::uint8_t, 32> priv{}, pub{};
        if (auto ok = generate_clamped_x25519(priv, pub); !ok) return std::unexpected(ok.error());
        auto priv_s = encode_base64(priv, url_safe, !url_safe);
        auto pub_s = encode_base64(pub, url_safe, !url_safe);
        crypto::cleanse(priv);
        return std::pair{std::move(priv_s), std::move(pub_s)};
    }

    auto generate_ss2022_key(std::size_t key_bytes) -> std::expected<std::string, std::string> {
        if (key_bytes != 16 && key_bytes != 32)
            return std::unexpected("ss2022 key length must be 16 or 32 bytes");
        std::vector<std::uint8_t> raw(key_bytes);
        if (!crypto::random_bytes(raw)) return std::unexpected("random_bytes failed");
        auto encoded = encode_base64(raw, false, true);
        crypto::cleanse(raw);
        return encoded;
    }

    auto generate_self_signed_tls(std::string_view common_name, int days)
        -> std::expected<std::pair<std::string, std::string>, std::string> {
        if (common_name.empty() || common_name.size() > 253 || days <= 0 || days > 36500)
            return std::unexpected("invalid common name or validity days");
        SslPtr<EC_KEY, EC_KEY_free> ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
        if (!ec || !EC_KEY_generate_key(ec.get())) return std::unexpected("EC P-256 keygen failed");
        SslPtr<EVP_PKEY, EVP_PKEY_free> pkey(EVP_PKEY_new());
        if (!pkey || !EVP_PKEY_set1_EC_KEY(pkey.get(), ec.get())) return std::unexpected("EVP_PKEY setup failed");

        SslPtr<X509, X509_free> x(X509_new());
        if (!x) return std::unexpected("X509_new failed");
        X509_set_version(x.get(), 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x.get()), 1);
        X509_gmtime_adj(X509_getm_notBefore(x.get()), 0);
        X509_gmtime_adj(X509_getm_notAfter(x.get()), static_cast<long>(days) * 86400L);
        X509_set_pubkey(x.get(), pkey.get());
        X509_NAME* sub = X509_get_subject_name(x.get());
        X509_NAME_add_entry_by_txt(sub, "CN", MBSTRING_ASC,
            reinterpret_cast<unsigned char const*>(common_name.data()), static_cast<int>(common_name.size()), -1, 0);
        X509_set_issuer_name(x.get(), sub);
        if (!X509_sign(x.get(), pkey.get(), EVP_sha256())) return std::unexpected("X509_sign failed");

        SslPtr<BIO, BIO_free> cert_bio(BIO_new(BIO_s_mem())), key_bio(BIO_new(BIO_s_mem()));
        if (!cert_bio || !key_bio || !PEM_write_bio_X509(cert_bio.get(), x.get()) ||
            !PEM_write_bio_PrivateKey(key_bio.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr))
            return std::unexpected("PEM serialization failed");
        return std::pair{bio_to_string(cert_bio.get()), bio_to_string(key_bio.get())};
    }

    auto generate_ech_keypair(std::string_view public_name, std::uint8_t config_id)
        -> std::expected<EchKeypairOutput, std::string> {
        if (public_name.empty() || public_name.size() > 253)
            return std::unexpected("invalid ECH public-name");
        std::array<std::uint8_t, 32> priv{}, pub{};
        if (auto ok = generate_clamped_x25519(priv, pub); !ok) return std::unexpected(ok.error());

        std::vector<std::uint8_t> contents;
        contents.push_back(config_id);
        put_u16(contents, 0x0020); // DHKEM(X25519, HKDF-SHA256)
        put_u16(contents, 32);
        contents.insert(contents.end(), pub.begin(), pub.end());
        put_u16(contents, 4);      // cipher_suites len
        put_u16(contents, 0x0001); // HKDF-SHA256
        put_u16(contents, 0x0001); // AES-128-GCM
        contents.push_back(64);    // maximum_name_length
        contents.push_back(static_cast<std::uint8_t>(public_name.size()));
        contents.insert(contents.end(), public_name.begin(), public_name.end());
        put_u16(contents, 0);      // extensions len

        std::vector<std::uint8_t> cfg;
        put_u16(cfg, 0xfe0d);
        put_u16(cfg, static_cast<std::uint16_t>(contents.size()));
        cfg.insert(cfg.end(), contents.begin(), contents.end());

        std::vector<std::uint8_t> list;
        put_u16(list, static_cast<std::uint16_t>(cfg.size()));
        list.insert(list.end(), cfg.begin(), cfg.end());

        EchKeypairOutput out{
            .private_key_base64 = encode_base64(priv, false, true),
            .config_list_base64 = encode_base64(list, false, true),
            .config_list_wire = std::move(list),
        };
        crypto::cleanse(priv);
        return out;
    }

    auto nexus_generate(int argc, char** argv) -> int {
        auto usage = [] {
            std::cerr << "usage: nexus generate <uuid|reality-keypair|wg-keypair|ss2022-key|tls-selfsigned|ech-keypair> [options]\n";
        };
        if (argc < 2 || std::string_view(argv[1]) == "--help") { usage(); return argc < 2 ? 2 : 0; }
        std::string_view sub = argv[1];
        if (sub == "uuid") {
            auto res = generate_uuid();
            if (!res) { std::cerr << res.error() << '\n'; return 1; }
            std::cout << *res << '\n';
            return 0;
        }
        if (sub == "reality-keypair" || sub == "wg-keypair") {
            auto res = generate_x25519_keypair(sub == "reality-keypair");
            if (!res) { std::cerr << res.error() << '\n'; return 1; }
            std::cout << "PrivateKey: " << res->first << "\nPublicKey: " << res->second << '\n';
            return 0;
        }
        if (sub == "ss2022-key") {
            std::size_t bytes = 32;
            if (argc >= 3) {
                std::string_view arg = argv[2];
                if (arg == "16") bytes = 16;
                else if (arg == "32") bytes = 32;
                else { std::cerr << "ss2022-key size must be 16 or 32\n"; return 2; }
            }
            auto res = generate_ss2022_key(bytes);
            if (!res) { std::cerr << res.error() << '\n'; return 1; }
            std::cout << *res << '\n';
            return 0;
        }
        if (sub == "tls-selfsigned") {
            std::string_view cn = "localhost";
            int days = 365;
            for (int i = 2; i + 1 < argc; i += 2) {
                std::string_view opt = argv[i];
                if (opt == "--cn") cn = argv[i + 1];
                else if (opt == "--days") days = std::stoi(argv[i + 1]);
            }
            auto res = generate_self_signed_tls(cn, days);
            if (!res) { std::cerr << res.error() << '\n'; return 1; }
            std::cout << res->first << res->second;
            return 0;
        }
        if (sub == "ech-keypair") {
            std::string_view pub_name = "cloudflare-ech.com";
            for (int i = 2; i + 1 < argc; i += 2) {
                if (std::string_view(argv[i]) == "--public-name") pub_name = argv[i + 1];
            }
            auto res = generate_ech_keypair(pub_name);
            if (!res) { std::cerr << res.error() << '\n'; return 1; }
            std::cout << "PrivateKey: " << res->private_key_base64 << "\nEchConfigList: " << res->config_list_base64 << '\n';
            return 0;
        }
        std::cerr << "unknown generate subcommand: " << sub << '\n';
        usage();
        return 2;
    }
}
