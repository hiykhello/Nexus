#include <cassert>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

import std;
import boringssl;
import acme.types;
import acme.jws;
import acme.store;
import acme.client;

namespace {
    using namespace boringssl;

    auto extract_json_str(std::string_view json, std::string_view key) -> std::string {
        auto pat = std::format("\"{}\":\"", key);
        auto pos = json.find(pat);
        if (pos == std::string_view::npos) return {};
        pos += pat.size();
        auto end = json.find('"', pos);
        return end == std::string_view::npos ? std::string{} : std::string(json.substr(pos, end - pos));
    }

    auto sign_cert_from_csr_der(std::span<std::uint8_t const> csr_der) -> std::string {
        auto const* p = csr_der.data();
        std::unique_ptr<X509_REQ, decltype(&X509_REQ_free)> req(
            d2i_X509_REQ(nullptr, &p, static_cast<long>(csr_der.size())), X509_REQ_free);
        assert(req != nullptr);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pub(X509_REQ_get_pubkey(req.get()), EVP_PKEY_free);
        assert(pub != nullptr);
        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> kctx(
            EVP_PKEY_CTX_new_id(evp_pkey_ed25519, nullptr), EVP_PKEY_CTX_free);
        EVP_PKEY* ca_raw = nullptr;
        assert(kctx && EVP_PKEY_keygen_init(kctx.get()) == 1 && EVP_PKEY_keygen(kctx.get(), &ca_raw) == 1);
        std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> ca_key(ca_raw, EVP_PKEY_free);
        std::unique_ptr<X509, decltype(&X509_free)> cert(X509_new(), X509_free);
        assert(cert && X509_set_version(cert.get(), 2) == 1 && ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 7) == 1);
        assert(X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60) &&
               X509_gmtime_adj(X509_getm_notAfter(cert.get()), 86400 * 90));
        assert(X509_set_pubkey(cert.get(), pub.get()) == 1);
        assert(X509_set_subject_name(cert.get(), X509_REQ_get_subject_name(req.get())) == 1);
        assert(X509_set_issuer_name(cert.get(), X509_REQ_get_subject_name(req.get())) == 1);
        assert(X509_sign(cert.get(), ca_key.get(), nullptr) > 0);
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
        assert(bio && PEM_write_bio_X509(bio.get(), cert.get()) == 1);
        char* data = nullptr;
        auto len = BIO_get_mem_data(bio.get(), &data);
        return std::string(data, static_cast<std::size_t>(len));
    }

    struct MockAcmeServer {
        std::string override_cert_pem;
        std::string issued_cert_pem;
        std::string alpn_cert_pem;
        std::string http_token, http_key_auth;
        std::string dns_domain, dns_txt;
        std::string order_status = "pending";
        unsigned pending_polls_before_ready = 0;
        unsigned processing_polls_before_valid = 0;
        unsigned order_polls = 0;
        unsigned post_fin_polls = 0;
        unsigned finalize_calls = 0;
        bool finalized = false;
        unsigned challenge_acks = 0;

        auto exchange(acme::HttpRequest const& req) -> std::expected<acme::HttpResponse, std::string> {
            using R = acme::HttpResponse;
            if (req.method == "GET" && req.url == "https://mock.acme/dir")
                return R{200, "n1", {}, R"({"newNonce":"https://mock.acme/nonce","newAccount":"https://mock.acme/acc","newOrder":"https://mock.acme/order"})"};
            if (req.method == "HEAD" && req.url == "https://mock.acme/nonce")
                return R{200, "n2", {}, {}};
            if (req.url == "https://mock.acme/acc")
                return R{201, "n3", "https://mock.acme/acct/1", R"({"status":"valid"})"};
            if (req.url == "https://mock.acme/order")
                return R{201, "n4", "https://mock.acme/order/1",
                    R"({"status":"pending","authorizations":["https://mock.acme/authz/1"],"finalize":"https://mock.acme/fin/1"})"};
            if (req.url == "https://mock.acme/authz/1")
                return R{200, "n5", {},
                    R"({"identifier":{"type":"dns","value":"edge.example.com"},"status":"pending","challenges":[{"type":"http-01","url":"https://mock.acme/ch/http","token":"tokHTTP","status":"pending"},{"type":"tls-alpn-01","url":"https://mock.acme/ch/alpn","token":"tokALPN","status":"pending"},{"type":"dns-01","url":"https://mock.acme/ch/dns","token":"tokDNS","status":"pending"}]})"};
            if (req.url.starts_with("https://mock.acme/ch/")) {
                ++challenge_acks;
                order_status = (pending_polls_before_ready == 0) ? "ready" : "pending";
                return R{200, "n6", {}, R"({"status":"valid"})"};
            }
            if (req.url == "https://mock.acme/fin/1") {
                ++finalize_calls;
                finalized = true;
                assert(req.body.contains("signature") && req.body.contains("protected"));
                auto pay = acme::base64url_decode(extract_json_str(req.body, "payload"));
                assert(pay.has_value());
                auto csr_der = acme::base64url_decode(
                    extract_json_str({reinterpret_cast<char const*>(pay->data()), pay->size()}, "csr"));
                assert(csr_der.has_value());
                issued_cert_pem = override_cert_pem.empty() ? sign_cert_from_csr_der(*csr_der) : override_cert_pem;
                if (processing_polls_before_valid == 0) {
                    order_status = "valid";
                    return R{200, "n7", "https://mock.acme/order/1",
                        R"({"status":"valid","finalize":"https://mock.acme/fin/1","certificate":"https://mock.acme/cert/1"})"};
                }
                order_status = "processing";
                return R{200, "n7", "https://mock.acme/order/1",
                    R"({"status":"processing","finalize":"https://mock.acme/fin/1"})"};
            }
            if (req.url == "https://mock.acme/order/1") {
                ++order_polls;
                if (!finalized && pending_polls_before_ready > 0 && order_polls > pending_polls_before_ready)
                    order_status = "ready";
                if (finalized && order_status == "processing") {
                    ++post_fin_polls;
                    if (post_fin_polls > processing_polls_before_valid) order_status = "valid";
                }
                auto body = (order_status == "valid")
                    ? std::string(R"({"status":"valid","finalize":"https://mock.acme/fin/1","certificate":"https://mock.acme/cert/1"})")
                    : std::format(R"({{"status":"{}","finalize":"https://mock.acme/fin/1"}})", order_status);
                return R{200, "n8", "https://mock.acme/order/1", std::move(body)};
            }
            if (req.url == "https://mock.acme/cert/1")
                return R{200, "n9", {}, issued_cert_pem};
            return std::unexpected("unexpected URL");
        }
    };

    auto write_file_mode(std::filesystem::path const& p, std::string_view text, bool priv) -> void {
        std::ofstream(p, std::ios::binary | std::ios::trunc).write(text.data(), static_cast<std::streamsize>(text.size()));
        if (priv) {
            std::filesystem::permissions(p, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace);
        }
    }
}

int main() {
    auto key = acme::EcAccountKey::generate_p256();
    assert(key.has_value());
    auto reloaded = acme::EcAccountKey::from_pem(key->to_pem());
    assert(reloaded.has_value() && *reloaded->jwk_thumbprint() == *key->jwk_thumbprint());

    auto alpn_dig = key->tls_alpn01_digest("tokALPN");
    assert(alpn_dig.has_value());
    auto sample_cert = acme::generate_alpn01_cert("edge.example.com", *alpn_dig);
    assert(sample_cert.has_value() && sample_cert->cert_pem.contains("BEGIN CERTIFICATE"));
    assert(acme::verify_cert_key_pair(sample_cert->cert_pem, sample_cert->key_pem).has_value());
    auto sample_cert2 = acme::generate_alpn01_cert("edge.example.com", *alpn_dig);
    assert(sample_cert2.has_value());
    assert(!acme::verify_cert_key_pair(sample_cert->cert_pem, sample_cert2->key_pem).has_value());
    auto now_ep = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    auto tmp_dir = std::filesystem::temp_directory_path() / "nexus_acme_unit_test";
    for (auto ch_type : {acme::ChallengeType::http01, acme::ChallengeType::tls_alpn01, acme::ChallengeType::dns01}) {
        MockAcmeServer srv{};
        acme::CertificateStore store;
        std::filesystem::remove_all(tmp_dir);

        acme::AcmeConfig cfg{
            .directory_url = "https://mock.acme/dir", .domains = {"edge.example.com"},
            .email = "ops@example.com", .challenge = ch_type, .state_dir = tmp_dir,
            .renew_before_seconds = 3600, .poll_initial_backoff_ms = 0,
        };
        bool published = false;
        acme::ChallengeHooks hooks{
            .publish_http01 = [&](std::string_view t, std::string_view ka) { srv.http_token = t; srv.http_key_auth = ka; return true; },
            .publish_alpn01 = [&](std::string_view, std::string_view cp, std::string_view) { srv.alpn_cert_pem = cp; return true; },
            .publish_dns01 = [&](std::string_view d, std::string_view txt) { srv.dns_domain = d; srv.dns_txt = txt; return true; },
            .publish_certificate = [&](acme::CertificateBundle const& b) -> std::expected<void, std::string> {
                assert(acme::verify_cert_key_pair(b.cert_pem, b.key_pem).has_value());
                published = true;
                return {};
            },
        };
        auto ok = acme::ensure_certificate(cfg, store, *key,
            [&](acme::HttpRequest const& req) { return srv.exchange(req); }, hooks, now_ep);
        assert(ok.has_value() && *ok && srv.finalized && srv.challenge_acks == 1 && published);
        auto cur = store.current();
        assert(cur && cur->cert_pem == srv.issued_cert_pem && !cur->key_pem.empty());
        assert(acme::verify_cert_key_pair(cur->cert_pem, cur->key_pem).has_value());
        assert(!store.needs_renewal(now_ep, 3600));
        assert(store.needs_renewal(cur->not_after_epoch - 100, 3600));

        auto disk = acme::CertificateStore::load_from_dir(tmp_dir);
        assert(disk.has_value() && disk->cert_pem == srv.issued_cert_pem && disk->key_pem == cur->key_pem);
        std::filesystem::remove_all(tmp_dir);
    }

    // R6 P1-3: Mismatched certificate returned by CA must be rejected before publish, disk save, or store install.
    {
        std::filesystem::remove_all(tmp_dir);
        MockAcmeServer bad_srv{.override_cert_pem = sample_cert->cert_pem};
        acme::CertificateStore store;
        acme::AcmeConfig cfg{
            .directory_url = "https://mock.acme/dir", .domains = {"edge.example.com"},
            .email = "ops@example.com", .challenge = acme::ChallengeType::http01,
            .state_dir = tmp_dir, .renew_before_seconds = 3600, .poll_initial_backoff_ms = 0,
        };
        bool published = false;
        acme::ChallengeHooks hooks{
            .publish_http01 = [&](std::string_view, std::string_view) { return true; },
            .publish_certificate = [&](acme::CertificateBundle const&) -> std::expected<void, std::string> {
                published = true;
                return {};
            },
        };
        auto res = acme::ensure_certificate(cfg, store, *key,
            [&](acme::HttpRequest const& req) { return bad_srv.exchange(req); }, hooks, now_ep);
        assert(!res.has_value() && res.error().contains("does not match private key"));
        assert(!published && !store.current() && store.needs_renewal(now_ep, 3600));
        assert(!acme::CertificateStore::load_from_dir(tmp_dir).has_value());
    }

    // R6 P1-3: Live publish failure propagates and prevents disk commit or advancing renewal state.
    {
        std::filesystem::remove_all(tmp_dir);
        MockAcmeServer srv{};
        acme::CertificateStore store;
        acme::AcmeConfig cfg{
            .directory_url = "https://mock.acme/dir", .domains = {"edge.example.com"},
            .email = "ops@example.com", .challenge = acme::ChallengeType::http01,
            .state_dir = tmp_dir, .renew_before_seconds = 3600, .poll_initial_backoff_ms = 0,
        };
        acme::ChallengeHooks hooks{
            .publish_http01 = [&](std::string_view, std::string_view) { return true; },
            .publish_certificate = [&](acme::CertificateBundle const&) -> std::expected<void, std::string> {
                return std::unexpected("live TLS swap rejected");
            },
        };
        auto res = acme::ensure_certificate(cfg, store, *key,
            [&](acme::HttpRequest const& req) { return srv.exchange(req); }, hooks, now_ep);
        assert(!res.has_value() && res.error().contains("live TLS swap rejected"));
        assert(!store.current() && store.needs_renewal(now_ep, 3600));
        assert(!acme::CertificateStore::load_from_dir(tmp_dir).has_value());
    }

    // R6 P1-3: Cold-start load_from_dir rejects mismatched legacy fullchain.pem+privkey.pem and mismatched credential.pem;
    // existing valid gen 1 survives failed mismatched renewal.
    {
        std::filesystem::remove_all(tmp_dir);
        std::filesystem::create_directories(tmp_dir);
        write_file_mode(tmp_dir / "fullchain.pem", sample_cert->cert_pem, false);
        write_file_mode(tmp_dir / "privkey.pem", sample_cert2->key_pem, true);
        assert(!acme::CertificateStore::load_from_dir(tmp_dir).has_value());

        write_file_mode(tmp_dir / "credential.pem", sample_cert2->key_pem + "\n" + sample_cert->cert_pem, true);
        assert(!acme::CertificateStore::load_from_dir(tmp_dir).has_value());

        std::filesystem::remove_all(tmp_dir);
        MockAcmeServer gen1_srv{};
        acme::CertificateStore store;
        acme::AcmeConfig cfg{
            .directory_url = "https://mock.acme/dir", .domains = {"edge.example.com"},
            .email = "ops@example.com", .challenge = acme::ChallengeType::http01,
            .state_dir = tmp_dir, .renew_before_seconds = 3600, .poll_initial_backoff_ms = 0,
        };
        acme::ChallengeHooks hooks{.publish_http01 = [&](std::string_view, std::string_view) { return true; }};
        auto r1 = acme::ensure_certificate(cfg, store, *key,
            [&](acme::HttpRequest const& req) { return gen1_srv.exchange(req); }, hooks, now_ep);
        assert(r1.has_value() && *r1);
        auto gen1 = store.current();
        assert(gen1 != nullptr);

        // Renew near expiry with a mismatched gen 2 cert -> must fail and preserve gen 1 on disk & in store.
        MockAcmeServer gen2_bad{.override_cert_pem = sample_cert->cert_pem};
        auto r2 = acme::ensure_certificate(cfg, store, *key,
            [&](acme::HttpRequest const& req) { return gen2_bad.exchange(req); }, hooks, gen1->not_after_epoch - 60);
        assert(!r2.has_value());
        assert(store.current() && store.current()->cert_pem == gen1->cert_pem && store.current()->key_pem == gen1->key_pem);
        auto reloaded_gen1 = acme::CertificateStore::load_from_dir(tmp_dir);
        assert(reloaded_gen1 && reloaded_gen1->cert_pem == gen1->cert_pem && reloaded_gen1->key_pem == gen1->key_pem);
        std::filesystem::remove_all(tmp_dir);
    }

    // R6 P2-3: Slow order staying pending for 15 polls (> old 10-poll limit) transitions to ready -> calls finalize ONCE -> processing -> valid.
    {
        std::filesystem::remove_all(tmp_dir);
        MockAcmeServer slow_srv{.pending_polls_before_ready = 15, .processing_polls_before_valid = 2};
        acme::CertificateStore store;
        acme::AcmeConfig cfg{
            .directory_url = "https://mock.acme/dir", .domains = {"edge.example.com"},
            .email = "ops@example.com", .challenge = acme::ChallengeType::http01,
            .state_dir = tmp_dir, .renew_before_seconds = 3600,
            .max_poll_attempts = 30, .poll_initial_backoff_ms = 1, .poll_max_backoff_ms = 4, .poll_deadline_ms = 5000,
        };
        acme::ChallengeHooks hooks{.publish_http01 = [&](std::string_view, std::string_view) { return true; }};
        auto ok = acme::ensure_certificate(cfg, store, *key,
            [&](acme::HttpRequest const& req) { return slow_srv.exchange(req); }, hooks, now_ep);
        assert(ok.has_value() && *ok && slow_srv.finalize_calls == 1 && slow_srv.order_polls >= 16 &&
               store.current() && acme::verify_cert_key_pair(store.current()->cert_pem, store.current()->key_pem).has_value());
        std::filesystem::remove_all(tmp_dir);
    }

    // R6 P2-3: Order stuck pending past poll_deadline_ms exits cleanly with error.
    {
        MockAcmeServer stuck_srv{.pending_polls_before_ready = 9999};
        acme::CertificateStore store;
        acme::AcmeConfig cfg{
            .directory_url = "https://mock.acme/dir", .domains = {"edge.example.com"},
            .email = "ops@example.com", .challenge = acme::ChallengeType::http01,
            .max_poll_attempts = 200, .poll_initial_backoff_ms = 5, .poll_max_backoff_ms = 15, .poll_deadline_ms = 50,
        };
        acme::ChallengeHooks hooks{.publish_http01 = [&](std::string_view, std::string_view) { return true; }};
        auto res = acme::ensure_certificate(cfg, store, *key,
            [&](acme::HttpRequest const& req) { return stuck_srv.exchange(req); }, hooks, now_ep);
        assert(!res.has_value() && !stuck_srv.finalized && !store.current());
    }

    std::println("ACME unit tests (HTTP-01 / TLS-ALPN-01 / DNS-01 / CSR / R6 P1-3 / R6 P2-3) passed");
    return 0;
}
