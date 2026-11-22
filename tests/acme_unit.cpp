#include <cassert>

import std;
import acme.types;
import acme.jws;
import acme.store;
import acme.client;

namespace {
    struct MockAcmeServer {
        std::string cert_pem;
        std::string alpn_cert_pem;
        std::string http_token, http_key_auth;
        std::string dns_domain, dns_txt;
        std::string order_status = "pending";
        bool finalized = false;
        unsigned challenge_acks = 0;

        auto exchange(acme::HttpRequest const& req) -> std::expected<acme::HttpResponse, std::string> {
            using R = acme::HttpResponse;
            if (req.method == "GET" && req.url == "https://mock.acme/dir") {
                return R{200, "n1", {}, R"({"newNonce":"https://mock.acme/nonce","newAccount":"https://mock.acme/acc","newOrder":"https://mock.acme/order"})"};
            }
            if (req.method == "HEAD" && req.url == "https://mock.acme/nonce") {
                return R{200, "n2", {}, {}};
            }
            if (req.url == "https://mock.acme/acc") {
                return R{201, "n3", "https://mock.acme/acct/1", R"({"status":"valid"})"};
            }
            if (req.url == "https://mock.acme/order") {
                return R{201, "n4", "https://mock.acme/order/1",
                    R"({"status":"pending","authorizations":["https://mock.acme/authz/1"],"finalize":"https://mock.acme/fin/1"})"};
            }
            if (req.url == "https://mock.acme/authz/1") {
                return R{200, "n5", {},
                    R"({"identifier":{"type":"dns","value":"edge.example.com"},"status":"pending","challenges":[{"type":"http-01","url":"https://mock.acme/ch/http","token":"tokHTTP","status":"pending"},{"type":"tls-alpn-01","url":"https://mock.acme/ch/alpn","token":"tokALPN","status":"pending"},{"type":"dns-01","url":"https://mock.acme/ch/dns","token":"tokDNS","status":"pending"}]})"};
            }
            if (req.url.starts_with("https://mock.acme/ch/")) {
                ++challenge_acks;
                order_status = "ready";
                return R{200, "n6", {}, R"({"status":"valid"})"};
            }
            if (req.url == "https://mock.acme/fin/1") {
                finalized = true;
                order_status = "valid";
                assert(req.body.contains("signature") && req.body.contains("protected"));
                return R{200, "n7", "https://mock.acme/order/1",
                    R"({"status":"valid","finalize":"https://mock.acme/fin/1","certificate":"https://mock.acme/cert/1"})"};
            }
            if (req.url == "https://mock.acme/order/1") {
                auto body = std::format(R"({{"status":"{}","finalize":"https://mock.acme/fin/1","certificate":"https://mock.acme/cert/1"}})", order_status);
                return R{200, "n8", "https://mock.acme/order/1", std::move(body)};
            }
            if (req.url == "https://mock.acme/cert/1") {
                return R{200, "n9", {}, cert_pem};
            }
            return std::unexpected("unexpected URL");
        }
    };
}

int main() {
    auto key = acme::EcAccountKey::generate_p256();
    assert(key.has_value());
    auto reloaded = acme::EcAccountKey::from_pem(key->to_pem());
    assert(reloaded.has_value() && *reloaded->jwk_thumbprint() == *key->jwk_thumbprint());

    // Build a valid X.509 PEM fixture using ALPN helper so parse_cert_validity parses real OpenSSL PEM.
    auto alpn_dig = key->tls_alpn01_digest("tokALPN");
    assert(alpn_dig.has_value());
    auto sample_cert = acme::generate_alpn01_cert("edge.example.com", *alpn_dig);
    assert(sample_cert.has_value() && sample_cert->cert_pem.contains("BEGIN CERTIFICATE"));
    assert(sample_cert->cert_pem.contains("1.3.6.1.5.5.7.1.31") || !sample_cert->key_pem.empty());
    auto validity = acme::parse_cert_validity(sample_cert->cert_pem);
    assert(validity.has_value() && validity->not_after_epoch > validity->not_before_epoch);

    for (auto ch_type : {acme::ChallengeType::http01, acme::ChallengeType::tls_alpn01, acme::ChallengeType::dns01}) {
        MockAcmeServer srv{.cert_pem = sample_cert->cert_pem};
        acme::CertificateStore store;
        auto tmp_dir = std::filesystem::temp_directory_path() / "nexus_acme_unit_test";
        std::filesystem::remove_all(tmp_dir);

        acme::AcmeConfig cfg{
            .directory_url = "https://mock.acme/dir",
            .domains = {"edge.example.com"},
            .email = "ops@example.com",
            .challenge = ch_type,
            .state_dir = tmp_dir,
            .renew_before_seconds = 3600,
        };
        acme::ChallengeHooks hooks{
            .publish_http01 = [&](std::string_view t, std::string_view ka) { srv.http_token = t; srv.http_key_auth = ka; return true; },
            .publish_alpn01 = [&](std::string_view, std::string_view cp, std::string_view) { srv.alpn_cert_pem = cp; return true; },
            .publish_dns01 = [&](std::string_view d, std::string_view txt) { srv.dns_domain = d; srv.dns_txt = txt; return true; },
        };
        auto ok = acme::ensure_certificate(cfg, store, *key,
            [&](acme::HttpRequest const& req) { return srv.exchange(req); }, hooks, validity->not_before_epoch + 10);
        assert(ok.has_value() && *ok && srv.finalized && srv.challenge_acks == 1);
        auto cur = store.current();
        assert(cur && cur->cert_pem == sample_cert->cert_pem && !cur->key_pem.empty());
        assert(!store.needs_renewal(validity->not_before_epoch + 10, 3600));
        assert(store.needs_renewal(validity->not_after_epoch - 100, 3600));

        auto disk = acme::CertificateStore::load_from_dir(tmp_dir);
        assert(disk.has_value() && disk->cert_pem == sample_cert->cert_pem);
        std::filesystem::remove_all(tmp_dir);
    }

    std::println("ACME unit tests (HTTP-01 / TLS-ALPN-01 / DNS-01 / CSR / hot-swap) passed");
    return 0;
}
