#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/timeout.hpp>
#include <cstdlib>

import std;
import acme.types;
import acme.jws;
import acme.store;
import acme.client;
import acme.dns01_providers;
import capy;
import cli.cert_reloader;
import config;
import corosio;
import crypto;
import encoding.base64;
import encoding.base64_key;
import relay;
import tls.profiles;
import tls.server_credential;
import tls.client_handshake_io;
import tls.corosio_client;

namespace io = ::corosio;
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

namespace {
    auto require(bool ok, std::string_view msg) -> void {
        if (!ok) { std::cerr << "FAIL [wave31-acme-tls-reload]: " << msg << '\n'; std::exit(1); }
    }

    struct TempDir {
        fs::path path;
        ~TempDir() { if (!path.empty()) { std::error_code ec; fs::remove_all(path, ec); } }
    };

    auto make_temp_dir(std::string_view prefix) -> TempDir {
        auto dir = fs::temp_directory_path() / (std::string(prefix) + "-" + std::to_string(Clock::now().time_since_epoch().count()));
        fs::create_directories(dir);
        return TempDir{dir};
    }

    auto write_file(fs::path const& file, std::string_view content, bool private_mode = false) -> void {
        { std::ofstream out(file, std::ios::binary | std::ios::trunc); require(bool(out), "open write"); out.write(content.data(), static_cast<std::streamsize>(content.size())); require(bool(out), "write"); }
        if (private_mode) { std::error_code ec; fs::permissions(file, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec); require(!ec, "chmod"); }
    }
    auto read_text(fs::path const& file) -> std::string { std::ifstream f(file, std::ios::binary); require(bool(f), "read"); return {std::istreambuf_iterator<char>(f), {}}; }
    auto make_cert(fs::path const& cert, fs::path const& key, std::string_view cn, std::string_view san) -> void {
        auto cmd = std::format("openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout '{}' -out '{}' -subj '/CN={}' -addext 'subjectAltName={}' -days 1 >/dev/null 2>&1", key.string(), cert.string(), cn, san);
        require(std::system(cmd.c_str()) == 0, "openssl cert gen");
        std::error_code ec; fs::permissions(key, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace, ec); require(!ec, "chmod key");
    }
    auto now_ms() noexcept -> std::uint64_t { return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count()); }
    auto json_field(std::string_view json, std::string_view key) -> std::string {
        auto pat = std::format("\"{}\":\"", key); auto pos = json.find(pat);
        if (pos == std::string_view::npos) return {};
        pos += pat.size(); auto end = json.find('"', pos);
        return end == std::string_view::npos ? std::string{} : std::string(json.substr(pos, end - pos));
    }

    auto test_eab_and_wildcard_acme() -> void {
        auto dec = acme::base64url_decode("SGVsbG8td29ybGQ");
        require(dec.has_value() && std::string(dec->begin(), dec->end()) == "Hello-world", "b64url decode valid");
        require(!acme::base64url_decode("a").has_value() && !acme::base64url_decode("abc+").has_value() &&
                !acme::base64url_decode("abc/").has_value() && !acme::base64url_decode("SGVs=").has_value() &&
                !acme::base64url_decode("AB").has_value(), "b64url invalid rejected");

        auto key = acme::EcAccountKey::generate_p256();
        require(key.has_value(), "generate_p256");
        std::vector<std::uint8_t> hmac_key{0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80};
        auto eab = acme::sign_eab_jws(*key, "https://ca.example/new-account", "kid-zero-1", hmac_key);
        require(eab.has_value(), eab ? "" : eab.error());

        auto prot_b64 = json_field(*eab, "protected"), pay_b64 = json_field(*eab, "payload"), sig_b64 = json_field(*eab, "signature");
        auto prot_raw = acme::base64url_decode(prot_b64), pay_raw = acme::base64url_decode(pay_b64);
        require(prot_raw.has_value() && pay_raw.has_value() && !sig_b64.empty(), "eab decode");
        require(std::string(prot_raw->begin(), prot_raw->end()) ==
            R"({"alg":"HS256","kid":"kid-zero-1","url":"https://ca.example/new-account"})", "eab protected header exact");
        require(std::string(pay_raw->begin(), pay_raw->end()) == key->jwk_json(), "eab payload equals account jwk");

        std::string signing_input = prot_b64 + "." + pay_b64;
        auto expected_mac = crypto::hmac(crypto::Hash::sha256, hmac_key,
            {reinterpret_cast<std::uint8_t const*>(signing_input.data()), signing_input.size()});
        require(expected_mac.has_value() && sig_b64 == acme::base64url_encode(*expected_mac), "eab HS256 signature verified");

        auto tmp = make_temp_dir("nexus-w31-eab");
        auto cert_file = tmp.path / "issued.pem", key_file = tmp.path / "issued.key";
        make_cert(cert_file, key_file, "example.com", "DNS:*.example.com,DNS:example.com");
        auto issued_pem = read_text(cert_file);
        auto validity = acme::parse_cert_validity(issued_pem);
        require(validity.has_value(), "parse issued cert validity");

        bool saw_eab = false, cleaned_up = false;
        std::string published_domain, published_txt, order_status = "pending";
        auto exchange = [&](acme::HttpRequest const& req) -> std::expected<acme::HttpResponse, std::string> {
            using R = acme::HttpResponse;
            if (req.url == "https://ca.example/dir")
                return R{200, "n1", {}, R"({"newNonce":"https://ca.example/nonce","newAccount":"https://ca.example/acc","newOrder":"https://ca.example/order"})"};
            if (req.url == "https://ca.example/nonce") return R{200, "n2", {}, {}};
            if (req.url == "https://ca.example/acc") {
                auto pb = acme::base64url_decode(json_field(req.body, "payload"));
                require(pb.has_value(), "newAccount payload decode");
                std::string p(pb->begin(), pb->end());
                saw_eab = p.contains("\"externalAccountBinding\":") && p.contains("\"protected\":");
                return R{201, "n3", "https://ca.example/acct/9", R"({"status":"valid"})"};
            }
            if (req.url == "https://ca.example/order")
                return R{201, "n4", "https://ca.example/ord/9", R"({"status":"pending","authorizations":["https://ca.example/authz/9"],"finalize":"https://ca.example/fin/9"})"};
            if (req.url == "https://ca.example/authz/9")
                return R{200, "n5", {}, R"({"identifier":{"type":"dns","value":"example.com"},"status":"pending","challenges":[{"type":"dns-01","url":"https://ca.example/ch/9","token":"tokWild","status":"pending"}]})"};
            if (req.url == "https://ca.example/ch/9") { order_status = "ready"; return R{200, "n6", {}, R"({"status":"valid"})"}; }
            if (req.url == "https://ca.example/fin/9") { order_status = "valid"; return R{200, "n7", {}, R"({"status":"valid","finalize":"https://ca.example/fin/9","certificate":"https://ca.example/cert/9"})"}; }
            if (req.url == "https://ca.example/ord/9")
                return R{200, "n8", {}, std::format(R"({{"status":"{}","finalize":"https://ca.example/fin/9","certificate":"https://ca.example/cert/9"}})", order_status)};
            if (req.url == "https://ca.example/cert/9") return R{200, "n9", {}, issued_pem};
            return std::unexpected("unexpected url");
        };
        acme::AcmeConfig cfg{
            .directory_url = "https://ca.example/dir", .domains = {"*.example.com"},
            .email = "admin@example.com", .challenge = acme::ChallengeType::dns01,
            .state_dir = tmp.path / "store", .renew_before_seconds = 3600,
            .eab = acme::EabCredentials{"kid-zero-1", hmac_key},
        };
        acme::CertificateStore store;
        acme::ChallengeHooks hooks{
            .publish_dns01 = [&](std::string_view d, std::string_view txt) { published_domain = d; published_txt = txt; return true; },
            .cleanup = [&]() { cleaned_up = true; },
        };
        auto ok = acme::ensure_certificate(cfg, store, *key, exchange, hooks, validity->not_before_epoch + 10);
        require(ok.has_value() && *ok && saw_eab && cleaned_up, "eab + wildcard dns-01 issuance");
        require(published_domain == "example.com" && !published_txt.empty(), "wildcard dns-01 authz matched");
    }

    auto test_cloudflare_and_alidns_providers() -> void {
        int cf_gets = 0; bool cf_posted = false, cf_deleted = false;
        acme::CloudflareDns01Provider cf("cf-token-xyz");
        auto cf_http = [&](acme::HttpRequest const& req) -> std::expected<acme::HttpResponse, std::string> {
            bool has_auth = std::ranges::any_of(req.headers, [](auto const& kv) {
                return kv.first == "Authorization" && kv.second == "Bearer cf-token-xyz";
            });
            require(has_auth, "cloudflare bearer auth header");
            if (req.method == "GET" && (req.url.contains("name=app.sub.example.com") || req.url.contains("name=sub.example.com"))) {
                ++cf_gets;
                return acme::HttpResponse{200, {}, {}, R"({"success":true,"result":[]})"};
            }
            if (req.method == "GET" && req.url.contains("name=example.com")) {
                ++cf_gets;
                return acme::HttpResponse{200, {}, {}, R"({"success":true,"result":[{"id":"zone777","name":"example.com"}]})"};
            }
            if (req.method == "POST" && req.url.ends_with("/zones/zone777/dns_records")) {
                require(req.body.contains(R"("type":"TXT")") &&
                        req.body.contains(R"("name":"_acme-challenge.app.sub.example.com")") &&
                        req.body.contains(R"("content":"txt-digest-1")"), "cloudflare TXT payload");
                cf_posted = true;
                return acme::HttpResponse{200, {}, {}, R"({"success":true,"result":{"id":"rec888"}})"};
            }
            if (req.method == "DELETE" && req.url.ends_with("/zones/zone777/dns_records/rec888")) {
                cf_deleted = true;
                return acme::HttpResponse{200, {}, {}, R"({"success":true,"result":{"id":"rec888"}})"};
            }
            return std::unexpected("unexpected cf request");
        };
        auto cf_handle = cf.publish("*.app.sub.example.com.", "txt-digest-1", cf_http);
        require(cf_handle.has_value() && cf_handle->zone == "zone777" && cf_handle->record_id == "rec888" && cf_gets == 3 && cf_posted, "cf publish");
        auto cf_clean = cf.cleanup(*cf_handle, cf_http);
        require(cf_clean.has_value() && cf_deleted, "cf delete cleanup");
        auto cf_fail = cf.publish("example.com", "txt", [](acme::HttpRequest const&) -> std::expected<acme::HttpResponse, std::string> {
            return acme::HttpResponse{403, {}, {}, R"({"success":false,"errors":[{"message":"Forbidden"}]})"};
        });
        require(!cf_fail.has_value(), "cf error propagated");

        std::array<std::pair<std::string, std::string>, 5> params{{
            {"Action", "AddDomainRecord"}, {"DomainName", "example.com"},
            {"RR", "_acme-challenge"}, {"Type", "TXT"}, {"Value", "hello+world/test="},
        }};
        auto qs = acme::alidns_build_signed_query(params, "secret-key", "GET");
        require(qs.has_value(), qs ? "" : qs.error());
        auto sig_pos = qs->find("&Signature=");
        require(sig_pos != std::string::npos, "alidns Signature param present");
        std::string to_sign = "GET&%2F&" + acme::percent_encode_rfc3986(std::string_view(*qs).substr(0, sig_pos));
        std::string hmac_k = "secret-key&";
        auto ctx = crypto::HmacSha1Context::create({reinterpret_cast<std::uint8_t const*>(hmac_k.data()), hmac_k.size()});
        require(ctx && ctx->update({reinterpret_cast<std::uint8_t const*>(to_sign.data()), to_sign.size()}).has_value(), "hmac-sha1");
        auto mac = ctx->snapshot();
        require(mac && std::string_view(*qs).substr(sig_pos + 11) == acme::percent_encode_rfc3986(encoding::encode_base64(*mac)),
            "alidns HMAC-SHA1 signature exact");

        bool ali_added = false, ali_deleted = false;
        acme::AliDns01Provider ali("AKID123", "AKSECRET456");
        auto ali_http = [&](acme::HttpRequest const& req) -> std::expected<acme::HttpResponse, std::string> {
            require(req.url.contains("AccessKeyId=AKID123") && req.url.contains("Signature="), "alidns signed url");
            if (req.url.contains("Action=DescribeDomainInfo") && req.url.contains("DomainName=edge.example.com"))
                return acme::HttpResponse{400, {}, {}, R"({"Code":"InvalidDomainName.NoExist"})"};
            if (req.url.contains("Action=DescribeDomainInfo") && req.url.contains("DomainName=example.com"))
                return acme::HttpResponse{200, {}, {}, R"({"DomainName":"example.com"})"};
            if (req.url.contains("Action=AddDomainRecord")) {
                require(req.url.contains("RR=_acme-challenge.edge") && req.url.contains("Type=TXT") &&
                        req.url.contains("Value=ali-digest-9"), "alidns AddDomainRecord params");
                ali_added = true;
                return acme::HttpResponse{200, {}, {}, R"({"RecordId":"ali-rec-55"})"};
            }
            if (req.url.contains("Action=DeleteDomainRecord") && req.url.contains("RecordId=ali-rec-55")) {
                ali_deleted = true;
                return acme::HttpResponse{200, {}, {}, R"({"RecordId":"ali-rec-55"})"};
            }
            return std::unexpected("unexpected alidns request");
        };
        auto ali_h = ali.publish("edge.example.com", "ali-digest-9", ali_http, "2026-11-26T00:00:00Z", "nonce1");
        require(ali_h && ali_h->zone == "example.com" && ali_h->record_id == "ali-rec-55" && ali_added, "alidns publish");
        require(ali.cleanup(*ali_h, ali_http, "2026-11-26T00:00:01Z", "nonce2").has_value() && ali_deleted, "alidns cleanup");

        // P1-4 regression: AliDNS returning uppercase "Example.COM" for apex & subdomain must normalize safely (no npos underflow),
        // and unrelated/spoofed zone must be rejected.
        auto ali_upper_http = [&](acme::HttpRequest const& req) -> std::expected<acme::HttpResponse, std::string> {
            if (req.url.contains("Action=DescribeDomainInfo"))
                return acme::HttpResponse{200, {}, {}, R"({"DomainName":"Example.COM"})"};
            if (req.url.contains("Action=AddDomainRecord")) {
                require(req.url.contains("DomainName=example.com") && req.url.contains("RR=_acme-challenge&"),
                    "alidns uppercase apex RR exact");
                return acme::HttpResponse{200, {}, {}, R"({"RecordId":"ali-upper-1"})"};
            }
            return std::unexpected("unexpected upper alidns request");
        };
        auto ali_upper = ali.publish("Example.COM", "txt-upper", ali_upper_http, "2026-11-26T00:00:02Z", "nonce3");
        require(ali_upper && ali_upper->zone == "example.com" && ali_upper->record_id == "ali-upper-1", "alidns uppercase apex");

        auto ali_spoof = ali.publish("edge.example.com", "txt-spoof", [](acme::HttpRequest const& req) -> std::expected<acme::HttpResponse, std::string> {
            if (req.url.contains("Action=DescribeDomainInfo"))
                return acme::HttpResponse{200, {}, {}, R"({"DomainName":"evil.org"})"};
            return std::unexpected("should not call AddDomainRecord on spoofed zone");
        }, "2026-11-26T00:00:03Z", "nonce4");
        require(!ali_spoof.has_value(), "alidns spoofed zone rejected");
    }

    auto probe_tls_handshake(io::io_context& ctx, std::uint16_t port, std::string_view sni,
                             fs::path const& ca_file, std::span<std::string_view const> alpn,
                             std::string* negotiated_alpn_out = nullptr) -> bool {
        auto vtime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        auto prof = tls::ClientProfile::load(sni, ca_file.string(), 0x001d, false, alpn);
        if (!prof) return false;
        bool done = false, ok = false;
        auto task = [&]() -> capy::task<> {
            io::tcp_socket sock(ctx);
            if (!sock.open(io::family::v4)) {
                auto [ce] = co_await io::timeout(sock.connect(io::endpoint(io::ipv4_address::loopback(), port)), Clock::now() + 3s);
                if (!ce) {
                    if (auto hs = prof->handshake(now_ms(), now_ms() + 3000, vtime)) {
                        if (auto res = co_await tls::detail::corosio_handshake(sock, *hs)) {
                            if (negotiated_alpn_out && hs->negotiated() && hs->negotiated()->alpn) {
                                auto const& a = *hs->negotiated()->alpn;
                                negotiated_alpn_out->assign(reinterpret_cast<char const*>(a.data()), a.size());
                            }
                            ok = true;
                        }
                    }
                }
            }
            sock.close();
            done = true;
        };
        capy::run_async(ctx.get_executor())(task());
        auto dl = Clock::now() + 4s;
        while (!done && Clock::now() < dl) { ctx.restart(); ctx.run_for(10ms); }
        return ok;
    }

    auto test_acme_atomic_credential_live_swap() -> void {
        auto tmp = make_temp_dir("nexus-w31-acme-live");
        auto cert_a = tmp.path / "a.crt", key_a = tmp.path / "a.key";
        auto cert_b = tmp.path / "b.crt", key_b = tmp.path / "b.key";
        auto uuid_file = tmp.path / "user.uuid";
        make_cert(cert_a, key_a, "alpha.test", "DNS:alpha.test");
        make_cert(cert_b, key_b, "beta.test", "DNS:beta.test");
        write_file(uuid_file, "11111111-2222-3333-4444-555555555555\n", true);

        auto shared_io = relay::make_shared_io_context();
        require(shared_io.has_value(), "shared io");
        auto srv = relay::Server::create_shared(**shared_io);
        require(srv.has_value(), "create server");

        auto acme_cred = std::make_shared<tls::AtomicServerCredential>();
        (*srv)->set_inbound_tls_runtime({std::static_pointer_cast<void>(acme_cred), {"h2", "http/1.1"}, ""});
        std::array<std::string, 1> users{uuid_file.string()}, names{"alice"};
        auto prep = (*srv)->prepare_vless_inbound("", "", users, false, {}, names);
        require(prep.has_value(), prep ? "" : prep.error());
        auto port = (*srv)->start(0, relay::Inbound::vless, 1, false);
        require(port.has_value(), "start vless server");

        std::array<std::string_view, 2> alpn{"h2", "http/1.1"};
        require(!probe_tls_handshake(**shared_io, *port, "alpha.test", cert_a, alpn), "empty acme cred rejects cleanly");
        require((*srv)->healthy(), "server healthy after empty cred");

        auto g1 = acme_cred->update_pem(read_text(cert_a), read_text(key_a));
        require(g1 && *g1 == 1, "acme update gen 1");
        std::string neg;
        require(probe_tls_handshake(**shared_io, *port, "alpha.test", cert_a, alpn, &neg) && neg == "h2", "live cert A + alpn h2");

        auto g2 = acme_cred->update_pem(read_text(cert_b), read_text(key_b));
        require(g2 && *g2 == 2, "acme update gen 2");
        require(!probe_tls_handshake(**shared_io, *port, "alpha.test", cert_a, alpn), "old cert A no longer served");
        require(probe_tls_handshake(**shared_io, *port, "beta.test", cert_b, alpn), "live handshake swapped to cert B");
        (*srv)->stop();
    }

    auto test_static_cert_hot_reload() -> void {
        auto tmp = make_temp_dir("nexus-w31-hotreload");
        auto live_cert = tmp.path / "live.crt", live_key = tmp.path / "live.key";
        auto cert_b = tmp.path / "b.crt", key_b = tmp.path / "b.key";
        auto pass_file = tmp.path / "alice.pass", cert_a_copy = tmp.path / "ca_a.crt";
        make_cert(live_cert, live_key, "static1.test", "DNS:static1.test");
        make_cert(cert_b, key_b, "static2.test", "DNS:static2.test");
        write_file(pass_file, "anytls-secret-pw\n", true);
        write_file(cert_a_copy, read_text(live_cert));

        auto reloader = cli::StaticCertReloader::create(live_cert.string(), live_key.string(), nullptr, 50ms, 50ms);
        require(reloader && (*reloader)->generation() == 1, "reloader initial gen 1");

        auto shared_io = relay::make_shared_io_context();
        require(shared_io.has_value(), "shared io reload");
        auto srv = relay::Server::create_shared(**shared_io);
        require(srv.has_value(), "server reload");
        (*srv)->set_inbound_tls_runtime({(*reloader)->credential_erased(), {"http/1.1"}, ""});
        std::array<std::string, 1> pw{pass_file.string()}, names{"alice"};
        auto prep = (*srv)->prepare_anytls_inbound("", "", pw, names);
        require(prep.has_value(), prep ? "" : prep.error());
        auto port = (*srv)->start(0, relay::Inbound::anytls, 1, false);
        require(port.has_value(), "start anytls server");

        std::array<std::string_view, 1> alpn{"http/1.1"};
        require(probe_tls_handshake(**shared_io, *port, "static1.test", cert_a_copy, alpn), "initial static cert A works");

        write_file(live_cert, read_text(cert_b));
        require(!(*reloader)->check_now(true) && (*reloader)->generation() == 1 && (*reloader)->reload_failures() == 1,
            "mismatched cert/key rejected preserving gen 1");
        require(probe_tls_handshake(**shared_io, *port, "static1.test", cert_a_copy, alpn), "cert A still served after bad reload");

        write_file(live_key, read_text(key_b), true);
        require((*reloader)->check_now(true) && (*reloader)->generation() == 2, "valid cert+key reload bumped to gen 2");
        require(probe_tls_handshake(**shared_io, *port, "static2.test", cert_b, alpn), "live handshake serves cert B");
        (*srv)->stop();
    }

    auto test_kdl_config_parsing() -> void {
        constexpr std::string_view valid_kdl = R"kdl(
schema-version 1
role "server"
services {
    acme directory-url="https://acme.example/dir" email="ops@example.com" challenge="dns-01" state-dir="/tmp/acme-state" {
        domain "edge.example.com"
        dns01-provider "cloudflare"
        dns01-api-token-file "/tmp/cf.token"
        eab-kid "kid-123"
        eab-hmac-file "/tmp/eab.hmac"
    }
}
inbounds {
    inbound "vless-acme" type="vless" {
        listen host="127.0.0.1" port=18443; authentication { user "u1" uuid-file="/tmp/u1.uuid" }
        tls { certificate-provider "acme"; alpn "h2" "http/1.1"; ech-key-file "/tmp/ech.key" }
    }
    inbound "http-reload" type="http" {
        listen host="127.0.0.1" port=18444; authentication "none"; http2 #true
        tls { certificate-file "/tmp/c.pem"; private-key-file "/tmp/k.pem"; cert-hot-reload #true; alpn "h2" }
    }
    inbound "naive-acme" type="naive" {
        listen host="127.0.0.1" port=18445; authentication { user "n1" username="u" password-file="/tmp/p.txt" }
        tls { certificate-provider "acme" }
    }
}
outbounds { outbound "direct" type="direct" }
routing { default-outbound "direct" }
)kdl";
        auto parsed = config::parse_kdl(valid_kdl);
        require(parsed.has_value(), parsed ? "" : parsed.error());
        require(parsed->services.acme && parsed->services.acme->dns01_provider == "cloudflare" &&
                parsed->services.acme->dns01_api_token_file == "/tmp/cf.token" &&
                parsed->services.acme->eab_kid == "kid-123" && parsed->services.acme->eab_hmac_file == "/tmp/eab.hmac",
            "acme dns01/eab fields");
        require(parsed->inbounds.size() == 3 &&
                parsed->inbounds[0].vless->certificate_provider == "acme" &&
                parsed->inbounds[0].vless->ech_key_file == "/tmp/ech.key" && parsed->inbounds[0].vless->alpn.size() == 2 &&
                parsed->inbounds[1].http->cert_hot_reload && parsed->inbounds[1].http->alpn.size() == 1 &&
                parsed->inbounds[2].naive->certificate_provider == "acme" && parsed->inbounds[2].naive->certificate_file.empty(),
            "inbound shared TLS fields");

        constexpr std::string_view alidns_kdl = R"kdl(
schema-version 1
role "server"
services {
    acme directory-url="https://acme.example/dir" email="ops@example.com" challenge="dns-01" state-dir="/tmp/acme-state" dns01-provider="alidns" dns01-access-key-id-file="/tmp/ak.id" dns01-access-key-secret-file="/tmp/ak.sec" {
        domain "*.example.com"
    }
}
inbounds { inbound "s" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none" } }
outbounds { outbound "direct" type="direct" }
routing { default-outbound "direct" }
)kdl";
        auto parsed_ali = config::parse_kdl(alidns_kdl);
        require(parsed_ali && parsed_ali->services.acme && parsed_ali->services.acme->dns01_provider == "alidns" &&
                parsed_ali->services.acme->dns01_access_key_id_file == "/tmp/ak.id" &&
                parsed_ali->services.acme->dns01_access_key_secret_file == "/tmp/ak.sec", "alidns kdl parsed");

        constexpr std::string_view missing_acme = R"kdl(
schema-version 1; role "server"
inbounds { inbound "v" type="vless" { listen host="127.0.0.1" port=18443; authentication { user "u1" uuid-file="/tmp/u1.uuid" }; tls { certificate-provider "acme" } } }
outbounds { outbound "direct" type="direct" }
routing { default-outbound "direct" }
)kdl";
        require(!config::parse_kdl(missing_acme).has_value(), "reject certificate-provider without services.acme");

        constexpr std::string_view conflict = R"kdl(
schema-version 1; role "server"
services { acme directory-url="https://acme.example/dir" email="a@b.c" state-dir="/tmp/acme" { domain "a.example" } }
inbounds { inbound "v" type="vless" { listen host="127.0.0.1" port=18443; authentication { user "u1" uuid-file="/tmp/u1.uuid" }; tls { certificate-provider "acme"; cert-hot-reload #true } } }
outbounds { outbound "direct" type="direct" }
routing { default-outbound "direct" }
)kdl";
        require(!config::parse_kdl(conflict).has_value(), "reject provider + cert-hot-reload conflict");

        constexpr std::string_view bad_cf = R"kdl(
schema-version 1; role "server"
services { acme directory-url="https://acme.example/dir" email="a@b.c" challenge="dns-01" state-dir="/tmp/acme" { domain "a.example"; dns01-provider "cloudflare" } }
inbounds { inbound "s" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none" } }
outbounds { outbound "direct" type="direct" }
routing { default-outbound "direct" }
)kdl";
        require(!config::parse_kdl(bad_cf).has_value(), "reject cloudflare without api-token-file");

        constexpr std::string_view bad_eab = R"kdl(
schema-version 1; role "server"
services { acme directory-url="https://acme.example/dir" email="a@b.c" state-dir="/tmp/acme" { domain "a.example"; eab-kid "kid-only" } }
inbounds { inbound "s" type="socks5" { listen host="127.0.0.1" port=1080; authentication "none" } }
outbounds { outbound "direct" type="direct" }
routing { default-outbound "direct" }
)kdl";
        require(!config::parse_kdl(bad_eab).has_value(), "reject eab-kid without eab-hmac-file");

        // Wave 33A: Hysteria2 / TUIC / MASQUE now accept certificate-provider, cert-hot-reload, and ech-key-file,
        // while custom ALPN on QUIC inbounds, unconfigured certificate-provider, and ech-key-file on H3 inbounds remain rejected.
        constexpr std::array<std::string_view, 2> supported_quic_kdl{{
            R"kdl(schema-version 1; role "server"; services { acme directory-url="https://acme.example/dir" email="a@b.c" state-dir="/tmp/acme" { domain "a.example" } }
inbounds { inbound "h" type="hysteria2" { listen host="127.0.0.1" port=8443; authentication { user "u" password-file="/tmp/p" }; tls { certificate-provider "acme" } } }
outbounds { outbound "direct" type="direct" }; routing { default-outbound "direct" })kdl",
            R"kdl(schema-version 1; role "server"
inbounds { inbound "t" type="tuic" { listen host="127.0.0.1" port=8444; authentication { user "u" uuid-file="/tmp/u" password-file="/tmp/p" }; tls { certificate-file "/tmp/c"; private-key-file "/tmp/k"; cert-hot-reload #true } } }
outbounds { outbound "direct" type="direct" }; routing { default-outbound "direct" })kdl",
        }};
        for (auto doc : supported_quic_kdl)
            require(config::parse_kdl(doc).has_value(), "accept QUIC inbound cert-provider / cert-hot-reload");

        constexpr std::array<std::string_view, 4> unsupported_quic_kdl{{
            R"kdl(schema-version 1; role "server"
inbounds { inbound "h" type="hysteria2" { listen host="127.0.0.1" port=8443; authentication { user "u" password-file="/tmp/p" }; tls { certificate-provider "acme" } } }
outbounds { outbound "direct" type="direct" }; routing { default-outbound "direct" })kdl",
            R"kdl(schema-version 1; role "server"
inbounds { inbound "m" type="masque" { listen host="127.0.0.1" port=8445; authority "m.test"; bearer-file "/tmp/b"; tls { certificate-file "/tmp/c"; private-key-file "/tmp/k"; alpn "h3" } } }
outbounds { outbound "direct" type="direct" }; routing { default-outbound "direct" })kdl",
            R"kdl(schema-version 1; role "server"
inbounds { inbound "n" type="naive" { listen host="127.0.0.1" port=8446; protocol "h3"; authentication { user "u" password-file="/tmp/p" }; tls { certificate-file "/tmp/c"; private-key-file "/tmp/k"; ech-key-file "/tmp/e" } } }
outbounds { outbound "direct" type="direct" }; routing { default-outbound "direct" })kdl",
            R"kdl(schema-version 1; role "server"
inbounds { inbound "h3" type="http" { listen host="127.0.0.1" port=8447; authentication "none"; http3 #true; tls { certificate-file "/tmp/c"; private-key-file "/tmp/k"; ech-key-file "/tmp/e" } } }
outbounds { outbound "direct" type="direct" }; routing { default-outbound "direct" })kdl",
        }};
        for (auto doc : unsupported_quic_kdl)
            require(!config::parse_kdl(doc).has_value(), "reject unsupported QUIC/H3 TLS field");
    }
}

int main() {
    test_eab_and_wildcard_acme();
    test_cloudflare_and_alidns_providers();
    test_acme_atomic_credential_live_swap();
    test_static_cert_hot_reload();
    test_kdl_config_parsing();
    std::println("WAVE 31C ACME DNS-01 / EAB / ATOMIC CREDENTIAL / HOT-RELOAD TESTS PASSED");
    return 0;
}
