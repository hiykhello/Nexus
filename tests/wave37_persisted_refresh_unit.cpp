#include <boost/capy/ex/run_async.hpp>
#include <openssl/asn1.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sys/stat.h>
#include <unistd.h>

import std;
import capy;
import corosio;
import config;
import cli.proxy_dns_reload;
import cli.proxy_providers;
import cli.route_files;
import provider;
import rules;
import rules.rule_input;
import state;
import state.ruleset_storage;
import tls.application_io;
import tls.byte_stream;
import tls.corosio_application;
import tls.corosio_server_handshake;
import tls.profiles;
import tls.server_handshake_io;

namespace {
    int g_failures = 0;
    auto check(bool ok, std::string_view msg) -> void { if (!ok) { ++g_failures; std::cerr << "FAIL: " << msg << '\n'; } }
    struct TempDir {
        std::filesystem::path path;
        explicit TempDir(std::string_view stem) {
            auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
            path = std::filesystem::temp_directory_path() / std::format("{}-{}-{}", stem, ::getpid(), stamp);
            std::filesystem::remove_all(path); std::filesystem::create_directories(path);
        }
        ~TempDir() { std::error_code ec; std::filesystem::remove_all(path, ec); }
    };
    auto write_file(std::filesystem::path const& p, std::string_view data) -> void {
        std::filesystem::create_directories(p.parent_path());
        std::ofstream f(p, std::ios::out | std::ios::binary | std::ios::trunc);
        f.write(data.data(), static_cast<std::streamsize>(data.size()));
    }
    auto sha256_hex(std::string_view data) -> std::string {
        auto digest = state::rule_sha256(data);
        check(bool(digest), "compute sha256");
        static constexpr char kHex[] = "0123456789abcdef";
        std::string out; out.reserve(64);
        if (digest) for (auto b : *digest) { auto v = std::to_integer<unsigned>(b); out.push_back(kHex[v >> 4]); out.push_back(kHex[v & 0x0fu]); }
        return out;
    }
    auto make_loopback_cert(std::filesystem::path const& cert_path, std::filesystem::path const& key_path) -> bool {
        EVP_PKEY* pkey = EVP_PKEY_new();
        EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        X509* x = X509_new();
        bool ok = false;
        if (pkey && ec && x && EC_KEY_generate_key(ec) && EVP_PKEY_assign_EC_KEY(pkey, ec)) {
            ec = nullptr;
            X509_set_version(x, 2); ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
            X509_gmtime_adj(X509_getm_notBefore(x), 0); X509_gmtime_adj(X509_getm_notAfter(x), 86400);
            X509_set_pubkey(x, pkey);
            X509_NAME* sub = X509_get_subject_name(x);
            X509_NAME_add_entry_by_txt(sub, "CN", MBSTRING_ASC, reinterpret_cast<unsigned char const*>("localhost"), 9, -1, 0);
            X509_set_issuer_name(x, sub);
            X509_EXTENSION* ext = X509V3_EXT_nconf_nid(nullptr, nullptr, NID_subject_alt_name, const_cast<char*>("IP:127.0.0.1,DNS:localhost"));
            if (ext && X509_add_ext(x, ext, -1) && X509_sign(x, pkey, EVP_sha256())) {
                FILE *cf = std::fopen(cert_path.c_str(), "wb"), *kf = std::fopen(key_path.c_str(), "wb");
                if (cf && kf && PEM_write_X509(cf, x) && PEM_write_PrivateKey(kf, pkey, nullptr, nullptr, 0, nullptr, nullptr)) ok = true;
                if (cf) std::fclose(cf); if (kf) std::fclose(kf);
            }
            if (ext) X509_EXTENSION_free(ext);
        }
        if (ec) EC_KEY_free(ec); if (x) X509_free(x); if (pkey) EVP_PKEY_free(pkey);
        if (ok) {
            std::error_code sec;
            std::filesystem::permissions(key_path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace, sec);
        }
        return ok;
    }

    constexpr std::string_view kRsBodyA = "schema-version 2\nkind \"predicate\"\nrule type=\"domain\" value=\"a.refresh.test\"\n";
    constexpr std::string_view kRsBodyB = "schema-version 2\nkind \"predicate\"\nrule type=\"domain\" value=\"b.refresh.test\"\n";
    constexpr std::string_view kRsDomainList = "list.refresh.test\n";
    constexpr std::string_view kSubBodyA = "trojan://pw-a@198.51.100.1:443?sni=a.test#node-a\n";
    constexpr std::string_view kSubBodyB = "trojan://pw-b@198.51.100.2:443?sni=b.test#node-b\n";
    constexpr std::string_view kSipBody = R"({"version":1,"servers":[{"remarks":"sip-node","server":"198.51.100.8","server_port":8388,"password":"AAAAAAAAAAAAAAAAAAAAAA==","method":"2022-blake3-aes-128-gcm"}]})";

    struct RefreshHttpsServer {
        ::corosio::io_context ctx;
        ::corosio::tcp_acceptor acc{ctx};
        std::uint16_t port = 0;
        std::optional<tls::ServerCredential> cred;
        std::atomic<bool> stopping{false}, sub_a_corrupt{false}, sub_b_no_etag{false};
        std::atomic<int> rs_a_hits{0}, rs_a_304{0}, rs_b_hits{0}, rs_fmt_hits{0};
        std::atomic<int> sub_a_hits{0}, sub_a_304{0}, sub_b_hits{0}, sip_hits{0};
        std::mutex mu;
        std::string rs_fmt_body{kRsDomainList};
        std::jthread worker;

        auto serve_loop() -> ::capy::task<> {
            auto now_ms = []() noexcept {
                return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count());
            };
            while (!stopping.load(std::memory_order_relaxed)) {
                auto [ec, sock] = co_await acc.accept();
                if (ec) co_return;
                auto hs = tls::make_server_handshake(*cred, now_ms(), now_ms() + 4000);
                if (!hs) continue;
                auto res = co_await tls::detail::server_handshake(sock, *hs);
                if (!res) continue;
                tls::detail::ApplicationConnection<::corosio::tcp_socket> app(sock, std::move(res->records), std::move(res->unread));
                tls::detail::ByteStream<::corosio::tcp_socket> stream(app);
                std::string req;
                std::array<std::uint8_t, 4096> buf{};
                while (!req.contains("\r\n\r\n")) {
                    auto r = co_await stream.read(buf);
                    if (!r || *r == 0) break;
                    req.append(reinterpret_cast<char const*>(buf.data()), *r);
                }
                std::string lreq = req;
                for (auto& c : lreq) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
                auto ok_resp = [](std::string_view etag, std::string_view body) {
                    return etag.empty()
                        ? std::format("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.size(), body)
                        : std::format("HTTP/1.1 200 OK\r\nETag: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", etag, body.size(), body);
                };
                std::string resp;
                if (req.starts_with("GET /rs-a ")) {
                    rs_a_hits.fetch_add(1, std::memory_order_relaxed);
                    if (lreq.contains("if-none-match: \"rs-a\"")) {
                        rs_a_304.fetch_add(1, std::memory_order_relaxed);
                        resp = "HTTP/1.1 304 Not Modified\r\nETag: \"rs-a\"\r\nConnection: close\r\n\r\n";
                    } else resp = ok_resp("\"rs-a\"", kRsBodyA);
                } else if (req.starts_with("GET /rs-b ")) {
                    rs_b_hits.fetch_add(1, std::memory_order_relaxed);
                    resp = ok_resp("\"rs-b\"", kRsBodyB);
                } else if (req.starts_with("GET /rs-fmt ")) {
                    rs_fmt_hits.fetch_add(1, std::memory_order_relaxed);
                    std::string body;
                    { std::lock_guard lk(mu); body = rs_fmt_body; }
                    resp = ok_resp("\"rs-fmt\"", body);
                } else if (req.starts_with("GET /sub-a ")) {
                    sub_a_hits.fetch_add(1, std::memory_order_relaxed);
                    if (sub_a_corrupt.load(std::memory_order_relaxed)) resp = ok_resp("\"bad-200\"", "<html>captive</html>");
                    else if (lreq.contains("if-none-match: \"sub-a\"")) {
                        sub_a_304.fetch_add(1, std::memory_order_relaxed);
                        resp = "HTTP/1.1 304 Not Modified\r\nETag: \"sub-a\"\r\nConnection: close\r\n\r\n";
                    } else resp = ok_resp("\"sub-a\"", kSubBodyA);
                } else if (req.starts_with("GET /sub-b ")) {
                    sub_b_hits.fetch_add(1, std::memory_order_relaxed);
                    resp = ok_resp(sub_b_no_etag.load(std::memory_order_relaxed) ? "" : "\"sub-b\"", kSubBodyB);
                } else if (req.starts_with("GET /sub-sip ")) {
                    sip_hits.fetch_add(1, std::memory_order_relaxed);
                    resp = ok_resp("\"sip-1\"", kSipBody);
                } else resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                (void)co_await stream.send(std::span(reinterpret_cast<std::uint8_t const*>(resp.data()), resp.size()));
                (void)co_await stream.close_output();
            }
        }

        auto start(std::filesystem::path const& cert, std::filesystem::path const& key) -> bool {
            auto c = tls::load_server_credential(cert.string(), key.string());
            if (!c) return false;
            cred = std::move(*c);
            if (acc.open() || acc.bind(::corosio::endpoint(::corosio::ipv4_address::loopback(), 0)) || acc.listen())
                return false;
            port = acc.local_endpoint().port();
            ::capy::run_async(ctx.get_executor())(serve_loop());
            worker = std::jthread([this] { ctx.run_for(std::chrono::seconds(20)); });
            return true;
        }
        auto stop() -> void {
            stopping.store(true, std::memory_order_relaxed);
            ctx.stop();
            if (worker.joinable()) worker.join();
            acc.close();
        }
        ~RefreshHttpsServer() { stop(); }
    };

    auto rewrite_rs_cache(std::filesystem::path const& cache_dir, config::Config const& cfg, std::string_view url,
        state::RuleFormat fmt, std::string_view hc, std::string_view sha, std::string_view body,
        std::string_view etag, std::uint64_t fetched_at) -> void {
        std::string low(sha);
        for (auto& ch : low) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
        auto scope = state::rule_sha256(std::format("v2\n{}\n{}", cli::http_client_signature(cfg, hc), low));
        check(bool(scope), "build managed ruleset scope");
        state::RulesetKey key{std::string(url), fmt, 1};
        if (scope) std::ranges::copy(*scope, key.scope.begin());
        state::RulesetCache cache(cache_dir);
        auto cur = cache.lookup(key);
        check(bool(cur), "lookup ruleset cache before rewrite");
        if (!cur) return;
        state::RulesetMetadata meta{.etag = std::string(etag), .response_target = "/rs-a",
            .fetched_at = fetched_at, .expires_at = fetched_at + 3600};
        auto st = cache.store(key, cur->clear_epoch, std::move(meta), body);
        check(bool(st), "rewrite ruleset cache ok");
    }

    auto remaining_ms(std::optional<std::chrono::steady_clock::time_point> tp) -> std::int64_t {
        return tp ? std::chrono::duration_cast<std::chrono::milliseconds>(*tp - std::chrono::steady_clock::now()).count() : -1;
    }

    auto test_remaining_refresh_math() -> void {
        constexpr std::uint64_t now = 1'750'000'100ull;
        auto fresh = cli::compute_remaining_refresh_ms(now - 10, now, 60'000);
        check(fresh && *fresh == 50'000, "fresh remaining ms exact");
        check(!cli::compute_remaining_refresh_ms(now - 60, now, 60'000).has_value(), "exact boundary expired");
        check(!cli::compute_remaining_refresh_ms(now - 90, now, 60'000).has_value(), "past boundary expired");
        check(!cli::compute_remaining_refresh_ms(0, now, 60'000).has_value(), "missing fetched_at expired");
        check(!cli::compute_remaining_refresh_ms(now - 1, now, 0).has_value(), "zero interval expired");
        check(!cli::compute_remaining_refresh_ms(now + 5, now, 60'000).has_value(), "future clock skew rejected");
        check(!cli::compute_remaining_refresh_ms(1, std::numeric_limits<std::uint64_t>::max(), 60'000).has_value(),
            "overflow elapsed safely rejected");
    }

    auto test_ruleset_cache_scale_over_64(TempDir const& tmp) -> void {
        state::RulesetCacheLimits def{};
        check(def.max_entries == 4096, "default RulesetCacheLimits::max_entries lifted to 4096");
        auto dir = tmp.path / "scale-cache";
        check(state::ensure_private_directory(dir).has_value(), "create private scale cache dir");
        state::RulesetCache cache(dir);
        constexpr std::size_t kCount = 100;
        state::RulesetKey probe{"https://rules.test/set-0.kdl", state::RuleFormat::kdl, 1};
        auto init = cache.lookup(probe);
        check(bool(init), "init scale cache epoch");
        if (!init) return;
        for (std::size_t i = 0; i < kCount; ++i) {
            state::RulesetKey key{std::format("https://rules.test/set-{}.kdl", i), state::RuleFormat::kdl, 1};
            key.scope[0] = static_cast<std::byte>(i & 0xffu);
            auto body = std::format("schema-version 2\nkind \"predicate\"\nrule type=\"domain\" value=\"s{}.test\"\n", i);
            state::RulesetMetadata meta{.etag = std::format("\"e{}\"", i), .response_target = std::format("/set-{}.kdl", i),
                .fetched_at = 1'750'000'000ull + i, .expires_at = 1'750'003'600ull + i};
            check(cache.store(key, init->clear_epoch, std::move(meta), body).has_value(), "store scale entry ok");
        }
        std::size_t hits = 0;
        for (std::size_t i = 0; i < kCount; ++i) {
            state::RulesetKey key{std::format("https://rules.test/set-{}.kdl", i), state::RuleFormat::kdl, 1};
            key.scope[0] = static_cast<std::byte>(i & 0xffu);
            auto lk = cache.lookup(key);
            if (lk && lk->hit && lk->hit->metadata.fetched_at == 1'750'000'000ull + i) ++hits;
        }
        check(hits == kCount, "all 100 (>64) RulesetCache entries retained without eviction");
    }

    auto test_remote_ruleset_persisted_refresh(TempDir const& tmp, RefreshHttpsServer& srv,
        std::filesystem::path const& cert) -> void {
        auto cache_dir = tmp.path / "rs-cache";
        auto cfg_path = (tmp.path / "rs.kdl").string();
        auto make_kdl = [&](std::string_view path, std::string_view fmt, std::uint32_t interval_ms,
            std::string_view sha, std::string_view hc, std::string_view c1_tag) {
            std::string sha_prop = sha.empty() ? std::string{} : std::format(" sha256=\"{}\"", sha);
            return std::format(
                "schema-version 1\nrole \"client\"\nstate {{ cache-directory \"{}\" }}\n"
                "dns {{ servers {{ local \"sys\" }}; final \"sys\"; }}\n"
                "http-clients {{\n"
                "  c1 {{ outbound \"direct\"; domain-resolver \"sys\"; ca-file \"{}\"; protocol \"http/1.1\"; timeout-ms 5000; header \"x-client-tag\" \"{}\"; }}\n"
                "  c2 {{ outbound \"direct\"; domain-resolver \"sys\"; ca-file \"{}\"; protocol \"http/1.1\"; timeout-ms 5000; header \"x-client-tag\" \"c2\"; }}\n"
                "}}\n"
                "inbounds {{ inbound \"s\" type=\"socks5\" {{ listen \"127.0.0.1:1080\"; authentication \"none\"; }} }}\n"
                "outbounds {{ direct; }}\n"
                "routing {{\n"
                "  rulesets {{ rs url=\"https://127.0.0.1:{}{}\" format=\"{}\" http-client=\"{}\" update-interval-ms={}{}; }}\n"
                "  rules sniff-timeout-ms=300 unknown=\"skip\" {{ - rule-set=\"rs\" to=\"direct\"; }}\n"
                "  final \"direct\"\n}}\n",
                cache_dir.string(), cert.string(), c1_tag, cert.string(), srv.port, path, fmt, hc, interval_ms, sha_prop);
        };
        auto cold_start = [&](cli::run_detail::RemoteRulesetManager& mgr, std::string const& kdl, cli::RuleFileInput& in) {
            auto c = config::parse_kdl(kdl);
            check(bool(c), c ? "parse rs kdl" : c.error());
            return c && mgr.fetch_initial(*c, kdl, in).has_value();
        };
        auto hot_reload = [&](cli::run_detail::RemoteRulesetManager& mgr, std::string const& kdl, bool commit = false) {
            auto c = config::parse_kdl(kdl);
            check(bool(c), c ? "parse rs kdl" : c.error());
            cli::RuleFileInput in(cfg_path);
            if (!c) return false;
            auto st = mgr.prepare_reload(*c, kdl, in);
            if (st && commit) mgr.commit_reload(std::move(*st));
            return st.has_value();
        };
        std::string const url_a = std::format("https://127.0.0.1:{}/rs-a", srv.port);

        auto k1 = make_kdl("/rs-a", "kdl", 3'600'000, "", "c1", "v1");
        auto c1 = config::parse_kdl(k1);
        if (!c1) { check(false, c1.error()); return; }
        cli::run_detail::RemoteRulesetManager m1, m2, m_part, m_exp, m_skew, m_bad, m_sha, m_c2, m_b, m_fmt, m_fmt_r;
        cli::RuleFileInput in1(cfg_path), in2(cfg_path), in_part(cfg_path), in_tmp(cfg_path);

        // 1-2. Cold start fetches once; cold restart within interval makes 0 upstream HTTP requests!
        check(cold_start(m1, k1, in1) && srv.rs_a_hits.load() == 1, "RS initial cold start fetched once");
        auto r1 = remaining_ms(m1.next_refresh_for(url_a));
        check(r1 > 0 && r1 <= 3'600'000, "RS initial next_refresh within (0, interval]");
        check(cold_start(m2, k1, in2) && srv.rs_a_hits.load() == 1, "RS fresh cold restart made 0 upstream HTTP requests");
        auto b2 = in2.read(url_a);
        check(b2 && *b2 == kRsBodyA, "RS fresh cold restart seeded cached body");
        auto r2 = remaining_ms(m2.next_refresh_for(url_a));
        check(r2 > 0 && r2 <= 3'600'000, "RS cold restart next_refresh equals remaining cooldown");

        // 3. Partial cooldown (fetched_at = now - 30): restart with 120s skips network (rem <= 90s);
        //    hot reload unchanged/lengthened -> 0 fetches; shortened below elapsed -> immediate fetch!
        auto now_u = cli::current_unix_seconds();
        rewrite_rs_cache(cache_dir, *c1, url_a, state::RuleFormat::kdl, "c1", "", kRsBodyA, "\"rs-a\"", now_u - 30);
        auto k_120 = make_kdl("/rs-a", "kdl", 120'000, "", "c1", "v1");
        check(cold_start(m_part, k_120, in_part) && srv.rs_a_hits.load() == 1, "RS partial cooldown restart 0 requests");
        auto nr_part = m_part.next_refresh_for(url_a);
        auto rp = remaining_ms(nr_part);
        check(rp > 0 && rp <= 91'000, "RS partial cooldown remaining <= 90s");
        check(hot_reload(m_part, k_120) && srv.rs_a_hits.load() == 1, "RS hot reload unchanged 0 requests");
        check(hot_reload(m_part, make_kdl("/rs-a", "kdl", 240'000, "", "c1", "v1"), true) && srv.rs_a_hits.load() == 1,
            "RS hot reload lengthened 0 requests");
        auto nr_240 = m_part.next_refresh_for(url_a);
        check(nr_240 && nr_part && *nr_240 > *nr_part + std::chrono::seconds(60), "RS hot reload lengthened next_refresh");
        check(hot_reload(m_part, make_kdl("/rs-a", "kdl", 15'000, "", "c1", "v1")) &&
            srv.rs_a_hits.load() == 2 && srv.rs_a_304.load() == 1, "RS hot reload shortened interval triggers refetch");

        // 4. Expired restart, future clock skew, and corrupt cached blob each trigger immediate HTTP fetch.
        rewrite_rs_cache(cache_dir, *c1, url_a, state::RuleFormat::kdl, "c1", "", kRsBodyA, "\"rs-a\"", now_u - 120);
        check(cold_start(m_exp, make_kdl("/rs-a", "kdl", 60'000, "", "c1", "v1"), in_tmp) && srv.rs_a_hits.load() == 3,
            "RS expired cold restart triggers immediate HTTP fetch");
        rewrite_rs_cache(cache_dir, *c1, url_a, state::RuleFormat::kdl, "c1", "", kRsBodyA, "\"rs-a\"", now_u + 300);
        check(cold_start(m_skew, k1, in_tmp) && srv.rs_a_hits.load() == 4, "RS future clock skew triggers refetch");
        rewrite_rs_cache(cache_dir, *c1, url_a, state::RuleFormat::kdl, "c1", "", "corrupt{{{", "\"bad\"", now_u);
        check(cold_start(m_bad, k1, in_tmp) && srv.rs_a_hits.load() == 5, "RS corrupt blob triggers refetch");

        // 5. Config changes on cold restart & hot reload: sha256, http-client (name & def), url, format.
        auto k_sha = make_kdl("/rs-a", "kdl", 3'600'000, sha256_hex(kRsBodyA), "c1", "v1");
        check(cold_start(m_sha, k_sha, in_tmp) && srv.rs_a_hits.load() == 6, "RS sha256 change on restart triggers refetch");
        check(hot_reload(m_bad, k_sha) && srv.rs_a_hits.load() == 7, "RS sha256 change on hot reload triggers refetch");

        check(cold_start(m_c2, make_kdl("/rs-a", "kdl", 3'600'000, "", "c2", "v1"), in_tmp) && srv.rs_a_hits.load() == 8,
            "RS http-client change on restart triggers refetch");
        check(hot_reload(m_bad, make_kdl("/rs-a", "kdl", 3'600'000, "", "c1", "v2")) && srv.rs_a_hits.load() == 9,
            "RS http-client header change on hot reload triggers refetch");

        auto k_b = make_kdl("/rs-b", "kdl", 3'600'000, "", "c1", "v1");
        check(cold_start(m_b, k_b, in_tmp) && srv.rs_b_hits.load() == 1, "RS url change on restart triggers refetch");
        check(hot_reload(m_bad, k_b) && srv.rs_b_hits.load() == 2, "RS url change on hot reload triggers refetch");

        check(cold_start(m_fmt, make_kdl("/rs-fmt", "domain-list", 3'600'000, "", "c1", "v1"), in_tmp) && srv.rs_fmt_hits.load() == 1,
            "RS initial domain-list fetch ok");
        { std::lock_guard lk(srv.mu); srv.rs_fmt_body = std::string(kRsBodyA); }
        auto k_fmt2 = make_kdl("/rs-fmt", "kdl", 3'600'000, "", "c1", "v1");
        check(cold_start(m_fmt_r, k_fmt2, in_tmp) && srv.rs_fmt_hits.load() == 2, "RS format change on restart triggers refetch");
        check(hot_reload(m_fmt, k_fmt2) && srv.rs_fmt_hits.load() == 3, "RS format change on hot reload triggers refetch");
    }

    auto test_http_provider_persisted_refresh(TempDir const& tmp, RefreshHttpsServer& srv,
        std::filesystem::path const& cert) -> void {
        auto cache_dir = tmp.path / "prov-cache";
        auto cfg_path = (tmp.path / "prov.kdl").string();
        auto make_kdl = [&](std::string_view path, std::string_view fmt, std::uint32_t interval_ms,
            std::string_view hc, std::string_view c1_tag) {
            return std::format(
                "schema-version 1\nrole \"client\"\ncertificate {{ ca-file \"{}\" }}\nstate {{ cache-directory \"{}\" }}\n"
                "dns {{ servers {{ local \"sys\" }}; final \"sys\"; }}\n"
                "http-clients {{\n"
                "  c1 {{ outbound \"direct\"; domain-resolver \"sys\"; ca-file \"{}\"; protocol \"http/1.1\"; timeout-ms 5000; header \"x-client-tag\" \"{}\"; }}\n"
                "  c2 {{ outbound \"direct\"; domain-resolver \"sys\"; ca-file \"{}\"; protocol \"http/1.1\"; timeout-ms 5000; header \"x-client-tag\" \"c2\"; }}\n"
                "}}\n"
                "proxy-providers {{ http \"p\" {{ url \"https://127.0.0.1:{}{}\"; http-client \"{}\"; format \"{}\"; update-interval-ms {}; cache-dir \"{}\"; }} }}\n"
                "inbounds {{ inbound \"s\" type=\"socks5\" {{ listen \"127.0.0.1:1080\"; authentication \"none\"; }} }}\n"
                "outbounds {{ direct; selector \"auto\" {{ use \"p\"; }}; }}\nrouting {{ final \"auto\"; }}\n",
                cert.string(), cache_dir.string(), cert.string(), c1_tag, cert.string(), srv.port, path, hc, fmt, interval_ms, cache_dir.string());
        };
        std::string const url_a = std::format("https://127.0.0.1:{}/sub-a", srv.port);
        auto k1 = make_kdl("/sub-a", "uri", 3'600'000, "c1", "v1");

        // 1-2. Cold start fetches once & writes 0600 .meta; cold restart within interval makes 0 HTTP requests.
        cli::ProxyProviderManager m1, m2, m_part, m_short_cold, m_skew, m_bad, m_fmt, m_c2, m_b;
        auto e1 = m1.prepare_initial(k1, cfg_path, true);
        check(bool(e1) && e1->contains("198.51.100.1") && srv.sub_a_hits.load() == 1, "Provider initial cold start fetched once");
        auto meta_path = cli::provider_cache_meta_path(cache_dir, "p", url_a);
        struct stat mst{};
        check(::stat(meta_path.c_str(), &mst) == 0 && (mst.st_mode & 0777) == 0600, "Provider .meta written with 0600 mode");

        auto e2 = m2.prepare_initial(k1, cfg_path, true);
        check(bool(e2) && e2->contains("198.51.100.1") && srv.sub_a_hits.load() == 1, "Provider fresh cold restart 0 requests");
        auto r2 = remaining_ms(m2.next_refresh_for("p"));
        check(r2 > 0 && r2 <= 3'600'000, "Provider fresh cold restart next_refresh within (0, interval]");

        // 3. Explicit manual sync_once ALWAYS fetches ignoring cooldown.
        auto synced = m2.sync_once(false);
        check(bool(synced) && !*synced && srv.sub_a_hits.load() == 2 && srv.sub_a_304.load() == 1,
            "Provider sync_once ignores cooldown and revalidates with 304");

        // 4. Partial cooldown (fetched_at = now - 30): restart 120s skips network; hot reload 240s skips & adjusts next_refresh;
        //    shortened interval 15s refetches immediately on BOTH hot reload and cold restart.
        auto cached = cli::read_provider_cache(cache_dir, "p", url_a);
        check(bool(cached) && !cached->http_client_sig.empty(), "Provider cache meta populated");
        auto now_u = cli::current_unix_seconds();
        auto rewrite_meta = [&](std::uint64_t ts) {
            auto r = *cached;
            r.fetched_at = ts;
            check(cli::write_provider_cache(cache_dir, "p", url_a, r).has_value(), "rewrite provider cache meta");
        };
        rewrite_meta(now_u - 30);
        auto k_120 = make_kdl("/sub-a", "uri", 120'000, "c1", "v1");
        check(m_part.prepare_initial(k_120, cfg_path, true).has_value() && srv.sub_a_hits.load() == 2,
            "Provider partial cooldown restart 0 requests");
        auto nr_part = m_part.next_refresh_for("p");
        auto rp = remaining_ms(nr_part);
        check(rp > 0 && rp <= 91'000, "Provider partial cooldown remaining <= 90s");
        check(m_part.prepare_candidate(k_120, cfg_path, true).has_value() && srv.sub_a_hits.load() == 2,
            "Provider hot reload unchanged 0 requests");
        auto s_240 = m_part.prepare_candidate(make_kdl("/sub-a", "uri", 240'000, "c1", "v1"), cfg_path, true);
        check(bool(s_240) && srv.sub_a_hits.load() == 2, "Provider hot reload lengthened 0 requests");
        if (s_240) m_part.commit_candidate(std::move(*s_240));
        auto nr_240 = m_part.next_refresh_for("p");
        check(nr_240 && nr_part && *nr_240 > *nr_part + std::chrono::seconds(60), "Provider hot reload lengthened next_refresh");
        auto k_short = make_kdl("/sub-a", "uri", 15'000, "c1", "v1");
        check(m_part.prepare_candidate(k_short, cfg_path, true).has_value() && srv.sub_a_hits.load() == 3,
            "Provider hot reload shortened interval triggers immediate refetch");
        rewrite_meta(now_u - 30);
        check(m_short_cold.prepare_initial(k_short, cfg_path, true).has_value() && srv.sub_a_hits.load() == 4,
            "Provider cold restart shortened interval triggers immediate refetch");

        // 5. Clock skew & corrupt .sub each trigger immediate refetch (and self-heal corrupt .sub).
        rewrite_meta(now_u + 300);
        check(m_skew.prepare_initial(k1, cfg_path, true).has_value() && srv.sub_a_hits.load() == 5,
            "Provider future clock skew triggers refetch");
        auto [sub_p, etag_p, ui_p] = cli::provider_cache_paths(cache_dir, "p", url_a);
        (void)etag_p; (void)ui_p;
        write_file(sub_p, ":::not-a-valid-subscription:::");
        auto e_bad = m_bad.prepare_initial(k1, cfg_path, true);
        check(bool(e_bad) && e_bad->contains("198.51.100.1") && srv.sub_a_hits.load() == 6,
            "Provider corrupt .sub triggers unconditional refetch and self-heals");

        // 6. Config changes on cold restart & hot reload: format, http-client (name & def), url.
        auto k_auto = make_kdl("/sub-a", "auto", 3'600'000, "c1", "v1");
        check(m_fmt.prepare_initial(k_auto, cfg_path, true).has_value() && srv.sub_a_hits.load() == 7,
            "Provider format change on restart triggers refetch");
        check(m_bad.prepare_candidate(k_auto, cfg_path, true).has_value() && srv.sub_a_hits.load() == 8,
            "Provider format change on hot reload triggers refetch");
        check(m_c2.prepare_initial(make_kdl("/sub-a", "auto", 3'600'000, "c2", "v1"), cfg_path, true).has_value() &&
            srv.sub_a_hits.load() == 9, "Provider http-client change on restart triggers refetch");
        check(m_bad.prepare_candidate(make_kdl("/sub-a", "uri", 3'600'000, "c1", "v2"), cfg_path, true).has_value() &&
            srv.sub_a_hits.load() == 10, "Provider http-client header change on hot reload triggers refetch");

        auto k_b = make_kdl("/sub-b", "uri", 3'600'000, "c1", "v1");
        auto eb = m_b.prepare_initial(k_b, cfg_path, true);
        check(bool(eb) && eb->contains("198.51.100.2") && srv.sub_b_hits.load() == 1, "Provider url change on restart refetches");
        auto eb_hr = m_bad.prepare_candidate(k_b, cfg_path, true);
        check(bool(eb_hr) && eb_hr->expanded_kdl.contains("198.51.100.2") && srv.sub_b_hits.load() == 2,
            "Provider url change on hot reload refetches");

        // 7. P1-1 & P1-2: sip008 cold-restart skip, truncated .meta fail-closed, malformed 200 cache preservation, ETag-less 200.
        auto k_sip = make_kdl("/sub-sip", "sip008", 3'600'000, "c1", "v1");
        cli::ProxyProviderManager m_sip1, m_sip2, m_trunc;
        check(m_sip1.prepare_initial(k_sip, cfg_path, true).has_value() && srv.sip_hits.load() == 1, "Provider sip008 initial ok");
        check(m_sip2.prepare_initial(k_sip, cfg_path, true).has_value() && srv.sip_hits.load() == 1 &&
            remaining_ms(m_sip2.next_refresh_for("p")) > 0, "Provider sip008 cold restart skips network");
        write_file(meta_path, std::format("fetched_at={}\nclient={}\n", now_u, cached->http_client_sig));
        check(!cli::read_provider_cache(cache_dir, "p", url_a)->fetched_at &&
            m_trunc.prepare_initial(k_auto, cfg_path, true).has_value() && srv.sub_a_hits.load() == 11,
            "Provider truncated .meta fails closed for auto format");
        srv.sub_a_corrupt.store(true, std::memory_order_relaxed);
        check(!m_trunc.sync_once(false).has_value(), "Provider malformed 200 OK rejected");
        srv.sub_a_corrupt.store(false, std::memory_order_relaxed);
        auto kept = cli::read_provider_cache(cache_dir, "p", url_a);
        check(kept && kept->body == kSubBodyA && kept->etag == "\"sub-a\"", "Provider malformed 200 preserves valid disk cache");
        srv.sub_b_no_etag.store(true, std::memory_order_relaxed);
        check(m_b.sync_once(false).has_value(), "Provider ETag-less 200 OK succeeds");
        auto b_cached = cli::read_provider_cache(cache_dir, "p", std::format("https://127.0.0.1:{}/sub-b", srv.port));
        check(b_cached && b_cached->etag.empty(), "Provider ETag-less 200 clears stale ETag");
    }
}

auto main() -> int {
    TempDir tmp("nexus-w37-refresh");
    test_remaining_refresh_math();
    test_ruleset_cache_scale_over_64(tmp);
    auto cert = tmp.path / "srv.pem", key = tmp.path / "srv.key";
    check(make_loopback_cert(cert, key), "generate loopback cert");
    RefreshHttpsServer srv;
    check(srv.start(cert, key), "start loopback HTTPS refresh server");
    if (srv.port != 0) {
        test_remote_ruleset_persisted_refresh(tmp, srv, cert);
        test_http_provider_persisted_refresh(tmp, srv, cert);
    }
    srv.stop();
    if (g_failures != 0) { std::cerr << g_failures << " failure(s)\n"; return 1; }
    std::println("PASS wave37_persisted_refresh_unit");
    return 0;
}
