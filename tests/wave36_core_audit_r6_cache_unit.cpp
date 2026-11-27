#include <boost/capy/ex/run_async.hpp>
#include <openssl/asn1.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <unistd.h>
#include <zlib.h>

import std;
import capy;
import corosio;
import config;
import cli.proxy_dns_reload;
import cli.proxy_providers;
import cli.route_files;
import cli.route_files_nxmm;
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

auto nexus_state(int argc, char** argv) -> int;
auto nexus_rule_fetch(int argc, char** argv) -> int;

namespace {
    int g_failures = 0;
    auto check(bool ok, std::string_view msg) -> void {
        if (!ok) { ++g_failures; std::cerr << "FAIL: " << msg << '\n'; }
    }

    struct TempDir {
        std::filesystem::path path;
        explicit TempDir(std::string_view stem) {
            auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
            path = std::filesystem::temp_directory_path() / std::format("{}-{}-{}", stem, ::getpid(), stamp);
            std::filesystem::remove_all(path);
            std::filesystem::create_directories(path);
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
        std::string out;
        out.reserve(64);
        if (digest) for (auto b : *digest) {
            auto v = std::to_integer<unsigned>(b);
            out.push_back(kHex[v >> 4]); out.push_back(kHex[v & 0x0fu]);
        }
        return out;
    }

    auto make_loopback_cert(std::filesystem::path const& cert_path, std::filesystem::path const& key_path) -> bool {
        EVP_PKEY* pkey = EVP_PKEY_new();
        EC_KEY* ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        X509* x = X509_new();
        bool ok = false;
        if (pkey && ec && x && EC_KEY_generate_key(ec) && EVP_PKEY_assign_EC_KEY(pkey, ec)) {
            ec = nullptr;
            X509_set_version(x, 2);
            ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
            X509_gmtime_adj(X509_getm_notBefore(x), 0);
            X509_gmtime_adj(X509_getm_notAfter(x), 86400);
            X509_set_pubkey(x, pkey);
            X509_NAME* sub = X509_get_subject_name(x);
            X509_NAME_add_entry_by_txt(sub, "CN", MBSTRING_ASC, reinterpret_cast<unsigned char const*>("localhost"), 9, -1, 0);
            X509_set_issuer_name(x, sub);
            X509_EXTENSION* ext = X509V3_EXT_nconf_nid(nullptr, nullptr, NID_subject_alt_name,
                const_cast<char*>("IP:127.0.0.1,DNS:localhost"));
            if (ext && X509_add_ext(x, ext, -1) && X509_sign(x, pkey, EVP_sha256())) {
                FILE* cf = std::fopen(cert_path.c_str(), "wb");
                FILE* kf = std::fopen(key_path.c_str(), "wb");
                if (cf && kf && PEM_write_X509(cf, x) && PEM_write_PrivateKey(kf, pkey, nullptr, nullptr, 0, nullptr, nullptr))
                    ok = true;
                if (cf) std::fclose(cf);
                if (kf) std::fclose(kf);
            }
            if (ext) X509_EXTENSION_free(ext);
        }
        if (ec) EC_KEY_free(ec);
        if (x) X509_free(x);
        if (pkey) EVP_PKEY_free(pkey);
        if (ok) {
            std::error_code sec;
            std::filesystem::permissions(key_path,
                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace, sec);
        }
        return ok;
    }

    struct ProviderHttpsServer {
        ::corosio::io_context ctx;
        ::corosio::tcp_acceptor acc{ctx};
        std::uint16_t port = 0;
        std::optional<tls::ServerCredential> cred;
        std::string body_a, body_b;
        std::atomic<bool> stopping{false};
        std::atomic<int> req_b_count{0}, req_b_had_inm{0}, req_c_count{0};
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
                tls::detail::ApplicationConnection<::corosio::tcp_socket> app(
                    sock, std::move(res->records), std::move(res->unread));
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
                bool has_inm = lreq.contains("if-none-match:");
                std::string resp;
                if (req.starts_with("GET /sub-a ")) {
                    resp = lreq.contains("if-none-match: \"etag-a\"")
                        ? "HTTP/1.1 304 Not Modified\r\nETag: \"etag-a\"\r\nConnection: close\r\n\r\n"
                        : std::format("HTTP/1.1 200 OK\r\nETag: \"etag-a\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body_a.size(), body_a);
                } else if (req.starts_with("GET /sub-b ")) {
                    req_b_count.fetch_add(1, std::memory_order_relaxed);
                    if (has_inm) {
                        req_b_had_inm.fetch_add(1, std::memory_order_relaxed);
                        resp = "HTTP/1.1 304 Not Modified\r\nETag: \"etag-a\"\r\nConnection: close\r\n\r\n";
                    } else {
                        resp = std::format("HTTP/1.1 200 OK\r\nETag: \"etag-b\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body_b.size(), body_b);
                    }
                } else if (req.starts_with("GET /sub-c ")) {
                    req_c_count.fetch_add(1, std::memory_order_relaxed);
                    resp = "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n";
                } else {
                    resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                }
                (void)co_await stream.send(std::span(
                    reinterpret_cast<std::uint8_t const*>(resp.data()), resp.size()));
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
            worker = std::jthread([this] { ctx.run_for(std::chrono::seconds(10)); });
            return true;
        }
        auto stop() -> void {
            stopping.store(true, std::memory_order_relaxed);
            ctx.stop();
            if (worker.joinable()) worker.join();
            acc.close();
        }
        ~ProviderHttpsServer() { stop(); }
    };

    auto push_varint(std::vector<std::uint8_t>& out, std::uint64_t v) -> void {
        while (v >= 0x80u) { out.push_back(static_cast<std::uint8_t>((v & 0x7fu) | 0x80u)); v >>= 7; }
        out.push_back(static_cast<std::uint8_t>(v));
    }
    auto push_u64_be(std::vector<std::uint8_t>& out, std::uint64_t v) -> void {
        for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<std::uint8_t>((v >> shift) & 0xffu));
    }
    auto make_srs_with_domains(std::string_view tag, unsigned count) -> std::string {
        std::vector<std::string> keys;
        keys.reserve(count);
        for (unsigned i = 0; i < count; ++i) keys.push_back(std::format("\ndom-{}-{}.r6cache.test", tag, i));
        for (auto& k : keys) std::ranges::reverse(k);
        std::ranges::sort(keys);
        keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
        struct Node { std::vector<std::pair<std::uint8_t, std::size_t>> edges; bool leaf = false; };
        std::vector<Node> trie(1);
        for (auto const& key : keys) {
            std::size_t cur = 0;
            for (unsigned char c : key) {
                auto it = std::ranges::find(trie[cur].edges, c, &std::pair<std::uint8_t, std::size_t>::first);
                if (it == trie[cur].edges.end()) {
                    std::size_t nxt = trie.size(); trie.emplace_back();
                    trie[cur].edges.emplace_back(c, nxt); cur = nxt;
                } else cur = it->second;
            }
            trie[cur].leaf = true;
        }
        std::vector<std::size_t> order{0};
        std::vector<std::uint8_t> labels;
        std::vector<bool> bitmap_bits, leaf_bits;
        for (std::size_t qi = 0; qi < order.size(); ++qi) {
            auto const& node = trie[order[qi]];
            leaf_bits.push_back(node.leaf);
            for (auto [lbl, child] : node.edges) { labels.push_back(lbl); bitmap_bits.push_back(false); order.push_back(child); }
            bitmap_bits.push_back(true);
        }
        auto pack = [](std::vector<bool> const& bits) {
            std::vector<std::uint64_t> words((bits.size() + 63) / 64, 0);
            for (std::size_t i = 0; i < bits.size(); ++i) if (bits[i]) words[i / 64] |= (std::uint64_t{1} << (i % 64));
            return words;
        };
        std::vector<std::uint8_t> payload;
        push_varint(payload, 1);
        payload.push_back(0); payload.push_back(2); payload.push_back(0);
        auto lw = pack(leaf_bits), bw = pack(bitmap_bits);
        push_varint(payload, lw.size()); for (auto w : lw) push_u64_be(payload, w);
        push_varint(payload, bw.size()); for (auto w : bw) push_u64_be(payload, w);
        push_varint(payload, labels.size()); payload.insert(payload.end(), labels.begin(), labels.end());
        payload.push_back(255); payload.push_back(0);

        uLongf bound = compressBound(static_cast<uLong>(payload.size()));
        std::string out(4 + bound, '\0');
        out[0] = 'S'; out[1] = 'R'; out[2] = 'S'; out[3] = 3;
        uLongf out_len = bound;
        check(compress2(reinterpret_cast<Bytef*>(out.data() + 4), &out_len,
            reinterpret_cast<Bytef const*>(payload.data()), static_cast<uLong>(payload.size()), Z_BEST_COMPRESSION) == Z_OK,
            "zlib compress2 SRS");
        out.resize(4 + out_len);
        return out;
    }

    auto test_r6_p1_1_provider_cache_url_identity(TempDir const& tmp) -> void {
        auto cache_root = tmp.path / "prov-cache";
        cli::ManagedProviderFetchResult res_a{"body-a", "\"etag-a\"", std::nullopt, false};
        check(cli::write_provider_cache(cache_root, "shared", "https://EXAMPLE.TEST:443/sub-a", res_a).has_value(),
            "R6 P1-1 write_provider_cache for /sub-a");
        auto hit = cli::read_provider_cache(cache_root, "shared", "https://example.test/sub-a");
        check(hit && hit->body == "body-a" && hit->etag == "\"etag-a\"", "R6 P1-1 canonical URL hits cache");
        check(!cli::read_provider_cache(cache_root, "shared", "https://example.test/sub-b").has_value(),
            "R6 P1-1 different path misses cache");
        check(!cli::read_provider_cache(cache_root, "shared", "https://other.test/sub-a").has_value(),
            "R6 P1-1 different host misses cache");
        write_file(cache_root / "providers" / "shared.sub", "legacy-body");
        write_file(cache_root / "providers" / "shared.etag", "\"legacy-etag\"");
        check(!cli::read_provider_cache(cache_root, "shared", "https://example.test/sub-legacy").has_value(),
            "R6 P1-1 legacy name-only cache files ignored");

        auto cert = tmp.path / "srv.pem", key = tmp.path / "srv.key";
        check(make_loopback_cert(cert, key), "generate loopback cert");
        ProviderHttpsServer srv;
        srv.body_a = "proxies:\n  - {name: node-a, type: trojan, server: 198.51.100.1, port: 443, password: pw-a, sni: a.test}\n";
        srv.body_b = "proxies:\n  - {name: node-b, type: trojan, server: 198.51.100.2, port: 443, password: pw-b, sni: b.test}\n";
        check(srv.start(cert, key), "start loopback HTTPS provider server");
        auto live_cache = tmp.path / "live-prov-cache";
        auto make_cfg = [&](std::string_view url_path, std::uint16_t port) {
            return std::format(R"kdl(
schema-version 1
role "client"
certificate {{ ca-file "{}" }}
state {{ cache-directory "{}" }}
dns {{ servers {{ local "sys" }}; final "sys"; }}
http-clients {{ c1 {{ outbound "direct"; domain-resolver "sys"; ca-file "{}"; protocol "http/1.1"; timeout-ms 5000; }} }}
proxy-providers {{
    http "shared" {{ url "https://127.0.0.1:{}{}"; http-client "c1"; format "clash"; cache-dir "{}"; }}
}}
inbounds {{ inbound "s" type="socks5" {{ listen "127.0.0.1:1080"; authentication "none"; }} }}
outbounds {{ direct; selector "auto" {{ use "shared"; }}; }}
routing {{ final "auto"; }}
)kdl", cert.string(), live_cache.string(), cert.string(), port, url_path, live_cache.string());
        };
        auto cfg_path = (tmp.path / "prov.kdl").string();
        cli::ProxyProviderManager mgr1;
        auto exp_a = mgr1.prepare_initial(make_cfg("/sub-a", srv.port), cfg_path, true);
        check(bool(exp_a), exp_a ? "R6 P1-1 initial /sub-a ok" : exp_a.error());
        if (exp_a) check(exp_a->contains("198.51.100.1"), "R6 P1-1 /sub-a yields node-a");

        cli::ProxyProviderManager mgr2;
        auto exp_b = mgr2.prepare_initial(make_cfg("/sub-b", srv.port), cfg_path, true);
        check(bool(exp_b), exp_b ? "R6 P1-1 switched /sub-b ok" : exp_b.error());
        check(srv.req_b_count.load() == 1 && srv.req_b_had_inm.load() == 0,
            "R6 P1-1 /sub-b received zero If-None-Match from /sub-a");
        if (exp_b) check(exp_b->contains("198.51.100.2") && !exp_b->contains("198.51.100.1"),
            "R6 P1-1 /sub-b serves node-b and never leaks node-a");

        cli::ProxyProviderManager mgr3;
        auto exp_c = mgr3.prepare_initial(make_cfg("/sub-c", srv.port), cfg_path, true);
        check(!exp_c && srv.req_c_count.load() == 1, "R6 P1-1 unprompted 304 rejected");

        srv.stop();
        cli::ProxyProviderManager mgr4;
        auto exp_offline = mgr4.prepare_initial(make_cfg("/sub-offline", srv.port), cfg_path, true);
        check(!exp_offline, "R6 P1-1 unreachable new URL never reuses old URL offline cache");
    }

    auto test_r6_p1_2_remote_ruleset_sha256() -> void {
        std::string h1(64, 'a'), h2(64, 'b'), h1_upper(64, 'A');
        auto build_kdl = [](std::string_view r1_extra, std::string_view r2_url, std::string_view r2_extra, bool in_dns) {
            std::string dns_rs = in_dns
                ? std::format("rulesets {{ d1 url=\"{}\" format=\"kdl\" http-client=\"c1\"{}; }}\n    rules {{ - rule-set=\"d1\" server=\"sys\"; }}", r2_url, r2_extra)
                : std::string{};
            std::string route_rs2 = !in_dns
                ? std::format("        r2 url=\"{}\" format=\"kdl\" http-client=\"c1\"{}", r2_url, r2_extra)
                : std::string{};
            std::string route_rule2 = !in_dns ? "- rule-set=\"r2\" to=\"direct\";" : "";
            return std::format(R"kdl(
schema-version 1
role "client"
inbounds {{ inbound "s" type="socks5" {{ listen "127.0.0.1:1080"; authentication "none"; }} }}
outbounds {{ direct; }}
dns {{
    servers {{ local "sys"; }}
    {}
    final "sys"
}}
http-clients {{ c1 {{ outbound "direct"; domain-resolver "sys"; ca-file "/tmp/ca.pem"; }} }}
routing {{
    rulesets {{
        r1 url="https://rules.test/shared.kdl" format="kdl" http-client="c1"{}
{}
    }}
    rules sniff-timeout-ms=300 unknown="skip" {{ - rule-set="r1" to="direct"; {} }}
    final "direct"
}}
)kdl", dns_rs, r1_extra, route_rs2, route_rule2);
        };
        auto c1 = config::parse_kdl(build_kdl("", "https://rules.test/shared.kdl", " sha256=\"" + h1 + "\"", true));
        check(!c1 && c1.error().contains("conflicting sha256"), "R6 P1-2 rejects unpinned route + pinned DNS same URL");
        auto c2 = config::parse_kdl(build_kdl(" sha256=\"" + h1 + "\"", "https://rules.test/shared.kdl", " sha256=\"" + h2 + "\"", false));
        check(!c2 && c2.error().contains("conflicting sha256"), "R6 P1-2 rejects differing sha256 on same URL");
        auto c3 = config::parse_kdl(build_kdl(" sha256=\"" + h1 + "\"", "https://RULES.TEST:443/shared.kdl", "", true));
        check(!c3 && c3.error().contains("conflicting sha256"), "R6 P1-2 normalizes URL host/port for sha256 conflict");
        auto c4 = config::parse_kdl(build_kdl(" sha256=\"" + h1 + "\"", "https://rules.test/shared.kdl", " sha256=\"" + h1_upper + "\"", true));
        check(bool(c4), c4 ? "R6 P1-2 identical sha256 case-insensitive ok" : c4.error());

        std::string const body = "schema-version 2\nkind \"predicate\"\nrule type=\"domain\" value=\"a.test\"\n";
        std::string const good_sha = sha256_hex(body), bad_sha(64, 'f');
        auto base = config::parse_kdl(build_kdl("", "https://rules.test/other.kdl", "", true));
        check(bool(base), base ? "base remote config ok" : base.error());
        if (!base) return;
        {
            auto prog = *base;
            prog.ordered_tcp.reset();
            config::BlockRules unpinned{.format = config::RuleFormat::kdl, .url = "https://rules.test/shared.kdl", .http_client = "c1"};
            config::BlockRules pinned = unpinned;
            pinned.sha256 = bad_sha;
            prog.routes.push_back({unpinned, config::RouteAction::direct, 0, "direct"});
            prog.routes.push_back({pinned, config::RouteAction::direct, 0, "direct"});
            cli::RuleFileInput in("/tmp/r6.kdl");
            in.seed("https://rules.test/shared.kdl", body);
            auto loaded = cli::load_route_files(prog, in);
            check(!loaded && loaded.error().contains("SHA-256"), "R6 P1-2 load_route_files verifies per-ref sha256");
            cli::run_detail::RemoteRulesetManager mgr;
            auto fi = mgr.fetch_initial(prog, "", in);
            check(!fi && fi.error().contains("conflicting sha256"), "R6 P1-2 RemoteRulesetManager rejects conflicting sha256");
            prog.routes[1].file.sha256 = good_sha;
            check(cli::load_route_files(prog, in).has_value(), "R6 P1-2 matching sha256 passes load_route_files");
        }
        {
            auto prog = *base;
            prog.dns->rule_files[0].file.url = "https://rules.test/shared.kdl";
            prog.dns->rule_files[0].file.sha256 = bad_sha;
            cli::RuleFileInput in("/tmp/r6.kdl");
            in.seed("https://rules.test/shared.kdl", body);
            auto loaded = cli::run_detail::load_dns_rules(*prog.dns, in);
            check(!loaded && loaded.error().contains("SHA-256"), "R6 P1-2 load_dns_rules rejects mismatched sha256");
            prog.dns->rule_files[0].file.sha256 = good_sha;
            check(cli::run_detail::load_dns_rules(*prog.dns, in).has_value(), "R6 P1-2 load_dns_rules accepts matching sha256");
        }
    }

    auto count_nxmm_files(std::filesystem::path const& dir, std::uint64_t& total_bytes) -> std::size_t {
        total_bytes = 0;
        std::size_t count = 0;
        std::error_code ec;
        if (!std::filesystem::is_directory(dir, ec)) return 0;
        for (auto const& ent : std::filesystem::directory_iterator(dir, ec)) {
            if (ent.is_regular_file(ec) && ent.path().filename().string().ends_with(".nxmm")) {
                ++count;
                total_bytes += ent.file_size(ec);
            }
        }
        return count;
    }

    auto test_r6_p2_4_nxmm_budget_and_clear(TempDir const& tmp) -> void {
        auto cache_dir = tmp.path / "cache", nxmm_dir = cache_dir / "nxmm";
        auto srs1 = make_srs_with_domains("one", 150), srs2 = make_srs_with_domains("two", 150);
        auto srs3 = make_srs_with_domains("thr", 150), srs4 = make_srs_with_domains("fou", 150);
        auto p1 = tmp.path / "r1.srs", p2 = tmp.path / "r2.srs", p3 = tmp.path / "r3.srs", p4 = tmp.path / "r4.srs";
        write_file(p1, srs1); write_file(p2, srs2); write_file(p3, srs3); write_file(p4, srs4);

        check(bool(cli::nxmm_detail::try_mmap_srs_sidecar(cache_dir, srs1, false)), "R6 P2-4 initial srs1 sidecar");
        auto s1 = cli::nxmm_detail::sidecar_path(cache_dir, srs1, false);
        auto s2 = cli::nxmm_detail::sidecar_path(cache_dir, srs2, false);
        auto s3 = cli::nxmm_detail::sidecar_path(cache_dir, srs3, false);
        auto s4 = cli::nxmm_detail::sidecar_path(cache_dir, srs4, false);
        auto one_sz = std::filesystem::file_size(s1);
        std::uint64_t budget = std::max<std::uint64_t>(4096, one_sz * 2 + 128);

        auto make_cfg = [&](std::filesystem::path const& srs_file) {
            return std::format(R"kdl(
schema-version 1
role "client"
state {{ cache-directory "{}"; ruleset-cache-max-bytes {}; }}
inbounds {{ inbound "s" type="socks5" {{ listen "127.0.0.1:1080"; authentication "none"; }} }}
outbounds {{ direct; }}
routing {{
    rulesets {{ geo path="{}" format="srs"; }}
    rules sniff-timeout-ms=300 unknown="skip" {{ - rule-set="geo" to="direct"; }}
    final "direct"
}}
)kdl", cache_dir.string(), budget, srs_file.string());
        };
        auto load_srs = [&](std::filesystem::path const& srs_file) {
            auto cfg = config::parse_kdl(make_cfg(srs_file));
            check(bool(cfg), cfg ? "cfg ok" : cfg.error());
            if (!cfg) return;
            auto files = cli::load_route_files(*cfg, (tmp.path / "cfg.kdl").string());
            check(bool(files) && files->ordered.size() == 1 && files->ordered[0].mmap != nullptr, "R6 P2-4 mmap ok");
        };
        auto now = std::filesystem::file_time_type::clock::now();
        std::filesystem::last_write_time(s1, now - std::chrono::seconds(30));
        load_srs(p2);
        std::filesystem::last_write_time(s2, now - std::chrono::seconds(20));
        load_srs(p3);
        std::uint64_t bytes = 0;
        auto cnt = count_nxmm_files(nxmm_dir, bytes);
        check(!std::filesystem::exists(s1) && std::filesystem::exists(s2) && std::filesystem::exists(s3),
            "R6 P2-4 oldest sidecar s1 evicted while s2 and active s3 kept");
        check(cnt == 2 && bytes <= budget, "R6 P2-4 cache/nxmm within ruleset-cache-max-bytes");

        std::filesystem::last_write_time(s3, now - std::chrono::seconds(10));
        load_srs(p2);
        load_srs(p4);
        cnt = count_nxmm_files(nxmm_dir, bytes);
        check(!std::filesystem::exists(s3) && std::filesystem::exists(s2) && std::filesystem::exists(s4),
            "R6 P2-4 recently-hit s2 preserved, stale s3 evicted on s4 write");
        check(cnt == 2 && bytes <= budget, "R6 P2-4 cache/nxmm bounded after LRU refresh");

        write_file(nxmm_dir / "orphan.nxmm.tmp.123", "tmp");
        write_file(cache_dir / "selectors.state", "keep");
        check(state::RulesetCache(cache_dir, {budget}).clear().has_value(), "R6 P2-4 RulesetCache::clear() ok");
        check(count_nxmm_files(nxmm_dir, bytes) == 0 && !std::filesystem::exists(nxmm_dir / "orphan.nxmm.tmp.123"),
            "R6 P2-4 RulesetCache::clear() removes .nxmm and .nxmm.tmp.*");
        check(std::filesystem::exists(cache_dir / "selectors.state"), "R6 P2-4 clear preserves authority files");

        load_srs(p1);
        check(count_nxmm_files(nxmm_dir, bytes) == 1, "R6 P2-4 repopulated cache/nxmm");
        auto cfg_file = tmp.path / "state_clear.kdl";
        write_file(cfg_file, make_cfg(p1));
        std::string a0 = "state", a1 = "clear-cache", a2 = "--config", a3 = cfg_file.string(), a4 = "--rulesets";
        char* argv_state[] = {a0.data(), a1.data(), a2.data(), a3.data(), a4.data()};
        check(nexus_state(5, argv_state) == 0, "R6 P2-4 nexus state clear-cache --rulesets exits 0");
        check(count_nxmm_files(nxmm_dir, bytes) == 0, "R6 P2-4 nexus state clear-cache --rulesets clears cache/nxmm");

        load_srs(p2);
        check(count_nxmm_files(nxmm_dir, bytes) == 1, "R6 P2-4 repopulated cache/nxmm for rule fetch clear");
        std::string f0 = "fetch", f1 = "--clear-cache", f2 = cache_dir.string();
        char* argv_fetch[] = {f0.data(), f1.data(), f2.data()};
        check(nexus_rule_fetch(3, argv_fetch) == 0, "R6 P2-4 nexus rule fetch --clear-cache exits 0");
        check(count_nxmm_files(nxmm_dir, bytes) == 0, "R6 P2-4 nexus rule fetch --clear-cache clears cache/nxmm");
    }
}

auto main() -> int {
    TempDir tmp("nexus-r6-cache");
    test_r6_p1_1_provider_cache_url_identity(tmp);
    test_r6_p1_2_remote_ruleset_sha256();
    test_r6_p2_4_nxmm_budget_and_clear(tmp);
    if (g_failures != 0) {
        std::cerr << g_failures << " failure(s)\n";
        return 1;
    }
    std::println("PASS wave36_core_audit_r6_cache_unit (R6 P1-1, R6 P1-2, R6 P2-4)");
    return 0;
}
