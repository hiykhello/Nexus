#include <boost/capy/ex/run_async.hpp>
#include <openssl/asn1.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

import std;
import capy;
import corosio;
import cli.proxy_providers;
import config;
import provider;
import relay;
import rulefile;
import rules;
import rules.rule_input;
import tls.profiles;
import tls.server_handshake_io;
import tls.application_io;
import tls.corosio_server_handshake;
import tls.corosio_application;
import tls.byte_stream;
import logging.cli;

namespace {
    int g_failures = 0;
    auto check(bool ok, std::string_view msg) -> void { if (!ok) { ++g_failures; std::cerr << "FAIL: " << msg << '\n'; } }
    struct TempDir {
        std::filesystem::path path;
        explicit TempDir(std::string_view stem) {
            path = std::filesystem::temp_directory_path() / (std::string(stem) + "-" + std::to_string(::getpid()));
            std::filesystem::remove_all(path); std::filesystem::create_directories(path);
        }
        ~TempDir() { std::error_code ec; std::filesystem::remove_all(path, ec); }
    };
    auto write_text(std::filesystem::path const& p, std::string_view content) -> void {
        std::ofstream f(p, std::ios::out | std::ios::binary | std::ios::trunc);
        f.write(content.data(), static_cast<std::streamsize>(content.size()));
    }
    auto b64_encode(std::string_view in) -> std::string {
        static constexpr char kT[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        for (std::size_t i = 0; i < in.size(); i += 3) {
            std::uint32_t v = std::uint32_t(static_cast<unsigned char>(in[i])) << 16;
            if (i + 1 < in.size()) v |= std::uint32_t(static_cast<unsigned char>(in[i + 1])) << 8;
            if (i + 2 < in.size()) v |= std::uint32_t(static_cast<unsigned char>(in[i + 2]));
            out.push_back(kT[(v >> 18) & 0x3f]); out.push_back(kT[(v >> 12) & 0x3f]);
            out.push_back(i + 1 < in.size() ? kT[(v >> 6) & 0x3f] : '=');
            out.push_back(i + 2 < in.size() ? kT[v & 0x3f] : '=');
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
            X509_EXTENSION* ext = X509V3_EXT_nconf_nid(nullptr, nullptr, NID_subject_alt_name, const_cast<char*>("IP:127.0.0.1,DNS:localhost"));
            if (ext && X509_add_ext(x, ext, -1) && X509_sign(x, pkey, EVP_sha256())) {
                FILE* cf = std::fopen(cert_path.c_str(), "wb"); FILE* kf = std::fopen(key_path.c_str(), "wb");
                if (cf && kf && PEM_write_X509(cf, x) && PEM_write_PrivateKey(kf, pkey, nullptr, nullptr, 0, nullptr, nullptr)) ok = true;
                if (cf) std::fclose(cf); if (kf) std::fclose(kf);
            }
            if (ext) X509_EXTENSION_free(ext);
        }
        if (ec) EC_KEY_free(ec); if (x) X509_free(x); if (pkey) EVP_PKEY_free(pkey);
        if (ok) {
            std::error_code sec;
            std::filesystem::permissions(key_path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write, std::filesystem::perm_options::replace, sec);
        }
        return ok;
    }

    struct LoopbackHttps {
        ::corosio::io_context ctx;
        ::corosio::tcp_acceptor acc{ctx};
        std::uint16_t port = 0;
        std::optional<tls::ServerCredential> cred;
        std::string body;
        std::atomic<bool> stopping{false};
        std::atomic<int> hits{0};
        std::atomic<int> not_modified{0};
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
                std::array<std::uint8_t, 4096> b{};
                while (!req.contains("\r\n\r\n")) {
                    auto r = co_await stream.read(b);
                    if (!r || *r == 0) break;
                    req.append(reinterpret_cast<char const*>(b.data()), *r);
                }
                std::string lower = req;
                for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                hits.fetch_add(1, std::memory_order_relaxed);
                std::string resp;
                if (lower.contains("if-none-match:") && lower.contains("\"v1\"")) {
                    not_modified.fetch_add(1, std::memory_order_relaxed);
                    resp = "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n";
                } else {
                    resp = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) +
                        "\r\nETag: \"v1\"\r\nSubscription-Userinfo: upload=1024; download=2048; total=1048576; expire=1893456000\r\nConnection: close\r\n\r\n" +
                        body;
                }
                (void)co_await stream.send(std::span(reinterpret_cast<std::uint8_t const*>(resp.data()), resp.size()));
                (void)co_await stream.close_output();
            }
        }

        auto start(std::filesystem::path const& cert, std::filesystem::path const& key, std::string payload) -> bool {
            auto loaded = tls::load_server_credential(cert.string(), key.string());
            if (!loaded) return false;
            cred = std::move(*loaded);
            body = std::move(payload);
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
        ~LoopbackHttps() { stop(); }
    };

    auto run_proc(std::vector<std::string> args) -> int {
        std::vector<char*> cargs;
        for (auto& a : args) cargs.push_back(a.data());
        cargs.push_back(nullptr);
        pid_t pid = ::fork();
        if (pid == 0) {
            ::execv(cargs[0], cargs.data());
            ::_exit(127);
        }
        int status = 0;
        if (::waitpid(pid, &status, 0) < 0) return -1;
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }

    auto test_uris_and_formats(TempDir const& tmp) -> void {
        auto ui = provider::parse_subscription_userinfo("upload=100; download=200; total=5000; expire=1900000000");
        check(ui && ui->upload == 100 && ui->download == 200 && ui->total == 5000 && ui->expire == 1900000000,
              "Subscription-Userinfo parsing");

        std::string uris =
            "vless://11111111-1111-1111-1111-111111111111@198.51.100.1:443?security=reality&sni=cdn.example&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&sid=01ab&flow=xtls-rprx-vision#HK-Reality\n"
            "trojan://secretpass@198.51.100.2:443?sni=tr.example&type=ws&path=/ws&host=ws.example#SG-Trojan\n"
            "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206MDFBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWjAxMjM=@198.51.100.3:8388?uot=1#JP-SS2022\n"
            "ss://YWVzLTI1Ni1nY206bGVnYWN5@198.51.100.4:8388#Legacy-SS\n"
            "hy2://hypass@198.51.100.5:443?sni=hy.example&obfs=salamander&obfs-password=salpw#US-Hy2\n"
            "tuic://22222222-2222-2222-2222-222222222222:tuicpw@198.51.100.6:443?sni=tuic.example&congestion_control=bbr#DE-Tuic\n"
            "anytls://anypw@198.51.100.7:443?sni=any.example#UK-Any\n"
            "snell://snellpsk@198.51.100.8:6160?version=5&obfs=http&obfs-host=bing.com#KR-Snell\n"
            "naive+https://user1:pass1@198.51.100.9:443?sni=naive.example#CA-Naive\n"
            "socks5://u:p@198.51.100.10:1080#Direct-Socks\n"
            "wg://privkey@198.51.100.11:51820?publickey=pubkey123&address=10.7.0.2/32&mtu=1380#WG-Node\n";

        auto b64 = b64_encode(uris);
        provider::ConvertOptions opts{.secrets_dir = (tmp.path / "uri_sec").string()};
        auto kdl = provider::convert_config_to_kdl(b64, opts);
        check(bool(kdl), "convert base64 URI list to KDL");
        if (kdl) {
            auto parsed = config::parse_kdl(kdl->first);
            check(bool(parsed), parsed ? "converted URI KDL parses" : "URI KDL parse failed: " + parsed.error());
            if (parsed) {
                check(parsed->vless_outbounds.size() == 1, "converted VLESS count");
                check(parsed->trojan_outbounds.size() == 1, "converted Trojan count");
                check(parsed->shadowsocks_outbounds.size() == 1, "SS-2022 kept, legacy skipped");
                check(parsed->hysteria2_outbounds.size() == 1, "converted Hysteria2 count");
                check(parsed->tuic_outbounds.size() == 1, "converted TUIC count");
                check(parsed->anytls_outbounds.size() == 1, "converted AnyTLS count");
                check(parsed->snell_outbounds.size() == 1, "converted Snell count");
                check(parsed->naive_outbounds.size() == 1, "converted Naive count");
                check(parsed->wireguard_outbounds.size() == 1, "converted WireGuard count");
            }
        }

        constexpr std::string_view clash_yaml = R"yaml(
mixed-port: 7892
proxies:
  - name: "HK 01"
    type: vless
    server: 198.51.100.20
    port: 443
    uuid: 33333333-3333-3333-3333-333333333333
    servername: cdn.hk.test
    network: ws
    ws-opts:
      path: /vless
      headers:
        Host: cdn.hk.test
  - {name: "Legacy VMess", type: vmess, server: 198.51.100.21, port: 443}
proxy-groups:
  - name: Auto
    type: url-test
    proxies: [HK 01]
    url: https://www.gstatic.com/generate_204
    interval: 60
    tolerance: 50
  - name: Proxy
    type: select
    proxies: [Auto, HK 01, DIRECT]
rules:
  - DOMAIN-SUFFIX,example.com,Proxy
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - MATCH,Proxy
)yaml";
        auto ck = provider::convert_config_to_kdl(clash_yaml, {.secrets_dir = (tmp.path / "clash_sec").string()});
        check(bool(ck), "convert Clash YAML to KDL");
        if (ck) {
            auto cp = config::parse_kdl(ck->first);
            check(bool(cp), cp ? "Clash KDL parses" : "Clash KDL parse failed: " + cp.error());
            check(cp && cp->selectors.size() == 2 && cp->vless_outbounds.size() == 1, "Clash groups & outbounds preserved");
        }

        constexpr std::string_view sb_json = R"json({
  "inbounds": [{"type": "mixed", "listen_port": 7895}],
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"},
    {"type": "trojan", "tag": "SB-TR", "server": "198.51.100.30", "server_port": 443, "password": "pw", "tls": {"enabled": true, "server_name": "tr.sb.test"}},
    {"type": "selector", "tag": "proxy", "outbounds": ["SB-TR", "direct"]}
  ],
  "route": {"final": "proxy", "rules": [{"domain_suffix": ["sb.example"], "outbound": "direct"}]}
})json";
        auto sk = provider::convert_config_to_kdl(sb_json, {.secrets_dir = (tmp.path / "sb_sec").string()});
        check(bool(sk), "convert sing-box JSON to KDL");
        if (sk) {
            auto sp = config::parse_kdl(sk->first);
            check(bool(sp), sp ? "sing-box KDL parses" : "sing-box KDL parse failed: " + sp.error());
        }

        constexpr std::string_view sip008 = R"json({"version": 1, "servers": [
  {"remarks": "S1", "server": "198.51.100.40", "server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": "base64key"}
]})json";
        auto pk = provider::convert_config_to_kdl(sip008, {.secrets_dir = (tmp.path / "sip_sec").string()});
        check(bool(pk) && config::parse_kdl(pk->first).has_value(), "SIP008 JSON -> KDL parses");
    }

    auto test_providers_and_https(TempDir const& tmp) -> void {
        auto cert = tmp.path / "ca.pem";
        auto key = tmp.path / "key.pem";
        check(make_loopback_cert(cert, key), "generate loopback SAN cert");

        auto sub_file = tmp.path / "local_sub.yaml";
        write_text(sub_file, R"yaml(
proxies:
  - {name: "HK-Edge", type: trojan, server: 198.51.100.51, port: 443, password: "p1", sni: "hk.test"}
  - {name: "HK-DirectDrop", type: trojan, server: 198.51.100.52, port: 443, password: "p2", sni: "drop.test"}
)yaml");
        auto local_cfg = tmp.path / "local_prov.kdl";
        std::string local_kdl = std::format(R"kdl(
schema-version 1
role "client"
certificate {{ ca-file "{}" }}
proxy-providers {{
  provider "loc" {{
    type "file"
    path "{}"
    cache-dir "{}"
    filter {{ include "HK-"; exclude "DirectDrop"; tag-prefix "p-"; }}
  }}
}}
inbounds {{ inbound "in" type="socks5" {{ listen "127.0.0.1:1080"; authentication "none"; }} }}
outbounds {{ direct; selector "proxy" {{ use "loc"; }}; }}
routing {{ default "proxy"; }}
)kdl", cert.string(), sub_file.string(), (tmp.path / "loc_cache").string());
        write_text(local_cfg, local_kdl);

        cli::ProxyProviderManager mgr;
        auto expanded = mgr.prepare_initial(local_kdl, local_cfg.string(), true);
        check(bool(expanded), expanded ? "local provider expand" : expanded.error());
        if (expanded) {
            auto parsed = config::parse_kdl(*expanded);
            check(bool(parsed), parsed ? "expanded provider KDL parses" : parsed.error());
            check(parsed && parsed->trojan_outbounds.size() == 1 && parsed->trojan_outbounds[0].name == "p-HK-Edge",
                  "provider regex filter & prefix applied");
            if (parsed && !parsed->trojan_outbounds.empty()) {
                struct stat st{};
                check(::stat(parsed->trojan_outbounds[0].config.password_file.c_str(), &st) == 0 && (st.st_mode & 0777) == 0600,
                      "provider secret file written with 0600 mode");
            }
        }

        LoopbackHttps srv;
        std::string http_payload = b64_encode("trojan://pw9@198.51.100.90:443?sni=jp.test#JP-Live\n");
        check(srv.start(cert, key, http_payload), "start loopback HTTPS provider server");
        auto http_cfg = tmp.path / "http_prov.kdl";
        auto state_cache = tmp.path / "state_cache";
        std::string http_kdl = std::format(R"kdl(
schema-version 1
role "client"
state {{ cache-directory "{}" }}
dns {{ servers {{ local "sys" }}; final "sys"; }}
http-clients {{ hc {{ outbound "direct"; domain-resolver "sys"; ca-file "{}"; protocol "http/1.1"; }} }}
proxy-providers {{
  http "remote" {{
    url "https://127.0.0.1:{}/sub"
    http-client "hc"
    format "auto"
  }}
}}
inbounds {{ inbound "in" type="socks5" {{ listen "127.0.0.1:1080"; authentication "none"; }} }}
outbounds {{ direct; selector "proxy" {{ use "remote"; }}; }}
routing {{ default "proxy"; }}
)kdl", state_cache.string(), cert.string(), srv.port);
        write_text(http_cfg, http_kdl);

        cli::ProxyProviderManager hmgr;
        auto hexp = hmgr.prepare_initial(http_kdl, http_cfg.string(), true);
        check(bool(hexp), hexp ? "HTTPS initial fetch" : hexp.error());
        auto sums = hmgr.summaries();
        check(sums.size() == 1 && sums[0].etag == "\"v1\"" && sums[0].userinfo && sums[0].userinfo->upload == 1024,
              "HTTPS provider captured ETag & Subscription-Userinfo");
        auto synced = hmgr.sync_once(false);
        check(bool(synced) && !*synced && srv.not_modified.load() == 1,
              "HTTPS revalidation used If-None-Match -> 304 Not Modified");

        srv.stop();
        cli::ProxyProviderManager offline_mgr;
        auto oexp = offline_mgr.prepare_initial(http_kdl, http_cfg.string(), true);
        check(bool(oexp), oexp ? "HTTPS offline cache fallback" : oexp.error());
        auto osums = offline_mgr.summaries();
        check(osums.size() == 1 && osums[0].userinfo && osums[0].userinfo->total == 1048576,
              "offline cache preserved Subscription-Userinfo");
    }

    auto test_advanced_rules_and_nxmm(TempDir const& tmp) -> void {
        constexpr std::string_view adv_kdl = R"kdl(
schema-version 1
role "client"
inbounds { inbound "in" type="socks5" { listen "127.0.0.1:1080"; authentication "none"; } }
outbounds { direct; block; }
routing {
  rule-set "r1" { domain-suffix "r1.test"; }
  rule-set "r2" { domain "r2.test"; }
  sub-rule "media" {
    - "domain-suffix" "stream.org" "cdn.net" to="block"
  }
  rules {
    - "rule-set" "r1" "r2" to="block"
    - "domain" "keep.local" invert=#true to="block"
    - sub-rule="media" "network" "tcp"
    - default "direct"
  }
}
)kdl";
        auto parsed = config::parse_kdl(adv_kdl);
        check(bool(parsed), parsed ? "advanced sub-rule/multi-ruleset/invert parses" : parsed.error());
        if (parsed && parsed->ordered_tcp) {
            check(parsed->ordered_tcp->rules.size() == 3, "expanded ordered rules count");
        }
        constexpr std::string_view cyc_kdl = R"kdl(
schema-version 1
role "client"
inbounds { inbound "in" type="socks5" { listen "127.0.0.1:1080"; authentication "none"; } }
outbounds { direct; }
routing {
  sub-rule "a" { - sub-rule="b"; }
  sub-rule "b" { - sub-rule="a"; }
  rules { - sub-rule="a"; - default "direct"; }
}
)kdl";
        check(!config::parse_kdl(cyc_kdl), "cyclic sub-rule rejected");

        rules::RuleSet rs;
        rs.version = 2;
        rs.rules.reserve(22000);
        for (int i = 0; i < 20000; ++i)
            rs.rules.push_back({"domain-suffix", "zone" + std::to_string(i) + ".nxmm.test", {}});
        for (int i = 0; i < 2000; ++i)
            rs.rules.push_back({"ip-cidr", std::format("10.{}.{}.0/24", (i >> 8) & 0xff, i & 0xff), {}});
        rs.rules.push_back({"ip-cidr", "2001:db8::/32", {}});

        auto bin = rules::compile_nxmm(rs);
        check(bool(bin) && bin->size() > 64, "compile 22k rules to NXMM v1");
        if (bin) {
            auto nx_path = tmp.path / "big.nxmm";
            write_text(nx_path, *bin);
            auto mm = rules::MmapMatcher::open_file(nx_path.string());
            check(bool(mm), mm ? "mmap big.nxmm" : mm.error());
            if (mm) {
                check(mm->match_domain("api.zone19999.nxmm.test"), "NXMM suffix hit");
                check(mm->match_domain("zone500.nxmm.test"), "NXMM exact suffix hit");
                check(!mm->match_domain("miss.example.com"), "NXMM domain miss");
                auto ip4 = [](std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
                    return std::array<std::uint8_t, 16>{a, b, c, d};
                };
                std::array<std::uint8_t, 16> ip6{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
                check(mm->match_ip(ip4(10, 7, 200, 55), 4), "NXMM IPv4 hit");
                check(mm->match_ip(ip6, 6), "NXMM IPv6 hit");
                check(!mm->match_ip(ip6, 0) && !mm->match_ip(ip6, 99), "NXMM invalid family rejected");
                check(!mm->match_ip(ip4(192, 0, 2, 1), 4), "NXMM IP miss");

                auto rt = rules::nxmm_to_ruleset(*mm);
                check(bool(rt) && rules::Matcher::compile(*rt).has_value(), "NXMM roundtrip to RuleSet + AST compile");

                auto ptr = std::make_shared<rules::MmapMatcher const>(std::move(*mm));
                std::array<relay::IndexedRouteRule, 1> ir{{{{}, relay::RuleFormat::nxmm, 1, false, ptr}}};
                auto snap = relay::compile_routes(ir, 0, 2, std::nullopt, std::nullopt);
                check(bool(snap), "live relay::compile_routes with MmapMatcher");
                if (snap) {
                    auto pf = snap->matcher.preflight({.domain = "zone123.nxmm.test"});
                    check(pf && *pf == 1, "zero-copy RouteMatcher preflight avoids eager DNS");
                    auto m = snap->matcher.match_with_rule({.ip = "10.3.4.5"});
                    check(m && m->outbound == 1, "zero-copy RouteMatcher matches mapped IP");
                }
            }
            std::string corrupt = *bin;
            corrupt[corrupt.size() - 5] ^= 0xff;
            check(!rules::MmapMatcher::open_bytes(corrupt), "corrupted NXMM checksum rejected");
        }
    }

    auto test_cli_smoke(char const* argv0, TempDir const& tmp) -> void {
        auto nexus_bin = std::filesystem::path(argv0).parent_path() / "nexus";
        if (!std::filesystem::exists(nexus_bin)) return;
        auto yaml_p = tmp.path / "cli_in.yaml", out_kdl = tmp.path / "cli_out.kdl";
        write_text(yaml_p, "proxies:\n  - {name: \"C1\", type: trojan, server: 198.51.100.60, port: 443, password: \"pw\"}\n");
        check(run_proc({nexus_bin.string(), "convert-config", "--secrets-dir", (tmp.path / "csec").string(), "-o", out_kdl.string(), yaml_p.string()}) == 0, "CLI convert-config exit 0");
        check(run_proc({nexus_bin.string(), "check", out_kdl.string()}) == 0, "CLI check on converted KDL exit 0");
        auto rk = tmp.path / "r.kdl", rnx = tmp.path / "r.nxmm";
        write_text(rk, "schema-version 2\nkind \"predicate\"\ndomain-suffix \"cli.example\"\n");
        check(run_proc({nexus_bin.string(), "rule", "convert", "kdl", "nxmm", rk.string(), rnx.string()}) == 0, "CLI rule convert kdl->nxmm exit 0");
        check(run_proc({nexus_bin.string(), "provider", "inspect", "-c", (tmp.path / "local_prov.kdl").string()}) == 0, "CLI provider inspect exit 0");
    }

    auto test_provider_concurrency_and_file_watch(TempDir const& tmp) -> void {
        auto sub_file = tmp.path / "watch_sub.yaml", cfg_path = tmp.path / "watch_prov.kdl";
        write_text(sub_file, "proxies:\n  - {name: \"N1\", type: trojan, server: 198.51.100.71, port: 443, password: \"p1\"}\n");
        auto make_kdl = [&](std::string_view n) {
            return std::format("schema-version 1\nrole \"client\"\nproxy-providers {{\n  provider \"{}\" {{ type \"file\"; path \"{}\"; cache-dir \"{}\"; update-interval-ms 1000; }}\n}}\ninbounds {{ inbound \"in\" type=\"socks5\" {{ listen \"127.0.0.1:1080\"; authentication \"none\"; }} }}\noutbounds {{ direct; selector \"proxy\" {{ use \"{}\"; }}; }}\nrouting {{ default \"proxy\"; }}\n", n, sub_file.string(), (tmp.path / "wcache").string(), n);
        };
        auto kdl1 = make_kdl("loc1"), kdl2 = make_kdl("loc2");
        write_text(cfg_path, kdl1);
        logging::Runtime logs; check(logs.start({}).has_value(), "start logs for provider watch test");
        cli::ProxyProviderManager mgr;
        check(mgr.prepare_initial(kdl1, cfg_path.string(), true).has_value(), "prepare_initial watch provider");
        mgr.start_background(logs);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        write_text(sub_file, "proxies:\n  - {name: \"N2\", type: trojan, server: 198.51.100.72, port: 443, password: \"p2\"}\n");
        std::error_code ec;
        std::filesystem::last_write_time(sub_file, std::filesystem::file_time_type::clock::now() + std::chrono::seconds(2), ec);
        bool updated = false;
        for (int i = 0; i < 60 && !updated; ++i) {
            if (mgr.consume_updated()) updated = true;
            else std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        check(updated, "file provider background polling detects mtime update");
        check(mgr.prepare_initial(kdl2, cfg_path.string(), true).has_value(), "concurrent reload prepare_initial safe");
        mgr.stop(); logs.shutdown();
    }
}

int main(int, char** argv) {
    TempDir tmp("nexus-b187");
    test_uris_and_formats(tmp);
    test_providers_and_https(tmp);
    test_advanced_rules_and_nxmm(tmp);
    test_cli_smoke(argv[0], tmp);
    test_provider_concurrency_and_file_watch(tmp);
    if (g_failures == 0) std::cout << "BATCH 187 PROVIDER AND MMAP TESTS PASSED\n";
    return g_failures == 0 ? 0 : 1;
}
