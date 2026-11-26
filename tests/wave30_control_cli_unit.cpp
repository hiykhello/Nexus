// Wave 30 Track 30C unit tests: /v1/rules, /v1/dns/query, FakeIP flush, CORS, tools fetch, RFC 5780 STUN.
#include <arpa/inet.h>
#include <cassert>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import cli.dns_live_query;
import cli.proxy_http_control;
import cli.stun_rfc5780;
import cli.tools_fetch;
import config;
import control_api;
import control_api.http_extra_routes;
import control_api.types;
import dns.fakeip;
import dns.message;
import platform.unique_fd;

namespace {
    auto test_rules_endpoint() -> void {
        constexpr std::string_view kKdl = R"(
schema-version 1
role "client"
workers 1
inbounds {
    inbound "in-socks" type="socks5" {
        listen host="127.0.0.1" port=1080
        authentication "none"
    }
}
outbounds {
    outbound "direct" type="direct"
    outbound "block" type="block"
}
routing {
    tcp-program sniff-timeout-ms=500 unknown="skip" udp=#true {
        rule action="sniff"
        rule action="route" outbound="direct" {
            domain-suffix "example.com"
        }
        rule action="reject" {
            port 25
        }
    }
    default-outbound "direct"
}
)";
        auto cfg = config::parse_kdl(kKdl);
        if (!cfg) { std::cerr << "rules kdl err: " << cfg.error() << '\n'; }
        assert(cfg.has_value());
        auto rules_vec = cli::run_detail::build_rules_snapshot(*cfg);
        assert(rules_vec.size() == 4);
        assert(rules_vec[0].index == 1 && rules_vec[0].action == "sniff");
        assert(rules_vec[1].index == 2 && rules_vec[1].action == "route" && rules_vec[1].target == "direct");
        assert(rules_vec[1].summary.contains("example.com"));
        assert(rules_vec[2].index == 3 && rules_vec[2].action == "reject");
        assert(rules_vec[3].index == 4 && rules_vec[3].type == "final" && rules_vec[3].target == "direct");

        control_api::HttpControlServer srv;
        bool requested_rules_only = false;
        auto snap_fn = [&](control_api::SnapshotFields f, std::optional<std::uint64_t>) -> control_api::ControlSnapshot {
            requested_rules_only = (f == control_api::SnapshotFields::rules);
            control_api::ControlSnapshot s{};
            s.rules = rules_vec;
            return s;
        };
        auto cmd_fn = [](std::span<std::string_view const>) -> std::expected<std::string, std::string> {
            return std::unexpected("unused");
        };
        auto resp = srv.handle_direct_http_for_test("GET /v1/rules HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", snap_fn, cmd_fn);
        assert(requested_rules_only);
        assert(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert(resp.contains("\"rules\":["));
        assert(resp.contains("\"action\":\"sniff\""));
        assert(resp.contains("example.com"));
        assert(resp.contains("\"type\":\"final\""));
    }

    auto test_dns_query_validation_and_rdata() -> void {
        using namespace control_api::http_detail;
        assert(valid_dns_query_name("example.com"));
        assert(valid_dns_query_name("sub_1.example.com."));
        assert(!valid_dns_query_name(""));
        assert(!valid_dns_query_name("bad..example.com"));
        assert(!valid_dns_query_name("bad host.com"));

        auto p1 = parse_dns_query_params("name=example.com&type=HTTPS&server=cf");
        assert(p1 && p1->name == "example.com" && p1->qtype == 65 && p1->server == "cf");
        auto p2 = parse_dns_query_params("name=example.com");
        assert(p2 && p2->qtype == 1 && p2->type_name == "A");
        assert(!parse_dns_query_params("type=A").has_value());
        assert(!parse_dns_query_params("name=example.com&type=NOPE").has_value());
        assert(!parse_dns_query_params("name=example.com&type=41").has_value());

        // Craft a minimal DNS wire response containing A + TXT answers for example.com.
        dns::Response resp{};
        resp.rcode = 0;
        // RDATA at offsets: A (4 bytes), TXT (6 bytes: len 5 "hello"), AAAA (16 bytes)
        resp.wire = {
            93, 184, 216, 34,
            5, 'h', 'e', 'l', 'l', 'o',
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        };
        dns::Record r_a{.name = "example.com", .type = 1, .klass = 1, .ttl = 120,
            .section = dns::Section::answer, .data_offset = 0, .data_length = 4};
        dns::Record r_txt{.name = "example.com", .type = 16, .klass = 1, .ttl = 60,
            .section = dns::Section::answer, .data_offset = 4, .data_length = 6};
        dns::Record r_aaaa{.name = "example.com", .type = 28, .klass = 1, .ttl = 300,
            .section = dns::Section::answer, .data_offset = 10, .data_length = 16};
        resp.records = {r_a, r_txt, r_aaaa};
        auto json = cli::live_dns_detail::format_dns_response_json("example.com", 1, resp, 12);
        assert(json.contains("\"rcode\":0"));
        assert(json.contains("\"rcode_name\":\"NOERROR\""));
        assert(json.contains("\"ttl\":60"));
        assert(json.contains("\"elapsed_ms\":12"));
        assert(json.contains("93.184.216.34"));
        assert(json.contains("\"type\":\"TXT\""));
        assert(json.contains("\"data\":\"hello\""));
        assert(json.contains("2001:db8::1"));

        // Direct HTTP /v1/dns/query route test (validation error + 200 immediate + 404 unknown-server).
        control_api::HttpControlServer srv;
        auto snap_fn = [](control_api::SnapshotFields, std::optional<std::uint64_t>) { return control_api::ControlSnapshot{}; };
        auto cmd_fn = [&](std::span<std::string_view const> args) -> std::expected<std::string, std::string> {
            assert(args.size() >= 3 && args[0] == "dns-query");
            if (args.size() == 4 && args[3] == "missing") return std::unexpected("unknown-server");
            return json;
        };
        auto r_bad = srv.handle_direct_http_for_test("GET /v1/dns/query?name=bad..name HTTP/1.1\r\nHost: x\r\n\r\n", snap_fn, cmd_fn);
        assert(r_bad.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        auto r_404 = srv.handle_direct_http_for_test("GET /v1/dns/query?name=example.com&server=missing HTTP/1.1\r\nHost: x\r\n\r\n", snap_fn, cmd_fn);
        assert(r_404.starts_with("HTTP/1.1 404 Not Found\r\n"));
        auto r_ok = srv.handle_direct_http_for_test("GET /v1/dns/query?name=example.com&type=A HTTP/1.1\r\nHost: x\r\n\r\n", snap_fn, cmd_fn);
        assert(r_ok.starts_with("HTTP/1.1 200 OK\r\n"));
        assert(r_ok.contains("93.184.216.34"));
    }

    auto test_fakeip_unpinned_flush_and_cache_routes() -> void {
        constexpr std::uint32_t kFirst = 0xc6120001u; // 198.18.0.1
        constexpr std::uint32_t kLast = 0xc6120020u;
        auto pool = dns::FakeIpPool::create(kFirst, kLast, std::chrono::seconds(60), std::chrono::seconds(5));
        assert(pool.has_value());
        auto now = std::chrono::steady_clock::now();
        auto a1 = (*pool)->publish("pinned.example", 0, now);
        auto a2 = (*pool)->publish("idle1.example", 0, now);
        auto a3 = (*pool)->publish("idle2.example", 0, now);
        assert(a1 && a2 && a3);
        assert((*pool)->pin(*a1, now).has_value());
        auto flushed = (*pool)->flush_unpinned();
        assert(flushed == 2);
        auto still_pinned = (*pool)->lookup(a1->address, now);
        assert(still_pinned && *still_pinned && (*still_pinned)->domain == "pinned.example");
        auto gone2 = (*pool)->lookup(a2->address, now);
        auto gone3 = (*pool)->lookup(a3->address, now);
        assert(gone2 && !gone2->has_value());
        assert(gone3 && !gone3->has_value());

        // Test LiveDnsQueryHub hook dispatch + HTTP /v1/cache/fakeip/flush & /v1/state/clear-cache?scope=fakeip.
        int hook_owner = 0;
        bool dns_cleared = false;
        cli::LiveDnsQueryHub::instance().register_hooks({
            .owner = &hook_owner,
            .clear_cache = [&] { dns_cleared = true; },
            .flush_fakeip = [&]() -> std::optional<std::size_t> { return (*pool)->flush_unpinned(); },
        });
        auto a4 = (*pool)->publish("idle3.example", 0, now);
        assert(a4.has_value());
        control_api::HttpControlServer srv;
        auto snap_fn = [](control_api::SnapshotFields, std::optional<std::uint64_t>) { return control_api::ControlSnapshot{}; };
        auto cmd_fn = [](std::span<std::string_view const> args) -> std::expected<std::string, std::string> {
            if (args.size() == 1 && args[0] == "flush-fakeip") {
                auto n = cli::LiveDnsQueryHub::instance().flush_active_fakeip();
                if (!n) return std::unexpected("fakeip-unavailable");
                return std::format("flushed={}\n", *n);
            }
            if (args.size() == 2 && args[0] == "clear-cache") {
                if (args[1] == "all" || args[1] == "dns") cli::LiveDnsQueryHub::instance().clear_active_dns_caches();
                if (args[1] == "all" || args[1] == "fakeip") (void)cli::LiveDnsQueryHub::instance().flush_active_fakeip();
                return std::format("cleared={}\n", args[1]);
            }
            return std::unexpected("invalid");
        };
        auto fresp = srv.handle_direct_http_for_test("POST /v1/cache/fakeip/flush HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", snap_fn, cmd_fn);
        assert(fresp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert(fresp.contains("\"flushed\":1"));
        auto kept = (*pool)->lookup(a1->address, now);
        auto gone4 = (*pool)->lookup(a4->address, now);
        assert(kept && *kept && (*kept)->domain == "pinned.example");
        assert(gone4 && !gone4->has_value());

        auto cresp = srv.handle_direct_http_for_test("POST /v1/state/clear-cache?scope=all HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", snap_fn, cmd_fn);
        assert(cresp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert(dns_cleared);
        auto cbad = srv.handle_direct_http_for_test("POST /v1/state/clear-cache?scope=bogus HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", snap_fn, cmd_fn);
        assert(cbad.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        cli::LiveDnsQueryHub::instance().unregister_hooks(&hook_owner);
    }

    auto test_cors_config_and_preflight() -> void {
        constexpr std::string_view kBase =
            "schema-version 1\nrole \"client\"\nworkers 1\n"
            "inbounds { inbound \"s\" type=\"socks5\" { listen host=\"127.0.0.1\" port=1080; authentication \"none\" } }\n"
            "outbounds { outbound \"direct\" type=\"direct\" }\n"
            "routing { default-outbound \"direct\" }\n";
        auto good = config::parse_kdl(std::string(kBase) +
            "control http-listen=\"127.0.0.1:19090\" {\n"
            "  cors-allow-origin \"https://ui.example.com\"\n"
            "  cors-allow-origin \"http://localhost:3000\"\n}\n");
        assert(good && good->control_http && good->control_http->cors_allow_origins.size() == 2);
        assert(good->control_http->cors_allow_origins[0] == "https://ui.example.com");
        assert(good->control_http->cors_allow_origins[1] == "http://localhost:3000");
        auto good_prop = config::parse_kdl(std::string(kBase) +
            "control http-listen=\"127.0.0.1:19090\" cors-allow-origin=\"https://a.example, https://b.example\"\n");
        assert(good_prop && good_prop->control_http && good_prop->control_http->cors_allow_origins.size() == 2);
        assert(!config::parse_kdl(std::string(kBase) +
            "control http-listen=\"127.0.0.1:19090\" { cors-allow-origin \"ftp://bad.example.com\" }\n").has_value());
        assert(!config::parse_kdl(std::string(kBase) +
            "control { cors-allow-origin \"https://ui.example.com\" }\n").has_value());

        // Write a temporary bearer token file (0600) to verify CORS never weakens Bearer auth.
        auto tok_path = std::filesystem::temp_directory_path() / ("nexus-w30-tok-" + std::to_string(::getpid()));
        {
            std::ofstream ofs(tok_path, std::ios::binary | std::ios::trunc);
            ofs << "super-secret-wave30-token-0123456789\n";
        }
        std::filesystem::permissions(tok_path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace);
        struct RemoveGuard { std::filesystem::path p; ~RemoveGuard() { std::error_code ec; std::filesystem::remove(p, ec); } } rm{tok_path};

        config::ControlHttpConfig hc{};
        hc.host = "127.0.0.1";
        hc.port = 0;
        hc.bearer_token_file = tok_path.string();
        hc.cors_allow_origins = {"https://ui.example.com"};
        control_api::HttpControlServer srv;
        assert(srv.start(hc).has_value());

        auto snap_fn = [](control_api::SnapshotFields, std::optional<std::uint64_t>) {
            control_api::ControlSnapshot s{};
            s.instance = "test-inst";
            return s;
        };
        auto cmd_fn = [](std::span<std::string_view const>) -> std::expected<std::string, std::string> { return std::unexpected("unused"); };

        // Allowed preflight (no auth header) -> 204 + ACAO + Vary: Origin
        auto pre_ok = srv.handle_direct_http_for_test(
            "OPTIONS /v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://ui.example.com\r\n\r\n", snap_fn, cmd_fn);
        assert(pre_ok.starts_with("HTTP/1.1 204 No Content\r\n"));
        assert(pre_ok.contains("Access-Control-Allow-Origin: https://ui.example.com\r\n"));
        assert(pre_ok.contains("Vary: Origin\r\n"));

        // Disallowed preflight -> 403 without ACAO
        auto pre_deny = srv.handle_direct_http_for_test(
            "OPTIONS /v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://evil.example\r\n\r\n", snap_fn, cmd_fn);
        assert(pre_deny.starts_with("HTTP/1.1 403 Forbidden\r\n"));
        assert(!pre_deny.contains("Access-Control-Allow-Origin:"));

        // Authenticated endpoint without token still returns 401 (CORS does NOT weaken auth)
        auto no_auth = srv.handle_direct_http_for_test(
            "GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://ui.example.com\r\n\r\n", snap_fn, cmd_fn);
        assert(no_auth.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
        assert(no_auth.contains("Access-Control-Allow-Origin: https://ui.example.com\r\n"));

        // Valid bearer + allowed origin -> 200 + ACAO
        auto authed = srv.handle_direct_http_for_test(
            "GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://ui.example.com\r\n"
            "Authorization: Bearer super-secret-wave30-token-0123456789\r\n\r\n", snap_fn, cmd_fn);
        assert(authed.starts_with("HTTP/1.1 200 OK\r\n"));
        assert(authed.contains("Access-Control-Allow-Origin: https://ui.example.com\r\n"));
        assert(authed.contains("Vary: Origin\r\n"));

        // Default server (CORS disabled): zero CORS headers emitted.
        control_api::HttpControlServer no_cors;
        auto plain = no_cors.handle_direct_http_for_test(
            "GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://ui.example.com\r\n\r\n", snap_fn, cmd_fn);
        assert(plain.starts_with("HTTP/1.1 200 OK\r\n"));
        assert(!plain.contains("Access-Control-Allow-Origin:"));
    }

    auto test_tools_fetch_parser_and_loopback() -> void {
        using namespace cli::fetch;
        auto u1 = parse_fetch_url("https://example.com/path?a=1");
        assert(u1 && u1->https && u1->destination.port == 443 && u1->target == "/path?a=1");
        auto u2 = parse_fetch_url("http://127.0.0.1:8080");
        assert(u2 && !u2->https && u2->destination.port == 8080 && u2->target == "/");
        auto u3 = parse_fetch_url("https://[::1]:8443/v1");
        assert(u3 && u3->https && u3->destination.port == 8443);
        assert(!parse_fetch_url("ftp://example.com/file").has_value());

        auto h1 = parse_header_line("X-Custom: hello world");
        assert(h1 && h1->name == "X-Custom" && h1->value == "hello world");
        assert(!parse_header_line("InvalidHeader").has_value());

        std::array<char const*, 9> argv_ok{"fetch", "http://127.0.0.1/test", "-X", "post", "-d", "abc", "-H", "X-A: 1", "--json"};
        auto parsed = parse_fetch_args(static_cast<int>(argv_ok.size()), const_cast<char**>(argv_ok.data()));
        assert(parsed && parsed->method == "POST" && parsed->body == "abc" && parsed->headers.size() == 1 && parsed->json);

        std::array<char const*, 4> argv_bad{"fetch", "http://127.0.0.1/", "--outbound", "proxy"};
        assert(!parse_fetch_args(static_cast<int>(argv_bad.size()), const_cast<char**>(argv_bad.data())).has_value());

        // Live loopback HTTP/1.1 server for GET, HEAD, and POST.
        platform::UniqueFd lfd(::socket(AF_INET, SOCK_STREAM, 0));
        assert(lfd.valid());
        int one = 1;
        (void)::setsockopt(lfd.get(), SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in sin{};
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_port = 0;
        assert(::bind(lfd.get(), reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) == 0);
        assert(::listen(lfd.get(), 8) == 0);
        socklen_t slen = sizeof(sin);
        assert(::getsockname(lfd.get(), reinterpret_cast<sockaddr*>(&sin), &slen) == 0);
        auto port = ntohs(sin.sin_port);

        std::thread server_thr([fd = lfd.get()] {
            for (int i = 0; i < 3; ++i) {
                platform::UniqueFd cfd(::accept(fd, nullptr, nullptr));
                if (!cfd.valid()) break;
                std::string req;
                char buf[2048];
                while (!req.contains("\r\n\r\n")) {
                    auto n = ::recv(cfd.get(), buf, sizeof(buf), 0);
                    if (n <= 0) break;
                    req.append(buf, static_cast<std::size_t>(n));
                }
                bool is_head = req.starts_with("HEAD ");
                bool is_post = req.starts_with("POST ");
                std::string body = is_post ? "post-ok" : "hello-nexus-fetch";
                std::string resp = std::format(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Echo-Method: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    is_head ? "HEAD" : (is_post ? "POST" : "GET"), body.size(), is_head ? "" : body);
                (void)::send(cfd.get(), resp.data(), resp.size(), 0);
            }
        });

        FetchOptions get_opts{};
        get_opts.url = std::format("http://127.0.0.1:{}/hello?x=1", port);
        get_opts.headers.push_back({"X-Probe", "wave30"});
        auto get_res = run_fetch(get_opts);
        assert(get_res && get_res->status == 200 && get_res->protocol == "http/1.1");
        assert(get_res->resolved_ip == "127.0.0.1" && get_res->body_bytes == 17 && get_res->body_preview == "hello-nexus-fetch");
        auto j = format_fetch_json(*get_res);
        assert(j.contains("\"protocol\":\"http/1.1\"") && j.contains("\"status\":200"));

        FetchOptions head_opts = get_opts;
        head_opts.method = "HEAD";
        auto head_res = run_fetch(head_opts);
        assert(head_res && head_res->status == 200 && head_res->body_bytes == 0);

        FetchOptions post_opts = get_opts;
        post_opts.method = "POST";
        post_opts.body = "payload=1";
        auto post_res = run_fetch(post_opts);
        assert(post_res && post_res->status == 200 && post_res->body_preview == "post-ok");

        server_thr.join();
    }

    auto test_stun_rfc5780_codec_and_classifier() -> void {
        using namespace cli::stun;
        std::array<std::uint8_t, 12> tx{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        auto req0 = build_binding_request(tx, false, false);
        assert(req0.size() == 20 && req0[0] == 0x00 && req0[1] == 0x01 && req0[3] == 0x00);
        auto req_both = build_binding_request(tx, true, true);
        assert(req_both.size() == 28 && req_both[20] == 0x00 && req_both[21] == 0x03 && req_both[27] == 0x06);
        auto req_port = build_binding_request(tx, false, true);
        assert(req_port.size() == 28 && req_port[27] == 0x02);

        // Build synthetic Binding Success Response with XOR-MAPPED-ADDRESS (203.0.113.5:54321) + OTHER-ADDRESS (198.51.100.2:3479)
        std::vector<std::uint8_t> pkt(20 + 12 + 12, 0);
        pkt[0] = 0x01; pkt[1] = 0x01; // Binding Success
        pkt[2] = 0x00; pkt[3] = 24;   // message length = 24
        pkt[4] = 0x21; pkt[5] = 0x12; pkt[6] = 0xa4; pkt[7] = 0x42;
        std::ranges::copy(tx, pkt.begin() + 8);
        // XOR-MAPPED-ADDRESS (0x0020)
        pkt[20] = 0x00; pkt[21] = 0x20; pkt[22] = 0x00; pkt[23] = 8;
        pkt[25] = 0x01;
        std::uint16_t xport = 54321u ^ 0x2112u;
        pkt[26] = static_cast<std::uint8_t>(xport >> 8); pkt[27] = static_cast<std::uint8_t>(xport & 0xffu);
        pkt[28] = 203 ^ 0x21; pkt[29] = 0 ^ 0x12; pkt[30] = 113 ^ 0xa4; pkt[31] = 5 ^ 0x42;
        // OTHER-ADDRESS (0x802c)
        pkt[32] = 0x80; pkt[33] = 0x2c; pkt[34] = 0x00; pkt[35] = 8;
        pkt[37] = 0x01;
        pkt[38] = static_cast<std::uint8_t>(3479u >> 8); pkt[39] = static_cast<std::uint8_t>(3479u & 0xffu);
        pkt[40] = 198; pkt[41] = 51; pkt[42] = 100; pkt[43] = 2;

        auto parsed = parse_binding_response(pkt, tx);
        assert(parsed && parsed->mapped && parsed->other);
        assert(parsed->mapped->format() == "203.0.113.5:54321");
        assert(parsed->other->format() == "198.51.100.2:3479");

        std::array<std::uint8_t, 12> wrong_tx{};
        assert(!parse_binding_response(pkt, wrong_tx).has_value());

        Endpoint local{false, {10, 0, 0, 2}, 40000};
        Endpoint m1 = *parsed->mapped;
        Endpoint m2{false, {203, 0, 113, 5}, 54322};
        Endpoint m3{false, {203, 0, 113, 5}, 54323};
        assert(classify_nat_mapping(m1, m1, std::nullopt, std::nullopt) == NatMapping::direct);
        assert(classify_nat_mapping(local, m1, m1, std::nullopt) == NatMapping::endpoint_independent);
        assert(classify_nat_mapping(local, m1, m2, m2) == NatMapping::address_dependent);
        assert(classify_nat_mapping(local, m1, m2, m3) == NatMapping::address_and_port_dependent);
        assert(classify_nat_mapping(local, m1, std::nullopt, std::nullopt) == NatMapping::unknown);

        assert(classify_nat_filtering(true, false) == NatFiltering::endpoint_independent);
        assert(classify_nat_filtering(false, true) == NatFiltering::address_dependent);
        assert(classify_nat_filtering(false, false) == NatFiltering::address_and_port_dependent);

        NatBehaviorReport rep{"stun.example:3478", m1, parsed->other, NatMapping::endpoint_independent,
            NatFiltering::address_dependent, 14.5, true};
        auto rj = format_report_json(rep);
        assert(rj.contains("\"mapping\":\"Endpoint-Independent\""));
        assert(rj.contains("\"filtering\":\"Address-Dependent\""));
        assert(format_report_text(rep).contains("NAT Mapping: Endpoint-Independent"));
    }

    auto test_live_dns_hub_raii_gate_and_eviction() -> void {
        cli::LiveDnsQueryHub hub;
        config::Config cfg{};
        cfg.dns.emplace();
        cfg.dns->servers.push_back(config::DnsServer{.name = "sys"});
        cfg.dns->final = 0;
        std::optional<config::Config> running = cfg;
        auto gate = std::make_shared<cli::LiveDnsHookGate>();
        int owner = 0;
        bool drop_finish = false;
        std::optional<cli::LiveDnsCompletion> pinned_front;
        hub.register_hooks({
            .owner = &owner, .gate = gate,
            .submit_query = [&](std::uint64_t, std::string name, std::uint16_t, std::string, std::uint32_t,
                cli::LiveDnsCompletion fin) -> bool {
                if (name == "pin-front.test") { pinned_front = std::move(fin); return true; }
                if (drop_finish) return true; // Drops fin without calling it -> RAII must cancel & free slot!
                fin(std::string("{\"ok\":true}\n"));
                return true;
            },
        });
        // 1. Pin front entry pending, then fill > kMaxEntries completed queries -> must NOT wedge!
        auto front = hub.enqueue(running, "pin-front.test", 1, "");
        assert(front && hub.in_flight_count() == 1);
        for (std::size_t i = 0; i < cli::LiveDnsQueryHub::kMaxEntries + 8; ++i) {
            auto r = hub.enqueue(running, "ok.test", 1, "");
            assert(r.has_value());
        }
        assert(hub.in_flight_count() == 1);
        // 2. Dropped completion guard automatically cancels & releases in_flight_ slot.
        drop_finish = true;
        auto dropped = hub.enqueue(running, "dropped.test", 1, "");
        assert(dropped.has_value());
        assert(hub.in_flight_count() == 1);
        pinned_front.reset(); // RAII cancels front entry too!
        assert(hub.in_flight_count() == 0);
        // 3. Deactivated hook gate rejects new entries cleanly without invoking callback.
        bool called = false;
        hub.register_hooks({.owner = &owner, .gate = gate, .clear_cache = [&] { called = true; }});
        gate->deactivate_and_drain();
        hub.clear_active_dns_caches();
        assert(!called);
        hub.unregister_hooks(&owner);
    }
}

int main() {
    test_rules_endpoint();
    test_dns_query_validation_and_rdata();
    test_fakeip_unpinned_flush_and_cache_routes();
    test_cors_config_and_preflight();
    test_tools_fetch_parser_and_loopback();
    test_stun_rfc5780_codec_and_classifier();
    test_live_dns_hub_raii_gate_and_eviction();
    std::cout << "wave30_control_cli_unit: all tests passed\n";
    return 0;
}
