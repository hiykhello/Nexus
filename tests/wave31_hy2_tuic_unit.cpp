#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
import std;
import config;
import hysteria2.salamander;
import hysteria2.transport_options;
import net.datagram_driver;
import quic.datagram_port;
import relay.hysteria2_masquerade;
import capy;
import corosio;

namespace io = ::corosio;
using Clock = std::chrono::steady_clock;

namespace {
    struct TempDir {
        std::filesystem::path dir;
        std::string cert, key, pass, uuid;
        TempDir(std::filesystem::path d, std::string c, std::string k, std::string p, std::string u)
            : dir(std::move(d)), cert(std::move(c)), key(std::move(k)), pass(std::move(p)), uuid(std::move(u)) {}
        TempDir(TempDir&& o) noexcept
            : dir(std::exchange(o.dir, {})), cert(std::move(o.cert)), key(std::move(o.key)), pass(std::move(o.pass)), uuid(std::move(o.uuid)) {}
        TempDir& operator=(TempDir&&) = delete;
        ~TempDir() { if (!dir.empty()) { std::error_code ec; std::filesystem::remove_all(dir, ec); } }
    };

    auto make_temp() -> std::optional<TempDir> {
        auto dir = std::filesystem::temp_directory_path() /
            ("nexus-w31-hy2-unit-" + std::to_string(Clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(dir);
        TempDir out{dir, (dir / "cert.pem").string(), (dir / "key.pem").string(),
            (dir / "pass.txt").string(), (dir / "uuid.txt").string()};
        std::ofstream(out.cert) << "dummy\n";
        std::ofstream(out.key) << "dummy\n";
        std::ofstream(out.pass) << "test-secret-pass\n";
        std::ofstream(out.uuid) << "b7c2f3e8-1d44-4a5b-9e6c-0a1b2c3d4e5f\n";
        return out;
    }

    auto test_kdl_configs(TempDir const& tmp) -> int {
        auto make_hy2_in = [&](std::string_view masq_block) {
            return std::format(R"(schema-version 1
role "server"
inbounds {{
    inbound "hy2-in" type="hysteria2" {{
        listen host="127.0.0.1" port=8443
        authentication {{ user "u1" password-file="{}" }}
        tls {{ certificate-file "{}"; private-key-file "{}" }}
        {}
    }}
}}
outbounds {{ outbound "direct" type="direct" }}
routing {{ default "direct" }}
)", tmp.pass, tmp.cert, tmp.key, masq_block);
        };
        auto c1 = config::parse_kdl(make_hy2_in(R"(masquerade { type "string"; status 418; content "teapot"; header "X-Fake" "nginx"; header "Server" "decoy"; })"));
        if (!c1) { std::cerr << "c1 err: " << c1.error() << "\n"; return 10; }
        if (c1->inbounds.empty() || !c1->inbounds[0].hysteria2) return 10;
        auto const& m1 = c1->inbounds[0].hysteria2->masquerade;
        if (m1.type != "string" || m1.status_code != 418 || m1.target != "teapot" || m1.headers.size() != 2 || m1.headers[0].first != "x-fake") return 11;
        if (config::parse_kdl(make_hy2_in(R"(masquerade { type "string"; header "Hysteria-Auth" "bad"; })"))) return 12;
        if (config::parse_kdl(make_hy2_in(R"(masquerade { type "string"; status 99; })"))) return 13;
        if (config::parse_kdl(make_hy2_in(R"(masquerade { type "string"; status 199; })"))) return 13;

        auto c2 = config::parse_kdl(make_hy2_in(std::format(R"(masquerade {{ type "file"; directory "{}"; }})", tmp.dir.string())));
        if (!c2) { std::cerr << "c2 err: " << c2.error() << "\n"; return 14; }
        if (c2->inbounds.empty() || !c2->inbounds[0].hysteria2 || c2->inbounds[0].hysteria2->masquerade.type != "file" ||
            c2->inbounds[0].hysteria2->masquerade.target != tmp.dir.string()) return 14;
        if (config::parse_kdl(make_hy2_in(R"(masquerade { type "file"; directory "relative/path"; })"))) return 15;

        auto c3 = config::parse_kdl(make_hy2_in(R"(masquerade { type "proxy"; url "http://127.0.0.1:8080"; rewrite-host #false; })"));
        if (!c3) { std::cerr << "c3 err: " << c3.error() << "\n"; return 16; }
        if (c3->inbounds.empty() || !c3->inbounds[0].hysteria2 || c3->inbounds[0].hysteria2->masquerade.type != "proxy" ||
            c3->inbounds[0].hysteria2->masquerade.rewrite_host) return 16;
        if (config::parse_kdl(make_hy2_in(R"(masquerade { type "proxy"; url "ftp://127.0.0.1"; })"))) return 17;

        auto make_hy2_out = [&](std::string_view quic_block) {
            return std::format(R"(schema-version 1
role "client"
inbounds {{ inbound "in" type="socks5" {{ listen host="127.0.0.1" port=1080; authentication "none" }} }}
outbounds {{
    outbound "direct" type="direct"
    outbound "hy2-out" type="hysteria2" {{
        server host="127.0.0.1" port=8443
        authentication {{ password-file "{}" }}
        tls {{ server-name "localhost"; ca-file "{}"; verify #true }}
        quic {{ {} }}
    }}
}}
routing {{ default "hy2-out" }}
)", tmp.pass, tmp.cert, quic_block);
        };
        auto ho1 = config::parse_kdl(make_hy2_out(R"(ports "10000-10020"; hop-interval-ms 1000; hop-interval-max-ms 5000)"));
        if (!ho1) { std::cerr << "ho1 err: " << ho1.error() << "\n"; return 18; }
        if (ho1->hysteria2_outbounds.empty() || ho1->hysteria2_outbounds[0].config.transport.hop_interval_ms != 1000 ||
            ho1->hysteria2_outbounds[0].config.transport.hop_interval_max_ms != 5000) return 18;
        if (config::parse_kdl(make_hy2_out(R"(hop-interval-max-ms 5000)"))) return 19;
        if (config::parse_kdl(make_hy2_out(R"(ports "10000-10020"; hop-interval-ms 5000; hop-interval-max-ms 2000)"))) return 20;

        auto tuic_cfg = config::parse_kdl(std::format(R"(schema-version 1
role "client"
inbounds {{
    inbound "tuic-in" type="tuic" {{
        listen host="127.0.0.1" port=8444
        authentication {{ user "u1" uuid-file="{}" password-file="{}" }}
        tls {{ certificate-file "{}"; private-key-file "{}" }}
        zero-rtt-handshake #true
    }}
}}
outbounds {{
    outbound "direct" type="direct"
    outbound "tuic-out" type="tuic" {{
        server host="127.0.0.1" port=8444
        authentication {{ uuid-file "{}"; password-file "{}" }}
        tls {{ server-name "localhost"; ca-file "{}"; verify #true }}
        zero-rtt-handshake #true
    }}
}}
routing {{ default "tuic-out" }}
)", tmp.uuid, tmp.pass, tmp.cert, tmp.key, tmp.uuid, tmp.pass, tmp.cert));
        if (!tuic_cfg) { std::cerr << "tuic_cfg err: " << tuic_cfg.error() << "\n"; return 21; }
        if (tuic_cfg->inbounds.empty() || !tuic_cfg->inbounds[0].tuic || !tuic_cfg->inbounds[0].tuic->zero_rtt_handshake) return 21;
        if (tuic_cfg->tuic_outbounds.empty() || !tuic_cfg->tuic_outbounds[0].config.zero_rtt_handshake) return 22;
        return 0;
    }

    struct MockPort {
        using Failure = quic::DatagramPortError;
        auto request_stop() noexcept -> void {}
        auto stop() noexcept -> void {}
        auto drain() noexcept -> void {}
        auto next_expiry() const noexcept -> net::DatagramDeadline { return {}; }
        auto expire(net::DatagramClock::time_point) -> std::expected<void, Failure> { return {}; }
        auto transmitted(std::uint64_t, net::DatagramClock::time_point) -> std::expected<void, Failure> { return {}; }
        auto receive(io::endpoint const&, std::span<std::uint8_t const>, net::DatagramClock::time_point) -> std::expected<void, Failure> { return {}; }
        auto output(std::span<std::uint8_t>, net::DatagramClock::time_point) -> std::expected<std::optional<net::DatagramOutput>, Failure> { return std::nullopt; }
    };

    auto test_hop_jitter() -> int {
        hysteria2::TransportOptions opts;
        opts.port_ranges = {{10000, 10050}};
        opts.hop_interval = std::chrono::milliseconds(1000);
        opts.hop_interval_max = std::chrono::milliseconds(5000);
        if (!opts.valid()) return 30;
        opts.hop_interval_max = std::chrono::milliseconds(900);
        if (opts.valid()) return 31;

        MockPort port;
        hysteria2::SalamanderPort<MockPort> wire(port, std::nullopt);
        std::array<std::pair<std::uint16_t, std::uint16_t>, 1> ranges{{{10000, 10050}}};
        auto t = net::DatagramClock::now();
        wire.configure_hopping(443, ranges, std::chrono::milliseconds(1000), t, std::chrono::milliseconds(5000));
        std::set<std::int64_t> seen;
        for (int i = 0; i < 64; ++i) {
            auto next = wire.next_hop_time();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(next - t).count();
            if (ms < 1000 || ms > 5000) return 32;
            auto p = wire.active_hop_port();
            if (p < 10000 || p > 10050) return 33;
            seen.insert(ms);
            t = next;
            if (!wire.expire(t)) return 34;
        }
        if (seen.size() < 5) return 35;
        return 0;
    }

    auto test_masquerade_unit(TempDir const& tmp) -> int {
        namespace m = relay::hysteria2_masquerade;
        config::Hysteria2Masquerade str_cfg{"string", "hello decoy", 418, {{"x-custom", "ok"}, {"hysteria-auth", "leak"}}, true};
        auto r1 = m::serve_string(str_cfg, {"GET", "/", "example.com", {}});
        if (r1.status != 418 || std::string_view(reinterpret_cast<char const*>(r1.body.data()), r1.body.size()) != "hello decoy") return 40;
        for (auto const& [k, _] : r1.headers) if (k.starts_with("hysteria-")) return 41;
        auto r1_head = m::serve_string(str_cfg, {"HEAD", "/", "example.com", {}});
        if (!r1_head.omit_body || r1_head.body.size() != 11) return 42;
        for (std::uint16_t sc : {std::uint16_t{204}, std::uint16_t{304}}) {
            config::Hysteria2Masquerade nb_cfg{"string", "ignored-body", sc, {}, true};
            auto r_nb = m::serve_string(nb_cfg, {"GET", "/", "example.com", {}});
            if (r_nb.status != sc || !r_nb.omit_body || !r_nb.body.empty()) return 42;
        }

        auto webroot = tmp.dir / "webroot";
        auto outside = tmp.dir / "outside";
        std::filesystem::create_directories(webroot / "sub");
        std::filesystem::create_directories(outside);
        std::ofstream(webroot / "index.html") << "<h1>Decoy</h1>";
        std::ofstream(webroot / "sub" / "data.json") << "{\"ok\":true}";
        std::ofstream(outside / "secret.txt") << "TOPSECRET";
        std::filesystem::create_symlink(outside / "secret.txt", webroot / "escape.txt");

        config::Hysteria2Masquerade file_cfg{"file", webroot.string(), 200, {}, true};
        auto rf_idx = m::serve_file(file_cfg, {"GET", "/", "localhost", {}});
        if (rf_idx.status != 200 || std::string_view(reinterpret_cast<char const*>(rf_idx.body.data()), rf_idx.body.size()) != "<h1>Decoy</h1>") return 43;
        if (rf_idx.headers.empty() || rf_idx.headers[0].second != "text/html; charset=utf-8") return 44;
        auto rf_json = m::serve_file(file_cfg, {"GET", "/sub/data.json?v=1", "localhost", {}});
        if (rf_json.status != 200 || rf_json.headers[0].second != "application/json") return 45;
        if (m::serve_file(file_cfg, {"GET", "/missing.html", "localhost", {}}).status != 404) return 46;
        if (m::serve_file(file_cfg, {"GET", "/../outside/secret.txt", "localhost", {}}).status != 404) return 47;
        if (m::serve_file(file_cfg, {"GET", "/%2e%2e/outside/secret.txt", "localhost", {}}).status != 404) return 48;
        if (m::serve_file(file_cfg, {"GET", "/sub/../../outside/secret.txt", "localhost", {}}).status != 404) return 49;
        if (m::serve_file(file_cfg, {"GET", "/escape.txt", "localhost", {}}).status != 404) return 50;
        if (m::serve_file(file_cfg, {"GET", "/index.html%00.txt", "localhost", {}}).status != 404) return 51;

        io::io_context ctx;
        io::tcp_acceptor acc(ctx);
        if (acc.open(io::family::v4) || acc.bind({io::ipv4_address::loopback(), 0}) || acc.listen()) return 52;
        auto port = acc.local_endpoint().port();
        std::string observed_host1, observed_host2;
        auto upstream = [&]() -> capy::task<> {
            for (int round = 0; round < 2; ++round) {
                io::tcp_socket s(ctx);
                auto [ec] = co_await acc.accept(s);
                if (ec) co_return;
                std::string req_buf;
                std::array<char, 2048> b{};
                while (!req_buf.contains("\r\n\r\n")) {
                    auto [rec, n] = co_await s.read_some(capy::mutable_buffer(b.data(), b.size()));
                    if (rec || !n) break;
                    req_buf.append(b.data(), n);
                }
                auto hpos = req_buf.find("Host: ");
                std::string host_val;
                if (hpos != std::string::npos) {
                    auto end = req_buf.find("\r\n", hpos);
                    host_val = req_buf.substr(hpos + 6, end - (hpos + 6));
                }
                if (round == 0) observed_host1 = host_val; else observed_host2 = host_val;
                std::string body = "proxied:" + host_val;
                std::string reply = std::format(
                    "HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nX-Decoy: yes\r\nHysteria-Auth: must-strip\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.size(), body);
                std::size_t off = 0;
                while (off < reply.size()) {
                    auto [wec, n] = co_await s.write_some(capy::const_buffer(reply.data() + off, reply.size() - off));
                    if (wec || !n) break;
                    off += n;
                }
            }
        };
        int proxy_res = 0;
        auto run_proxy = [&]() -> capy::task<> {
            config::Hysteria2Masquerade p1{"proxy", std::format("http://127.0.0.1:{}", port), 200, {}, true};
            auto resp1 = co_await m::serve_proxy(ctx, p1, {"GET", "/hello", "client.example.com", {{"hysteria-auth", "nope"}}});
            if (resp1.status != 201) { proxy_res = 53; co_return; }
            for (auto const& [k, _] : resp1.headers) if (k.starts_with("hysteria-")) { proxy_res = 54; co_return; }
            if (observed_host1 != std::format("127.0.0.1:{}", port)) { proxy_res = 55; co_return; }
            config::Hysteria2Masquerade p2{"proxy", std::format("http://127.0.0.1:{}", port), 200, {}, false};
            auto resp2 = co_await m::serve_proxy(ctx, p2, {"GET", "/hello", "client.example.com", {}});
            if (resp2.status != 201 || observed_host2 != "client.example.com") { proxy_res = 56; co_return; }
        };
        capy::run_async(ctx.get_executor())(upstream());
        capy::run_async(ctx.get_executor())(run_proxy());
        ctx.run_for(std::chrono::seconds(4));
        return proxy_res;
    }
}

auto main() -> int {
    auto tmp = make_temp();
    if (!tmp) return 1;
    if (int r = test_kdl_configs(*tmp); r) { std::println("KDL config test failed: {}", r); return r; }
    if (int r = test_hop_jitter(); r) { std::println("Hop jitter test failed: {}", r); return r; }
    if (int r = test_masquerade_unit(*tmp); r) { std::println("Masquerade unit test failed: {}", r); return r; }
    std::println("Wave 31 Track 31D unit tests (KDL configs, hop-interval-max-ms jitter, masquerade string/file/proxy) passed");
    return 0;
}
