// Wave 33 unit & loopback tests for Core Control API RFC 6455 multiplexed WebSocket (GET /v1/ws).
#if !defined(_WIN32)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

import std;
import config;
import control_api;
import control_api.http_format;
import control_api.http_stream;
import control_api.http_ws;
import control_api.types;

using namespace control_api;
using namespace control_api::http_detail;

namespace {
    void require(bool cond, std::string_view msg) {
        if (!cond) { std::cerr << "FAIL: " << msg << '\n'; std::exit(1); }
    }

    auto make_masked_frame(std::uint8_t opcode, std::string_view payload, bool fin = true,
        std::array<std::uint8_t, 4> mask = {0x37, 0xfa, 0x21, 0x3d}) -> std::string {
        std::string out;
        out.push_back(static_cast<char>((fin ? 0x80u : 0x00u) | (opcode & 0x0fu)));
        if (payload.size() < 126) {
            out.push_back(static_cast<char>(0x80u | payload.size()));
        } else if (payload.size() <= 0xffffu) {
            out.push_back(static_cast<char>(0x80u | 126u));
            out.push_back(static_cast<char>((payload.size() >> 8) & 0xffu));
            out.push_back(static_cast<char>(payload.size() & 0xffu));
        } else {
            out.push_back(static_cast<char>(0x80u | 127u));
            std::uint64_t n = payload.size();
            for (int s = 56; s >= 0; s -= 8) out.push_back(static_cast<char>((n >> s) & 0xffu));
        }
        for (auto m : mask) out.push_back(static_cast<char>(m));
        for (std::size_t i = 0; i < payload.size(); ++i)
            out.push_back(static_cast<char>(static_cast<std::uint8_t>(payload[i]) ^ mask[i & 3u]));
        return out;
    }

    struct ServerFrame { std::uint8_t opcode = 0; std::string payload; };

    auto pop_server_frame(std::string& buf) -> std::optional<ServerFrame> {
        if (buf.size() < 2) return std::nullopt;
        auto b0 = static_cast<std::uint8_t>(buf[0]);
        auto b1 = static_cast<std::uint8_t>(buf[1]);
        require((b1 & 0x80u) == 0, "server frames must be unmasked");
        std::size_t len = b1 & 0x7fu, hdr = 2;
        if (len == 126) {
            if (buf.size() < 4) return std::nullopt;
            len = (std::size_t{static_cast<std::uint8_t>(buf[2])} << 8) | static_cast<std::uint8_t>(buf[3]);
            hdr = 4;
        } else if (len == 127) {
            if (buf.size() < 10) return std::nullopt;
            len = 0;
            for (std::size_t i = 0; i < 8; ++i) len = (len << 8) | static_cast<std::uint8_t>(buf[2 + i]);
            hdr = 10;
        }
        if (buf.size() < hdr + len) return std::nullopt;
        ServerFrame f{static_cast<std::uint8_t>(b0 & 0x0fu), buf.substr(hdr, len)};
        buf.erase(0, hdr + len);
        return f;
    }

    auto close_code_of(ServerFrame const& f) -> std::uint16_t {
        require(f.opcode == 0x8 && f.payload.size() >= 2, "valid close frame");
        return static_cast<std::uint16_t>((std::uint16_t{static_cast<std::uint8_t>(f.payload[0])} << 8) |
            static_cast<std::uint8_t>(f.payload[1]));
    }

    auto parse_raw_req(std::string_view raw) -> ParsedHttpRequest {
        auto end = raw.find("\r\n\r\n");
        require(end != std::string_view::npos, "req has header terminator");
        return parse_http_request_head(raw, end);
    }

    auto to_u8(std::string_view s) -> std::vector<std::uint8_t> {
        return {reinterpret_cast<std::uint8_t const*>(s.data()), reinterpret_cast<std::uint8_t const*>(s.data()) + s.size()};
    }

    void test_accept_hash_and_origin() {
        // Official RFC 6455 §1.3 test vector.
        auto acc = compute_ws_accept("dGhlIHNhbXBsZSBub25jZQ==");
        require(acc.has_value() && *acc == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "RFC 6455 accept hash");
        require(!compute_ws_accept("too-short").has_value(), "reject short Sec-WebSocket-Key");
        require(!compute_ws_accept("!!!invalid-base64-key!!!").has_value(), "reject non-base64 key");

        // CSWSH Origin protection.
        std::vector<std::string> cors{"https://panel.trusted.example"};
        require(ws_origin_allowed(cors, ""), "empty Origin allowed for native clients");
        require(ws_origin_allowed(cors, "http://127.0.0.1:9090"), "IPv4 loopback allowed");
        require(ws_origin_allowed(cors, "https://localhost:5173"), "localhost allowed");
        require(ws_origin_allowed(cors, "http://[::1]:9090"), "IPv6 loopback allowed");
        require(ws_origin_allowed(cors, "https://panel.trusted.example"), "configured CORS origin allowed");
        require(!ws_origin_allowed(cors, "https://evil.example"), "cross-site origin rejected");
        require(!ws_origin_allowed(cors, "http://localhost.evil.example"), "localhost suffix spoof rejected");
        require(!ws_origin_allowed(cors, "http://127.0.0.1@evil.example"), "userinfo spoof rejected");
    }

    void test_upgrade_and_auth_rules() {
        auto tok = to_u8("0123456789abcdef-secret");
        std::vector<std::string> no_cors;
        constexpr std::string_view kKey = "dGhlIHNhbXBsZSBub25jZQ==";

        // 1. Reject ?token= and ?secret= with 400 Bad Request.
        for (std::string_view q : {"token=abc", "foo=1&secret=xyz", "TOKEN=abc"}) {
            auto raw = std::format("GET /v1/ws?{} HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
                "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\n\r\n", q, kKey);
            auto r = evaluate_ws_upgrade(parse_raw_req(raw), tok, no_cors);
            require(!r.upgraded && r.auth_failed && r.http_response.starts_with("HTTP/1.1 400 "), "reject URL token/secret");
        }

        // 2. Reject cross-site Origin with 403 Forbidden.
        {
            auto raw = std::format("GET /v1/ws HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: https://attacker.test\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\n\r\n", kKey);
            auto r = evaluate_ws_upgrade(parse_raw_req(raw), tok, no_cors);
            require(!r.upgraded && r.http_response.starts_with("HTTP/1.1 403 "), "CSWSH 403 Forbidden");
        }

        // 3. Invalid Bearer header -> 401 Unauthorized before upgrade.
        {
            auto raw = std::format("GET /v1/ws HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer wrong-token-value\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\n\r\n", kKey);
            auto r = evaluate_ws_upgrade(parse_raw_req(raw), tok, no_cors);
            require(!r.upgraded && r.auth_failed && r.http_response.starts_with("HTTP/1.1 401 "), "bad bearer -> 401");
        }

        // 4. Valid Bearer header -> 101 immediately authenticated.
        {
            auto raw = std::format("GET /v1/ws HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer 0123456789abcdef-secret\r\n"
                "Upgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\n\r\n", kKey);
            auto r = evaluate_ws_upgrade(parse_raw_req(raw), tok, no_cors);
            require(r.upgraded && r.authenticated && !r.auth_failed, "header bearer -> 101 authed");
            require(r.http_response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"), "accept header");
        }

        // 5. Browser upgrade (no Authorization header) with token configured -> 101 pending_auth.
        {
            auto raw = std::format("GET /v1/ws HTTP/1.1\r\nHost: 127.0.0.1\r\nOrigin: http://127.0.0.1:9090\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\n\r\n", kKey);
            auto r = evaluate_ws_upgrade(parse_raw_req(raw), tok, no_cors);
            require(r.upgraded && !r.authenticated && !r.auth_failed && r.http_response.starts_with("HTTP/1.1 101 "), "browser -> 101 pending_auth");
        }

        // 6. Missing Upgrade header -> 426 Upgrade Required; no server token -> immediately authed.
        {
            auto r426 = evaluate_ws_upgrade(parse_raw_req("GET /v1/ws HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"), {}, no_cors);
            require(!r426.upgraded && r426.http_response.starts_with("HTTP/1.1 426 "), "missing Upgrade -> 426");
            auto raw = std::format("GET /v1/ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
                "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\n\r\n", kKey);
            auto r_open = evaluate_ws_upgrade(parse_raw_req(raw), {}, no_cors);
            require(r_open.upgraded && r_open.authenticated, "open server -> authed");
        }
    }

    void test_framing_auth_and_multiplexing() {
        auto tok = to_u8("0123456789abcdef-secret");
        auto now = StreamClock::now();
        std::uint64_t authed = 0, unauthed = 0, exp = 0;

        auto snap_fn = [](SnapshotFields, std::optional<std::uint64_t>) -> ControlSnapshot {
            ControlSnapshot s{};
            s.instance = "ws-test";
            s.workers = 2;
            s.listeners.push_back({.upload_bytes = 123, .download_bytes = 456, .active_sessions = 1});
            s.connections.push_back({.id = 7, .listener = 0, .protocol = "socks5", .path = "direct",
                .destination_port = 443, .upload_bytes = 10, .download_bytes = 20, .duration_ms = 50, .can_close = true,
                .target = "example.com:443", .outbound = "direct"});
            return s;
        };
        int log_calls = 0;
        auto cmd_fn = [&](std::span<std::string_view const> args) -> std::expected<std::string, std::string> {
            if (!args.empty() && args[0] == "logs") {
                ++log_calls;
                if (args.size() >= 2 && args[1] == "since=0")
                    return "latest=2 evicted=0\nseq=1 ts=100 level=info domain=core event=101 session=0 msg=\"boot\"\n"
                           "seq=2 ts=200 level=warn domain=route event=102 session=7 msg=\"matched\"\n";
                return "latest=2 evicted=0\n";
            }
            return std::unexpected("unused");
        };

        // 1. Browser first-frame invalid auth -> Close 4401.
        {
            WsPeer p{}; p.auth = WsAuthState::pending_auth; p.auth_deadline = now + kWsAuthTimeout; p.idle_deadline = now + kWsIdleTimeout;
            p.in = make_masked_frame(0x1, R"({"type":"auth","token":"wrong"})");
            process_ws_peer_input(p, tok, now, snap_fn, cmd_fn, authed, unauthed);
            require(p.closing && unauthed == 1, "bad first-frame auth closes peer");
            auto f = pop_server_frame(p.out);
            require(f && close_code_of(*f) == 4401, "close code 4401 on bad auth");
        }

        // 2. Pending auth timeout (5s) -> Close 4401.
        {
            WsPeer p{}; p.auth = WsAuthState::pending_auth; p.auth_deadline = now + kWsAuthTimeout; p.idle_deadline = now + kWsIdleTimeout;
            require(tick_ws_peer(p, now + kWsAuthTimeout + std::chrono::milliseconds(1), snap_fn, cmd_fn, unauthed, exp), "tick queues close");
            require(p.closing && exp == 1, "auth timeout sets closing");
            auto f = pop_server_frame(p.out);
            require(f && close_code_of(*f) == 4401, "close code 4401 on auth timeout");
        }

        // 3. Unmasked client frame -> Close 1002; oversize frame (>64 KiB) -> Close 1009.
        {
            WsPeer p{}; p.auth = WsAuthState::authenticated; p.idle_deadline = now + kWsIdleTimeout;
            p.in = encode_ws_frame(0x1, R"({"type":"ping"})"); // unmasked!
            process_ws_peer_input(p, tok, now, snap_fn, cmd_fn, authed, unauthed);
            auto f = pop_server_frame(p.out);
            require(p.closing && f && close_code_of(*f) == 1002, "unmasked frame -> 1002");
        }
        {
            WsPeer p{}; p.auth = WsAuthState::authenticated; p.idle_deadline = now + kWsIdleTimeout;
            std::string huge_hdr;
            huge_hdr.push_back(static_cast<char>(0x81));
            huge_hdr.push_back(static_cast<char>(0x80 | 127));
            std::uint64_t sz = kMaxWsFrameBytes + 1;
            for (int s = 56; s >= 0; s -= 8) huge_hdr.push_back(static_cast<char>((sz >> s) & 0xffu));
            p.in = huge_hdr;
            process_ws_peer_input(p, tok, now, snap_fn, cmd_fn, authed, unauthed);
            auto f = pop_server_frame(p.out);
            require(p.closing && f && close_code_of(*f) == 1009, "oversize frame -> 1009");
        }

        // 4. Full browser auth + fragmented subscribe + logs/connections/metrics + RFC 6455 Ping/Pong + app ping/pong + unsubscribe + Close.
        {
            WsPeer p{}; p.auth = WsAuthState::pending_auth; p.auth_deadline = now + kWsAuthTimeout;
            p.idle_deadline = now + kWsIdleTimeout; p.last_ping_sent = now;
            p.in += make_masked_frame(0x1, R"({"type":"auth","token":"0123456789abcdef-secret"})");
            // Fragmented subscribe message with interleaved RFC 6455 Ping (RFC 6455 §5.4)!
            p.in += make_masked_frame(0x1, R"({"type":"subscribe","channels":)", false);
            p.in += make_masked_frame(0x9, "hb", true);
            p.in += make_masked_frame(0x0, R"(["logs","connections","metrics"],"since":0,"interval_ms":500})", true);
            p.in += make_masked_frame(0x1, R"({"type":"ping"})");
            process_ws_peer_input(p, tok, now, snap_fn, cmd_fn, authed, unauthed);
            require(!p.closing && p.auth == WsAuthState::authenticated && authed == 1, "browser auth succeeded");
            require(p.channels == (kWsChanLogs | kWsChanConnections | kWsChanMetrics) && p.log_cursor == "2", "subscribed all 3 channels & advanced cursor");

            std::vector<ServerFrame> frames;
            while (auto f = pop_server_frame(p.out)) frames.push_back(std::move(*f));
            require(frames.size() == 8, "expected auth_ok + pong(hb) + subscribed + 2 logs + connections + metrics + app pong");
            require(frames[0].opcode == 0x1 && frames[0].payload == R"({"type":"auth_ok"})", "frame 0 auth_ok");
            require(frames[1].opcode == 0xA && frames[1].payload == "hb", "frame 1 RFC 6455 pong");
            require(frames[2].payload == R"({"type":"subscribed","channels":["logs","connections","metrics"]})", "frame 2 subscribed");
            require(frames[3].payload.contains(R"("type":"log")") && frames[3].payload.contains(R"("message":"boot")"), "frame 3 log 1");
            require(frames[4].payload.contains(R"("type":"log")") && frames[4].payload.contains(R"("message":"matched")"), "frame 4 log 2");
            require(frames[5].payload.contains(R"("type":"connections")") && frames[5].payload.contains("example.com:443"), "frame 5 connections");
            require(frames[6].payload.contains(R"("type":"metrics")") && frames[6].payload.contains(R"("upload_bytes_total":"123")"), "frame 6 metrics");
            require(frames[7].payload == R"({"type":"pong"})", "frame 7 app pong");

            // Reject invalid non-numeric "since" without corrupting log_cursor.
            p.in = make_masked_frame(0x1, R"({"type":"subscribe","channels":["logs"],"since":"abc;drop"})");
            process_ws_peer_input(p, tok, now, snap_fn, cmd_fn, authed, unauthed);
            auto bad_since = pop_server_frame(p.out);
            require(bad_since && bad_since->payload.contains(R"("code":"invalid-since")") && p.log_cursor == "2", "reject non-numeric since");

            // Unsubscribe logs & metrics, verify only connections ticks next, then client Close -> server echoes Close 1000.
            p.in = make_masked_frame(0x1, R"({"type":"unsubscribe","channels":["logs","metrics"]})");
            process_ws_peer_input(p, tok, now, snap_fn, cmd_fn, authed, unauthed);
            auto unsub = pop_server_frame(p.out);
            require(unsub && unsub->payload == R"({"type":"subscribed","channels":["connections"]})", "unsubscribe updates bitmask");
            require(p.channels == kWsChanConnections, "only connections remains");

            require(tick_ws_peer(p, now + std::chrono::milliseconds(600), snap_fn, cmd_fn, unauthed, exp), "tick pushes connections");
            auto pushed = pop_server_frame(p.out);
            require(pushed && pushed->payload.contains(R"("type":"connections")") && !pop_server_frame(p.out).has_value(), "only connections pushed");

            p.in = make_masked_frame(0x8, "\x03\xe8");
            process_ws_peer_input(p, tok, now, snap_fn, cmd_fn, authed, unauthed);
            auto closed = pop_server_frame(p.out);
            require(p.closing && closed && close_code_of(*closed) == 1000, "client Close -> echo Close 1000");
        }
    }

#if !defined(_WIN32)
    void test_live_loopback_http_control_ws() {
        auto tok_path = std::filesystem::temp_directory_path() / ("nexus-w33-ws-tok-" + std::to_string(static_cast<unsigned long>(::getpid())));
        std::ofstream(tok_path, std::ios::binary) << "0123456789abcdef-live-ws\n";
        ::chmod(tok_path.c_str(), 0600);
        struct Rm { std::filesystem::path p; ~Rm() { std::error_code ec; std::filesystem::remove(p, ec); } } rm{tok_path};

        HttpControlServer srv;
        std::uint16_t port = 0;
        for (std::uint16_t cand = 39100; cand < 39200; ++cand) {
            config::ControlHttpConfig cfg{};
            cfg.host = "127.0.0.1"; cfg.port = cand; cfg.bearer_token_file = tok_path.string();
            if (srv.start(cfg)) { port = cand; break; }
        }
        require(port != 0, "bind HttpControlServer for live WS loopback");

        auto snap_fn = [](SnapshotFields, std::optional<std::uint64_t>) -> ControlSnapshot {
            ControlSnapshot s{}; s.instance = "live-ws"; s.workers = 1; return s;
        };
        auto cmd_fn = [](std::span<std::string_view const>) -> std::expected<std::string, std::string> {
            return "latest=1 evicted=0\nseq=1 ts=1 level=info domain=core event=100 session=0 msg=\"live\"\n";
        };

        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        require(fd >= 0, "create client socket");
        struct CloseFd { int fd; ~CloseFd() { if (fd >= 0) ::close(fd); } } guard{fd};
        sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
        ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        require(::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0, "connect loopback");
        timeval tv{1, 0}; ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        std::string req =
            "GET /v1/ws HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer 0123456789abcdef-live-ws\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        require(::send(fd, req.data(), req.size(), 0) == static_cast<ssize_t>(req.size()), "send upgrade");
        for (int i = 0; i < 20; ++i) { srv.poll(snap_fn, cmd_fn); std::this_thread::sleep_for(std::chrono::milliseconds(5)); }
        std::string rx(2048, '\0');
        auto n = ::recv(fd, rx.data(), rx.size(), 0);
        require(n > 0, "recv 101");
        rx.resize(static_cast<std::size_t>(n));
        require(rx.starts_with("HTTP/1.1 101 Switching Protocols\r\n") &&
            rx.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"), "live 101 accept");

        auto sub = make_masked_frame(0x1, R"({"type":"subscribe","channels":["logs","metrics"],"since":0,"interval_ms":500})");
        require(::send(fd, sub.data(), sub.size(), 0) == static_cast<ssize_t>(sub.size()), "send subscribe");
        std::string ws_buf;
        std::vector<ServerFrame> live_frames;
        for (int i = 0; i < 40 && live_frames.size() < 3; ++i) {
            srv.poll(snap_fn, cmd_fn);
            char tmp[2048];
            auto wn = ::recv(fd, tmp, sizeof(tmp), MSG_DONTWAIT);
            if (wn > 0) {
                ws_buf.append(tmp, static_cast<std::size_t>(wn));
                while (auto f = pop_server_frame(ws_buf)) live_frames.push_back(std::move(*f));
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        }
        require(live_frames.size() >= 3, "recv 3 live ws frames");
        require(live_frames[0].payload == R"({"type":"subscribed","channels":["logs","metrics"]})", "live subscribed");
        require(live_frames[1].payload.contains(R"("type":"log")") && live_frames[1].payload.contains(R"("message":"live")"), "live log push");
        require(live_frames[2].payload.contains(R"("type":"metrics")") && live_frames[2].payload.contains(R"("instance":"live-ws")"), "live metrics push");
        srv.stop();
    }
#endif

    void test_log_backlog_cursor_pagination() {
        auto now = StreamClock::now();
        auto snap_fn = [](SnapshotFields, std::optional<std::uint64_t>) -> ControlSnapshot { return {}; };
        auto parse_kv = [](std::span<std::string_view const> args, std::string_view prefix) -> std::uint64_t {
            for (auto a : args) {
                if (!a.starts_with(prefix)) continue;
                std::uint64_t v = 0;
                auto s = a.substr(prefix.size());
                std::from_chars(s.data(), s.data() + s.size(), v);
                return v;
            }
            return 0;
        };
        auto backlog_cmd = [&](std::span<std::string_view const> args) -> std::expected<std::string, std::string> {
            auto since = parse_kv(args, "since=");
            auto limit = parse_kv(args, "limit=");
            if (!limit) limit = 64;
            constexpr std::uint64_t kTotal = 100;
            std::vector<std::uint64_t> seqs;
            for (std::uint64_t seq = since + 1; seq <= kTotal && seqs.size() < limit; ++seq) seqs.push_back(seq);
            std::string out = std::format("latest={} evicted=0 count={}\n", kTotal, seqs.size());
            for (auto seq : seqs)
                out += std::format("seq={} ts={} level=info domain=core event=100 session=0 msg=\"entry-{}\"\n", seq, seq, seq);
            return out;
        };

        // 1. WebSocket log subscription drains 100 un-evicted entries across 2 pages (1..64, 65..100) without skipping.
        {
            WsPeer p{}; p.auth = WsAuthState::authenticated; p.channels = kWsChanLogs;
            p.idle_deadline = now + kWsIdleTimeout; p.last_ping_sent = now;
            push_ws_logs(p, backlog_cmd);
            require(p.log_cursor == "64", "WS page 1 advances cursor to last delivered seq 64, not 100");
            std::vector<std::uint64_t> got;
            while (auto f = pop_server_frame(p.out)) {
                auto pos = f->payload.find(R"("seq":)");
                require(pos != std::string::npos, "WS log frame has seq");
                std::uint64_t seq = 0;
                std::from_chars(f->payload.data() + pos + 6, f->payload.data() + f->payload.size(), seq);
                got.push_back(seq);
            }
            require(got.size() == 64 && got.front() == 1 && got.back() == 64, "WS page 1 delivers 1..64");

            push_ws_logs(p, backlog_cmd);
            require(p.log_cursor == "100", "WS page 2 advances cursor to 100");
            while (auto f = pop_server_frame(p.out)) {
                auto pos = f->payload.find(R"("seq":)");
                require(pos != std::string::npos, "WS page 2 log frame has seq");
                std::uint64_t seq = 0;
                std::from_chars(f->payload.data() + pos + 6, f->payload.data() + f->payload.size(), seq);
                got.push_back(seq);
            }
            require(got.size() == 100 && got.back() == 100, "WS delivers all 100 entries without gaps");
            for (std::uint64_t i = 0; i < 100; ++i) require(got[i] == i + 1, "WS entries strictly contiguous 1..100");

            push_ws_logs(p, backlog_cmd);
            require(p.log_cursor == "100" && p.out.empty(), "WS page 3 caught up");
        }

        // 2. SSE log subscription drains 100 un-evicted entries across 2 pages (1..64, 65..100) without skipping.
        {
            Peer p{}; p.stream = StreamKind::logs; p.last_sse_write = now;
            tick_sse_peer(p, now, snap_fn, backlog_cmd);
            require(p.stream_cursor == "64", "SSE page 1 advances cursor to 64, not 100");
            std::vector<std::uint64_t> got;
            auto collect_sse = [&](std::string_view wire) {
                std::size_t pos = 0;
                while ((pos = wire.find(R"("seq":)", pos)) != std::string_view::npos) {
                    std::uint64_t seq = 0;
                    std::from_chars(wire.data() + pos + 6, wire.data() + wire.size(), seq);
                    got.push_back(seq);
                    pos += 6;
                }
            };
            collect_sse(p.out);
            require(got.size() == 64 && got.front() == 1 && got.back() == 64, "SSE page 1 delivers 1..64");

            tick_sse_peer(p, now + std::chrono::milliseconds(100), snap_fn, backlog_cmd);
            require(p.stream_cursor == "100", "SSE page 2 advances cursor to 100");
            collect_sse(p.out);
            require(got.size() == 100 && got.back() == 100, "SSE delivers all 100 entries without gaps");
            for (std::uint64_t i = 0; i < 100; ++i) require(got[i] == i + 1, "SSE entries strictly contiguous 1..100");
        }

        // 3. Empty evicted/filtered batch advances to latest_seq; future cursor never regresses; partial 60 KiB batch uses last entry seq.
        {
            std::string c1 = "0";
            auto out1 = format_sse_logs("latest=150 evicted=50 count=0\n", c1);
            require(out1.empty() && c1 == "150", "empty evicted batch advances cursor to latest_seq");
            std::string c2 = "500";
            (void)format_sse_logs("latest=150 evicted=0 count=0\n", c2);
            require(c2 == "500", "future cursor never regresses on smaller latest_seq");
            std::string c3 = "0";
            (void)format_sse_logs("latest=100 evicted=0 count=64\nseq=1 ts=1 level=info domain=core event=1 session=0 msg=\"a\"\nseq=30 ts=2 level=info domain=core event=1 session=0 msg=\"b\"\n", c3);
            require(c3 == "30", "truncated wire batch advances cursor to last parsed entry seq 30");
        }
    }
}

int main() {
    test_accept_hash_and_origin();
    test_upgrade_and_auth_rules();
    test_framing_auth_and_multiplexing();
#if !defined(_WIN32)
    test_live_loopback_http_control_ws();
#endif
    test_log_backlog_cursor_pagination();
    std::println("wave33_control_ws_unit: PASS");
    return 0;
}
