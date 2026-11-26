#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

import std;
import desktop.http_control;

namespace {
    int g_failures = 0;

    auto check(bool cond, std::string_view msg) -> void {
        if (!cond) {
            std::cerr << "FAIL: " << msg << "\n";
            ++g_failures;
        }
    }

#ifdef _WIN32
    using SockHandle = SOCKET;
    constexpr SockHandle kBadSock = INVALID_SOCKET;
    auto close_sock_h(SockHandle s) -> void { if (s != INVALID_SOCKET) ::closesocket(s); }
#else
    using SockHandle = int;
    constexpr SockHandle kBadSock = -1;
    auto close_sock_h(SockHandle s) -> void { if (s >= 0) ::close(s); }
#endif

    auto send_bytes(SockHandle s, std::string_view data) -> bool {
        std::size_t off = 0;
        while (off < data.size()) {
#ifdef _WIN32
            auto n = ::send(s, data.data() + off, static_cast<int>(data.size() - off), 0);
#else
            auto n = ::send(s, data.data() + off, data.size() - off, 0);
#endif
            if (n <= 0) return false;
            off += static_cast<std::size_t>(n);
        }
        return true;
    }

    auto recv_exact(SockHandle s, std::string& buf, std::size_t need) -> bool {
        char tmp[1024];
        while (buf.size() < need) {
#ifdef _WIN32
            auto n = ::recv(s, tmp, static_cast<int>(sizeof(tmp)), 0);
#else
            auto n = ::recv(s, tmp, sizeof(tmp), 0);
#endif
            if (n <= 0) return false;
            buf.append(tmp, static_cast<std::size_t>(n));
        }
        return true;
    }

    auto make_server_frame(std::uint8_t opcode, std::string_view payload, bool fin = true) -> std::string {
        std::string out;
        out.push_back(static_cast<char>((fin ? 0x80u : 0x00u) | (opcode & 0x0fu)));
        if (payload.size() < 126u) {
            out.push_back(static_cast<char>(payload.size()));
        } else if (payload.size() <= 0xffffu) {
            out.push_back(static_cast<char>(126u));
            out.push_back(static_cast<char>((payload.size() >> 8) & 0xffu));
            out.push_back(static_cast<char>(payload.size() & 0xffu));
        } else {
            out.push_back(static_cast<char>(127u));
            std::uint64_t n = static_cast<std::uint64_t>(payload.size());
            for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<char>((n >> shift) & 0xffu));
        }
        out.append(payload);
        return out;
    }

    struct ClientFrameRead {
        bool ok = false;
        bool masked = false;
        std::uint8_t opcode = 0;
        std::string payload;
    };

    auto read_client_frame(SockHandle s, std::string& buf) -> ClientFrameRead {
        ClientFrameRead r{};
        if (!recv_exact(s, buf, 2)) return r;
        auto b0 = static_cast<std::uint8_t>(buf[0]);
        auto b1 = static_cast<std::uint8_t>(buf[1]);
        r.opcode = b0 & 0x0fu;
        r.masked = (b1 & 0x80u) != 0;
        std::uint64_t len = b1 & 0x7fu;
        std::size_t hdr = 2;
        if (len == 126) {
            if (!recv_exact(s, buf, 4)) return r;
            len = (std::uint64_t{static_cast<std::uint8_t>(buf[2])} << 8) | static_cast<std::uint8_t>(buf[3]);
            hdr = 4;
        }
        std::size_t need = hdr + (r.masked ? 4u : 0u) + static_cast<std::size_t>(len);
        if (!recv_exact(s, buf, need)) return r;
        r.payload.resize(static_cast<std::size_t>(len));
        for (std::size_t i = 0; i < r.payload.size(); ++i) {
            auto byte = static_cast<std::uint8_t>(buf[hdr + (r.masked ? 4u : 0u) + i]);
            if (r.masked) byte ^= static_cast<std::uint8_t>(buf[hdr + (i & 3u)]);
            r.payload[i] = static_cast<char>(byte);
        }
        buf.erase(0, need);
        r.ok = true;
        return r;
    }

    auto extract_sec_ws_key(std::string_view req) -> std::string {
        auto pos = req.find("Sec-WebSocket-Key:");
        if (pos == std::string_view::npos) return {};
        pos += 18;
        auto eol = req.find("\r\n", pos);
        auto v = req.substr(pos, eol == std::string_view::npos ? req.size() - pos : eol - pos);
        while (!v.empty() && v.front() == ' ') v.remove_prefix(1);
        return std::string(v);
    }

    struct LoopbackWsMock {
        SockHandle listen_fd = kBadSock;
        std::uint16_t port = 0;
        std::thread thr;

        explicit LoopbackWsMock(std::function<void(SockHandle)> session_fn) {
#ifdef _WIN32
            WSADATA wsa{};
            (void)::WSAStartup(MAKEWORD(2, 2), &wsa);
            listen_fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
            listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
            int one = 1;
            (void)::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#endif
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
            addr.sin_port = 0;
            if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || ::listen(listen_fd, 4) != 0) return;
            socklen_t len = sizeof(addr);
            if (::getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0) port = ntohs(addr.sin_port);
            thr = std::thread([this, fn = std::move(session_fn)] {
                auto c = ::accept(listen_fd, nullptr, nullptr);
                if (c != kBadSock) {
                    fn(c);
                    close_sock_h(c);
                }
            });
        }
        auto join() -> void {
            if (thr.joinable()) thr.join();
        }
        ~LoopbackWsMock() {
            close_sock_h(listen_fd);
            join();
        }
    };
}

auto main() -> int {
    // 1. RFC 6455 §1.3 SHA-1 + Base64 accept key test vector (GUID ...47DA...)
    check(desktop::compute_ws_accept_key("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
          "RFC 6455 §1.3 Sec-WebSocket-Accept vector");

    // 2. Envelope & status metrics JSON helpers
    {
        auto ev = desktop::parse_ws_envelope_json(R"({"type":"metrics","data":{"control_generation":"7","active_sessions":4,"upload_bytes_total":"1024","download_bytes_total":"8192"}})");
        check(ev && ev->type == "metrics", "parse_ws_envelope_json metrics");
        auto m = desktop::parse_status_metrics_json(ev->data_json);
        check(m && m->control_generation == 7 && m->active_sessions == 4 && m->upload_bytes == 1024 && m->download_bytes == 8192,
              "parse_status_metrics_json fields");
    }

    // 3. Loopback-only guard rejects non-loopback host immediately
    {
        desktop::HttpControlClient remote("192.168.1.50", 19090, "secret");
        auto res = remote.stream_ws({"logs"}, [](desktop::WsEvent const&) { return true; });
        check(!res.has_value(), "non-loopback WS host rejected");
    }

    // 4. Live loopback RFC 6455 handshake, Bearer header, masked subscribe, Ping->Pong, fragmented frame, Close 1000
    {
        bool saw_req_ok = false, saw_sub_ok = false, saw_pong_ok = false;
        LoopbackWsMock mock([&](SockHandle c) {
            std::string rx;
            while (!rx.contains("\r\n\r\n")) {
                if (!recv_exact(c, rx, rx.size() + 1)) return;
            }
            auto sep = rx.find("\r\n\r\n");
            auto req = rx.substr(0, sep + 2);
            rx.erase(0, sep + 4);
            saw_req_ok = req.starts_with("GET /v1/ws HTTP/1.1\r\n") &&
                         !req.contains("token=") && !req.contains("secret=") &&
                         req.contains("Authorization: Bearer ws-secret-tok\r\n");
            auto accept = desktop::compute_ws_accept_key(extract_sec_ws_key(req));
            auto resp = std::format("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", accept);
            (void)send_bytes(c, resp);

            auto sub = read_client_frame(c, rx);
            saw_sub_ok = sub.ok && sub.masked && sub.opcode == 0x1 &&
                         sub.payload.contains("\"type\":\"subscribe\"") &&
                         sub.payload.contains("\"logs\"") && sub.payload.contains("\"connections\"") && sub.payload.contains("\"metrics\"");

            // Send Ping -> expect masked Pong with same payload
            (void)send_bytes(c, make_server_frame(0x9u, "ping42"));
            auto pong = read_client_frame(c, rx);
            saw_pong_ok = pong.ok && pong.masked && pong.opcode == 0xAu && pong.payload == "ping42";

            // Send log + fragmented connections + metrics + clean Close 1000
            (void)send_bytes(c, make_server_frame(0x1u, R"({"type":"log","data":{"seq":55,"level":"info","domain":"route","message":"ws live"}})"));
            std::string conn_msg = R"({"type":"connections","data":{"connections":[{"id":"9","protocol":"tcp/tls","path":"proxy","target":"example.com:443","outbound":"hk-01","upload_bytes":"100","download_bytes":"200"}]}})";
            (void)send_bytes(c, make_server_frame(0x1u, conn_msg.substr(0, 40), false));
            (void)send_bytes(c, make_server_frame(0x0u, conn_msg.substr(40), true));
            (void)send_bytes(c, make_server_frame(0x1u, R"({"type":"metrics","data":{"active_sessions":2,"upload_bytes_total":"500","download_bytes_total":"1500"}})"));
            char close_body[2]{0x03, static_cast<char>(0xe8)};
            (void)send_bytes(c, make_server_frame(0x8u, std::string_view(close_body, 2)));
        });

        desktop::HttpControlClient cli("127.0.0.1", mock.port, "ws-secret-tok");
        bool connected = false;
        std::vector<desktop::WsEvent> evs;
        auto res = cli.stream_ws({"logs", "connections", "metrics"}, [&](desktop::WsEvent const& ev) {
            evs.push_back(ev);
            return true;
        }, {}, 0, 1000, std::chrono::milliseconds{2000}, std::chrono::milliseconds{50}, [&] { connected = true; });
        mock.join();
        check(res.has_value() && connected, "WS loopback stream completed cleanly");
        check(saw_req_ok, "WS zero-URL-token Bearer header verified");
        check(saw_sub_ok, "WS masked subscribe payload verified");
        check(saw_pong_ok, "WS masked Ping->Pong echo verified");
        check(evs.size() == 3 && evs[0].type == "log" && evs[1].type == "connections" && evs[2].type == "metrics",
              "WS received log, fragmented connections, and metrics events");
    }

    // 5. Upgrade rejection (404) returns error cleanly (enabling transparent SSE fallback)
    {
        LoopbackWsMock mock([](SockHandle c) {
            std::string rx;
            while (!rx.contains("\r\n\r\n")) { if (!recv_exact(c, rx, rx.size() + 1)) return; }
            (void)send_bytes(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        });
        desktop::HttpControlClient cli("127.0.0.1", mock.port);
        auto res = cli.stream_ws({"logs"}, [](desktop::WsEvent const&) { return true; });
        check(!res.has_value() && res.error().contains("404"), "WS 404 rejection triggers clean error for SSE fallback");
    }

    // 6. Oversized incoming frame (> 256 KiB) fails closed and sends Close 1009
    {
        std::uint16_t close_code = 0;
        LoopbackWsMock mock([&](SockHandle c) {
            std::string rx;
            while (!rx.contains("\r\n\r\n")) { if (!recv_exact(c, rx, rx.size() + 1)) return; }
            auto sep = rx.find("\r\n\r\n");
            auto accept = desktop::compute_ws_accept_key(extract_sec_ws_key(rx.substr(0, sep)));
            rx.erase(0, sep + 4);
            (void)send_bytes(c, std::format("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", accept));
            (void)read_client_frame(c, rx);
            // Send 300 KiB frame header (client aborts immediately upon seeing 300 KiB length)
            std::string big_hdr;
            big_hdr.push_back(static_cast<char>(0x81u));
            big_hdr.push_back(static_cast<char>(127u));
            std::uint64_t big_len = 300u * 1024u;
            for (int shift = 56; shift >= 0; shift -= 8) big_hdr.push_back(static_cast<char>((big_len >> shift) & 0xffu));
            (void)send_bytes(c, big_hdr);
            auto cf = read_client_frame(c, rx);
            if (cf.ok && cf.opcode == 0x8u && cf.payload.size() >= 2) {
                close_code = static_cast<std::uint16_t>((static_cast<std::uint8_t>(cf.payload[0]) << 8) |
                                                        static_cast<std::uint8_t>(cf.payload[1]));
            }
        });
        desktop::HttpControlClient cli("127.0.0.1", mock.port);
        auto res = cli.stream_ws({"logs"}, [](desktop::WsEvent const&) { return true; });
        mock.join();
        check(!res.has_value() && close_code == 1009u, "WS oversize frame rejected with Close 1009");
    }

    // 7. Stalled pre-upgrade handshake enforces connect_timeout deadline instead of spinning forever
    {
        LoopbackWsMock mock([](SockHandle c) {
            std::string rx;
            while (!rx.contains("\r\n\r\n")) { if (!recv_exact(c, rx, rx.size() + 1)) return; }
            char drain[64];
            while (true) {
#ifdef _WIN32
                auto n = ::recv(c, drain, static_cast<int>(sizeof(drain)), 0);
#else
                auto n = ::recv(c, drain, sizeof(drain), 0);
#endif
                if (n <= 0) break;
            }
        });
        desktop::HttpControlClient cli("127.0.0.1", mock.port);
        auto t0 = std::chrono::steady_clock::now();
        auto res = cli.stream_ws({"logs"}, [](desktop::WsEvent const&) { return true; },
                                 {}, 0, 1000, std::chrono::milliseconds{150}, std::chrono::milliseconds{25});
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);
        check(!res.has_value() && res.error().contains("timed out") && elapsed < std::chrono::milliseconds{2000},
              "WS handshake deadline aborts stalled upgrade cleanly");
    }

    // 8. Pre-upgrade TCP EOF returns error instead of silent success
    {
        LoopbackWsMock mock([](SockHandle c) {
            std::string rx;
            while (!rx.contains("\r\n\r\n")) { if (!recv_exact(c, rx, rx.size() + 1)) return; }
            (void)send_bytes(c, "HTTP/1.1 101 Switching Protocols\r\n");
        });
        desktop::HttpControlClient cli("127.0.0.1", mock.port);
        auto res = cli.stream_ws({"logs"}, [](desktop::WsEvent const&) { return true; });
        check(!res.has_value() && res.error().contains("closed before upgrade"),
              "WS pre-upgrade EOF returns explicit error");
    }

    // 9. RFC 6455 §5.1 masked server frame rejected immediately with Close 1002
    {
        std::uint16_t close_code = 0;
        LoopbackWsMock mock([&](SockHandle c) {
            std::string rx;
            while (!rx.contains("\r\n\r\n")) { if (!recv_exact(c, rx, rx.size() + 1)) return; }
            auto sep = rx.find("\r\n\r\n");
            auto accept = desktop::compute_ws_accept_key(extract_sec_ws_key(rx.substr(0, sep + 2)));
            rx.erase(0, sep + 4);
            (void)send_bytes(c, std::format("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n", accept));
            (void)read_client_frame(c, rx);
            constexpr std::uint8_t mask[4]{0x11u, 0x22u, 0x33u, 0x44u};
            std::string_view plain = "hello";
            std::string bad;
            bad.push_back(static_cast<char>(0x81u));
            bad.push_back(static_cast<char>(0x80u | plain.size()));
            for (auto m : mask) bad.push_back(static_cast<char>(m));
            for (std::size_t i = 0; i < plain.size(); ++i) {
                bad.push_back(static_cast<char>(static_cast<std::uint8_t>(plain[i]) ^ mask[i & 3u]));
            }
            (void)send_bytes(c, bad);
            auto cf = read_client_frame(c, rx);
            if (cf.ok && cf.opcode == 0x8u && cf.payload.size() >= 2) {
                close_code = static_cast<std::uint16_t>((static_cast<std::uint8_t>(cf.payload[0]) << 8) |
                                                        static_cast<std::uint8_t>(cf.payload[1]));
            }
        });
        desktop::HttpControlClient cli("127.0.0.1", mock.port);
        auto res = cli.stream_ws({"logs"}, [](desktop::WsEvent const&) { return true; });
        mock.join();
        check(!res.has_value() && res.error().contains("protocol error") && close_code == 1002u,
              "WS masked server frame rejected with Close 1002");
    }

    if (g_failures > 0) {
        std::cerr << g_failures << " WS test failure(s).\n";
        return 1;
    }
    std::cout << "ALL WAVE 33 DESKTOP RFC 6455 WS TESTS PASSED\n";
    return 0;
}
