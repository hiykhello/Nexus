// Cross-platform loopback RFC 6455 multiplexed WebSocket client (/v1/ws) for Nexus Control API.
module;

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

module desktop.http_control;

import std;
import desktop.mini_json;

#include "http_ws_codec.hpp"

namespace desktop {
    using namespace ws_detail;

    auto compute_ws_accept_key(std::string_view sec_ws_key) -> std::string { return compute_accept(sec_ws_key); }
    auto parse_ws_envelope_json(std::string_view json) -> std::optional<WsEvent> { return parse_envelope(json); }
    auto parse_status_metrics_json(std::string_view json) -> std::optional<MetricsSnapshot> { return parse_metrics(json); }

    auto HttpControlClient::stream_ws(this HttpControlClient const& self,
                                      std::vector<std::string> const& channels,
                                      std::function<bool(WsEvent const&)> on_event,
                                      std::stop_token stop,
                                      std::uint64_t since,
                                      std::uint32_t interval_ms,
                                      std::chrono::milliseconds connect_timeout,
                                      std::chrono::milliseconds poll_interval,
                                      std::function<void()> on_connected)
        -> std::expected<void, std::string> {
        std::string host, bearer_token;
        std::uint16_t port = 0;
        {
            std::scoped_lock lk(self.mu_);
            host = self.host_;
            port = self.port_;
            bearer_token = self.bearer_token_;
        }
        if (host.empty() || port == 0 || !is_loopback_ws_host(host) || has_ws_forbidden_ctrl(bearer_token)) {
            return std::unexpected("WS control client requires loopback host");
        }
        if (channels.empty()) return std::unexpected("WS subscribe requires non-empty channels");

#ifdef _WIN32
        static bool const wsa_ready = [] { WSADATA wsa{}; return ::WSAStartup(MAKEWORD(2, 2), &wsa) == 0; }();
        if (!wsa_ready) return std::unexpected("WSAStartup failed");
#endif
        std::string connect_host = (host.size() >= 2 && host.front() == '[' && host.back() == ']')
            ? host.substr(1, host.size() - 2) : host;
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        auto port_str = std::to_string(port);
        if (::getaddrinfo(connect_host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
            return std::unexpected("failed to resolve WS loopback host");
        }

#ifdef _WIN32
        SOCKET fd = INVALID_SOCKET;
        for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
            SOCKET s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (s == INVALID_SOCKET) continue;
            DWORD ms = static_cast<DWORD>(connect_timeout.count());
            ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char const*>(&ms), sizeof(ms));
            ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char const*>(&ms), sizeof(ms));
            if (::connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen)) == 0) { fd = s; break; }
            ::closesocket(s);
        }
        ::freeaddrinfo(res);
        if (fd == INVALID_SOCKET) return std::unexpected("WS connect failed");
        auto close_sock = [&] { ::closesocket(fd); };
#else
        int fd = -1;
        for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
#ifdef SOCK_CLOEXEC
            int s = ::socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
#else
            int s = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (s >= 0) (void)::fcntl(s, F_SETFD, FD_CLOEXEC);
#endif
            if (s < 0) continue;
#ifdef SO_NOSIGPIPE
            int one = 1;
            (void)::setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
            timeval tv{};
            tv.tv_sec = static_cast<time_t>(connect_timeout.count() / 1000);
            tv.tv_usec = static_cast<suseconds_t>((connect_timeout.count() % 1000) * 1000);
            ::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            ::setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            int rc = 0;
            do { rc = ::connect(s, ai->ai_addr, ai->ai_addrlen); } while (rc != 0 && errno == EINTR);
            if (rc == 0) { fd = s; break; }
            ::close(s);
        }
        ::freeaddrinfo(res);
        if (fd < 0) return std::unexpected("WS connect failed");
        auto close_sock = [&] { ::close(fd); };
#endif

        auto send_all = [&](std::string_view data) -> bool {
            std::size_t off = 0;
            while (off < data.size()) {
#ifdef _WIN32
                auto n = ::send(fd, data.data() + off, static_cast<int>(data.size() - off), 0);
#else
#ifdef MSG_NOSIGNAL
                constexpr int kFlags = MSG_NOSIGNAL;
#else
                constexpr int kFlags = 0;
#endif
                auto n = ::send(fd, data.data() + off, data.size() - off, kFlags);
                if (n < 0 && errno == EINTR) continue;
#endif
                if (n <= 0) return false;
                off += static_cast<std::size_t>(n);
            }
            return true;
        };

        auto ws_key = generate_ws_key();
        auto expected_accept = compute_ws_accept_key(ws_key);
        std::string host_hdr = (connect_host.contains(':'))
            ? std::format("[{}]:{}", connect_host, port)
            : std::format("{}:{}", connect_host, port);
        std::string req = std::format(
            "GET /v1/ws HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            "Sec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n",
            host_hdr, ws_key);
        if (!bearer_token.empty()) req += std::format("Authorization: Bearer {}\r\n", bearer_token);
        req += "\r\n";

        if (!send_all(req)) { close_sock(); return std::unexpected("WS upgrade send failed"); }

        int const wait_ms = static_cast<int>(std::clamp<long long>(poll_interval.count(), 25, 1000));
        auto poll_read = [&](int timeout_ms) -> int {
#ifdef _WIN32
            WSAPOLLFD pfd{};
            pfd.fd = fd;
            pfd.events = POLLRDNORM;
            return ::WSAPoll(&pfd, 1, timeout_ms);
#else
            pollfd pfd{};
            pfd.fd = fd;
            pfd.events = POLLIN;
            int prc = ::poll(&pfd, 1, timeout_ms);
            return (prc < 0 && errno == EINTR) ? 0 : prc;
#endif
        };

        std::string rx, frag_buf;
        bool upgraded = false, frag_active = false;
        char buf[4096];
        auto const handshake_deadline = std::chrono::steady_clock::now() + std::max(connect_timeout, std::chrono::milliseconds{50});

        while (!stop.stop_requested()) {
            int poll_ms = wait_ms;
            if (!upgraded) {
                auto now = std::chrono::steady_clock::now();
                if (now >= handshake_deadline) { close_sock(); return std::unexpected("WS handshake timed out"); }
                poll_ms = static_cast<int>(std::clamp<long long>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(handshake_deadline - now).count(), 1, wait_ms));
            }
            int prc = poll_read(poll_ms);
            if (prc == 0) {
                if (!upgraded && std::chrono::steady_clock::now() >= handshake_deadline) { close_sock(); return std::unexpected("WS handshake timed out"); }
                continue;
            }
            if (prc < 0) { close_sock(); return std::unexpected("WS poll failed"); }
#ifdef _WIN32
            auto n = ::recv(fd, buf, static_cast<int>(sizeof(buf)), 0);
#else
            auto n = ::recv(fd, buf, sizeof(buf), 0);
            if (n < 0 && errno == EINTR) continue;
#endif
            if (n == 0) {
                close_sock();
                return (!upgraded && !stop.stop_requested()) ? std::unexpected("WS closed before upgrade") : std::expected<void, std::string>{};
            }
            if (n < 0) { close_sock(); return std::unexpected("WS recv failed"); }
            rx.append(buf, static_cast<std::size_t>(n));

            if (!upgraded) {
                if (rx.size() > 32u * 1024u) { close_sock(); return std::unexpected("WS handshake too large"); }
                auto sep = rx.find("\r\n\r\n");
                if (sep == std::string::npos) continue;
                auto hdrs = std::string_view(rx).substr(0, sep);
                auto first_eol = hdrs.find("\r\n");
                auto status_line = first_eol == std::string_view::npos ? hdrs : hdrs.substr(0, first_eol);
                int code = 0;
                if (auto sp = status_line.find(' '); sp != std::string_view::npos) {
                    auto cs = status_line.substr(sp + 1);
                    std::from_chars(cs.data(), cs.data() + cs.size(), code);
                }
                auto accept_hdr = header_value_ci(hdrs, "sec-websocket-accept");
                if (code != 101 ||
                    !header_has_token_ci(header_value_ci(hdrs, "upgrade"), "websocket") ||
                    !header_has_token_ci(header_value_ci(hdrs, "connection"), "upgrade") ||
                    !ws_ct_equal(accept_hdr, expected_accept)) {
                    close_sock();
                    return std::unexpected(std::format("WS upgrade rejected (HTTP {})", code));
                }
                rx.erase(0, sep + 4);
                upgraded = true;

                std::string sub = "{\"type\":\"subscribe\",\"channels\":[";
                for (std::size_t i = 0; i < channels.size(); ++i) {
                    if (i > 0) sub.push_back(',');
                    sub += std::format("\"{}\"", json_escape(channels[i]));
                }
                auto clamped_ms = std::clamp<std::uint32_t>(interval_ms, 200u, 10000u);
                sub += std::format("],\"since\":{},\"interval_ms\":{}}}", since, clamped_ms);
                if (!send_all(encode_ws_client_frame(0x1u, sub))) {
                    close_sock();
                    return std::unexpected("WS subscribe send failed");
                }
                if (on_connected && !stop.stop_requested()) on_connected();
            }

            while (upgraded && !stop.stop_requested()) {
                ServerFrame frame{};
                auto st = decode_ws_server_frame(rx, frame, kMaxWsFrameBytes);
                if (st == FrameStatus::need_more) break;
                if (st == FrameStatus::too_large) {
                    (void)send_all(encode_ws_client_close(1009u));
                    close_sock();
                    return std::unexpected("WS frame exceeds 256 KiB cap");
                }
                if (st == FrameStatus::protocol_error) {
                    (void)send_all(encode_ws_client_close(1002u));
                    close_sock();
                    return std::unexpected("WS protocol error");
                }
                if (frame.opcode == 0x8u) {
                    (void)send_all(encode_ws_client_close(1000u));
                    close_sock();
                    return {};
                }
                if (frame.opcode == 0x9u) {
                    if (!send_all(encode_ws_client_frame(0xAu, frame.payload))) {
                        close_sock();
                        return std::unexpected("WS pong send failed");
                    }
                    continue;
                }
                if (frame.opcode == 0xAu) continue;
                std::string full_msg;
                if (frame.opcode == 0x0u) {
                    if (!frag_active) { (void)send_all(encode_ws_client_close(1002u)); close_sock(); return std::unexpected("WS unexpected continuation"); }
                    if (frag_buf.size() + frame.payload.size() > kMaxWsFrameBytes) {
                        (void)send_all(encode_ws_client_close(1009u)); close_sock(); return std::unexpected("WS fragmented message exceeds 256 KiB");
                    }
                    frag_buf.append(frame.payload);
                    if (!frame.fin) continue;
                    frag_active = false;
                    full_msg = std::move(frag_buf);
                    frag_buf.clear();
                } else if (frame.opcode == 0x1u) {
                    if (frag_active) { (void)send_all(encode_ws_client_close(1002u)); close_sock(); return std::unexpected("WS interleaved fragment"); }
                    if (!frame.fin) { frag_active = true; frag_buf = std::move(frame.payload); continue; }
                    full_msg = std::move(frame.payload);
                } else {
                    continue;
                }
                if (auto ev = parse_ws_envelope_json(full_msg)) {
                    if (on_event && !on_event(*ev)) {
                        (void)send_all(encode_ws_client_close(1000u));
                        close_sock();
                        return {};
                    }
                }
            }
        }
        if (upgraded && stop.stop_requested()) (void)send_all(encode_ws_client_close(1000u));
        close_sock();
        return {};
    }
}
