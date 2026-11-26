// Cross-platform HTTP/1.1 Server-Sent Events (SSE) client & incremental frame parser.
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

namespace desktop {
    namespace {
        auto has_sse_forbidden(std::string_view sv, bool forbid_space) noexcept -> bool {
            for (unsigned char c : sv) {
                if (c == '\r' || c == '\n' || c == '\0' || c < 0x20 || c == 0x7F) return true;
                if (forbid_space && (c == ' ' || c == '\t')) return true;
            }
            return false;
        }

        auto ascii_iequals(std::string_view a, std::string_view b) noexcept -> bool {
            if (a.size() != b.size()) return false;
            for (std::size_t i = 0; i < a.size(); ++i) {
                if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
                    return false;
            }
            return true;
        }

        auto contains_ci(std::string_view hay, std::string_view needle) noexcept -> bool {
            if (needle.empty() || hay.size() < needle.size()) return false;
            for (std::size_t i = 0; i + needle.size() <= hay.size(); ++i) {
                if (ascii_iequals(hay.substr(i, needle.size()), needle)) return true;
            }
            return false;
        }

        // Decodes HTTP/1.1 Transfer-Encoding: chunked body bytes incrementally with strict size caps.
        struct ChunkedDecoder {
            static constexpr std::size_t kMaxChunkHeaderBytes = 4096;
            static constexpr std::size_t kMaxChunkSize = 4u * 1024u * 1024u;
            static constexpr std::size_t kMaxPendingBufBytes = 512u * 1024u;

            std::string buf;
            std::size_t remaining = 0;
            bool in_chunk = false;
            bool done = false;

            auto decode(std::string_view input, std::string& out) -> bool {
                if (done) return true;
                if (input.size() > kMaxPendingBufBytes || buf.size() > kMaxPendingBufBytes - input.size()) return false;
                buf.append(input);
                for (;;) {
                    if (done) return true;
                    if (!in_chunk) {
                        auto crlf = buf.find("\r\n");
                        if (crlf == std::string::npos) {
                            return buf.size() <= kMaxChunkHeaderBytes;
                        }
                        if (crlf > kMaxChunkHeaderBytes) return false;
                        auto size_sv = std::string_view(buf).substr(0, crlf);
                        if (auto semi = size_sv.find(';'); semi != std::string_view::npos) size_sv = size_sv.substr(0, semi);
                        while (!size_sv.empty() && size_sv.front() == ' ') size_sv.remove_prefix(1);
                        while (!size_sv.empty() && size_sv.back() == ' ') size_sv.remove_suffix(1);
                        std::size_t sz = 0;
                        auto [ptr, ec] = std::from_chars(size_sv.data(), size_sv.data() + size_sv.size(), sz, 16);
                        if (ec != std::errc{} || ptr != size_sv.data() + size_sv.size() || sz > kMaxChunkSize) return false;
                        buf.erase(0, crlf + 2);
                        if (sz == 0) { done = true; return true; }
                        remaining = sz;
                        in_chunk = true;
                    }
                    if (buf.size() < remaining + 2) {
                        std::size_t take = std::min(buf.size(), remaining);
                        if (take > 0) {
                            out.append(buf, 0, take);
                            buf.erase(0, take);
                            remaining -= take;
                        }
                        return true;
                    }
                    if (remaining > 0) {
                        out.append(buf, 0, remaining);
                        buf.erase(0, remaining);
                        remaining = 0;
                    }
                    if (buf.size() >= 2 && buf[0] == '\r' && buf[1] == '\n') {
                        buf.erase(0, 2);
                        in_chunk = false;
                    } else if (buf.size() >= 2) {
                        return false;
                    }
                }
            }
        };
    }

    auto SseFrameParser::feed(this SseFrameParser& self, std::string_view chunk,
                              std::function<bool(SseEvent const&)> const& on_event) -> bool {
        constexpr std::size_t kMaxEventNameBytes = 1024;
        for (char c : chunk) {
            if (c == '\n') {
                if (!self.line_buf_.empty() && self.line_buf_.back() == '\r') self.line_buf_.pop_back();
                if (self.line_buf_.empty()) {
                    if (self.has_data_ && !self.frame_overflow_) {
                        SseEvent ev{self.cur_event_.empty() ? std::string("message") : std::move(self.cur_event_),
                                    std::move(self.cur_data_)};
                        self.cur_event_.clear();
                        self.cur_data_.clear();
                        self.has_data_ = false;
                        self.frame_overflow_ = false;
                        self.line_overflow_ = false;
                        if (on_event && !on_event(ev)) return false;
                    } else {
                        self.cur_event_.clear();
                        self.cur_data_.clear();
                        self.has_data_ = false;
                        self.frame_overflow_ = false;
                        self.line_overflow_ = false;
                    }
                } else if (self.line_buf_.front() != ':') {
                    if (self.line_overflow_) {
                        self.frame_overflow_ = true;
                        self.cur_data_.clear();
                    } else {
                        auto colon = self.line_buf_.find(':');
                        auto field = colon == std::string::npos
                            ? std::string_view(self.line_buf_)
                            : std::string_view(self.line_buf_).substr(0, colon);
                        std::string_view val{};
                        if (colon != std::string::npos) {
                            val = std::string_view(self.line_buf_).substr(colon + 1);
                            if (!val.empty() && val.front() == ' ') val.remove_prefix(1);
                        }
                        if (field == "event") {
                            if (!self.frame_overflow_) {
                                self.cur_event_.assign(val.substr(0, std::min(val.size(), kMaxEventNameBytes)));
                            }
                        } else if (field == "data") {
                            if (!self.frame_overflow_) {
                                std::size_t const add_len = val.size() + (self.has_data_ ? 1u : 0u);
                                if (add_len > kMaxFrameBytes || self.cur_data_.size() > kMaxFrameBytes - add_len) {
                                    self.frame_overflow_ = true;
                                    self.cur_data_.clear();
                                } else {
                                    if (self.has_data_) self.cur_data_.push_back('\n');
                                    self.cur_data_.append(val);
                                }
                            }
                            self.has_data_ = true;
                        }
                    }
                }
                self.line_buf_.clear();
                self.line_overflow_ = false;
            } else if (self.line_buf_.size() < kMaxFrameBytes) {
                self.line_buf_.push_back(c);
            } else if (!self.line_buf_.empty() && self.line_buf_.front() != ':') {
                self.line_overflow_ = true;
            }
        }
        return true;
    }

    auto SseFrameParser::finish(this SseFrameParser& self,
                                std::function<bool(SseEvent const&)> const& on_event) -> bool {
        if (!self.line_buf_.empty()) {
            if (!self.feed("\n", on_event)) return false;
        }
        if (self.has_data_) return self.feed("\n", on_event);
        return true;
    }

    auto HttpControlClient::stream_sse(this HttpControlClient const& self,
                                       std::string_view path,
                                       std::function<bool(SseEvent const&)> on_event,
                                       std::stop_token stop,
                                       std::chrono::milliseconds connect_timeout,
                                       std::chrono::milliseconds poll_interval,
                                       std::function<void()> on_connected)
        -> std::expected<void, std::string> {
        std::string host;
        std::uint16_t port = 0;
        std::string bearer_token;
        {
            std::scoped_lock lk(self.mu_);
            host = self.host_;
            port = self.port_;
            bearer_token = self.bearer_token_;
        }
        if (host.empty() || port == 0 || path.empty() || path.front() != '/' ||
            has_sse_forbidden(path, true) || has_sse_forbidden(host, true) || has_sse_forbidden(bearer_token, false)) {
            return std::unexpected("invalid SSE control request");
        }
        std::string host_hdr = (host.contains(':') && !host.starts_with('['))
            ? std::format("[{}]:{}", host, port)
            : std::format("{}:{}", host, port);
        std::string req = std::format(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n",
            path, host_hdr);
        if (!bearer_token.empty()) req += std::format("Authorization: Bearer {}\r\n", bearer_token);
        req += "\r\n";

#ifdef _WIN32
        static bool const wsa_ready = [] { WSADATA wsa{}; return ::WSAStartup(MAKEWORD(2, 2), &wsa) == 0; }();
        if (!wsa_ready) return std::unexpected("WSAStartup failed");
#endif
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        auto port_str = std::to_string(port);
        if (::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
            return std::unexpected("failed to resolve SSE control host");
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
        if (fd == INVALID_SOCKET) return std::unexpected("SSE connect failed");
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
        if (fd < 0) return std::unexpected("SSE connect failed");
        auto close_sock = [&] { ::close(fd); };
#endif

        std::size_t sent = 0;
        while (sent < req.size()) {
            if (stop.stop_requested()) { close_sock(); return {}; }
#ifdef _WIN32
            auto n = ::send(fd, req.data() + sent, static_cast<int>(req.size() - sent), 0);
#else
#ifdef MSG_NOSIGNAL
            constexpr int kSendFlags = MSG_NOSIGNAL;
#else
            constexpr int kSendFlags = 0;
#endif
            auto n = ::send(fd, req.data() + sent, req.size() - sent, kSendFlags);
            if (n < 0 && errno == EINTR) continue;
#endif
            if (n <= 0) { close_sock(); return std::unexpected("SSE send failed"); }
            sent += static_cast<std::size_t>(n);
        }

        int const wait_ms = static_cast<int>(std::clamp<long long>(poll_interval.count(), 25, 1000));
        std::string hdr_buf;
        bool headers_done = false;
        bool is_chunked = false;
        ChunkedDecoder chunked{};
        SseFrameParser parser{};
        char buf[4096];

        while (!stop.stop_requested()) {
#ifdef _WIN32
            WSAPOLLFD pfd{};
            pfd.fd = fd;
            pfd.events = POLLRDNORM;
            int prc = ::WSAPoll(&pfd, 1, wait_ms);
            if (prc == 0) continue;
            if (prc < 0) { close_sock(); return std::unexpected("SSE poll failed"); }
#else
            pollfd pfd{};
            pfd.fd = fd;
            pfd.events = POLLIN;
            int prc = ::poll(&pfd, 1, wait_ms);
            if (prc == 0) continue;
            if (prc < 0) {
                if (errno == EINTR) continue;
                close_sock();
                return std::unexpected("SSE poll failed");
            }
#endif
#ifdef _WIN32
            auto n = ::recv(fd, buf, static_cast<int>(sizeof(buf)), 0);
#else
            auto n = ::recv(fd, buf, sizeof(buf), 0);
#endif
#ifndef _WIN32
            if (n < 0 && errno == EINTR) continue;
#endif
            if (n == 0) break;
            if (n < 0) { close_sock(); return std::unexpected("SSE recv failed"); }

            std::string_view piece(buf, static_cast<std::size_t>(n));
            if (!headers_done) {
                hdr_buf.append(piece);
                if (hdr_buf.size() > 32u * 1024u) { close_sock(); return std::unexpected("SSE headers too large"); }
                auto sep = hdr_buf.find("\r\n\r\n");
                if (sep == std::string::npos) continue;
                auto hdrs = std::string_view(hdr_buf).substr(0, sep);
                auto first_end = hdrs.find("\r\n");
                auto status_line = first_end == std::string_view::npos ? hdrs : hdrs.substr(0, first_end);
                auto sp = status_line.find(' ');
                int code = 0;
                if (sp != std::string_view::npos) {
                    auto cs = status_line.substr(sp + 1);
                    std::from_chars(cs.data(), cs.data() + cs.size(), code);
                }
                if (code < 200 || code >= 300) {
                    close_sock();
                    return std::unexpected(std::format("SSE HTTP status {}", code));
                }
                is_chunked = contains_ci(hdrs, "transfer-encoding:") && contains_ci(hdrs, "chunked");
                headers_done = true;
                if (on_connected && !stop.stop_requested()) on_connected();
                std::string leftover = hdr_buf.substr(sep + 4);
                hdr_buf.clear();
                if (!leftover.empty()) {
                    if (is_chunked) {
                        std::string decoded;
                        if (!chunked.decode(leftover, decoded)) { close_sock(); return std::unexpected("SSE bad chunk"); }
                        if (!parser.feed(decoded, on_event) || chunked.done) break;
                    } else if (!parser.feed(leftover, on_event)) {
                        break;
                    }
                }
                continue;
            }

            if (is_chunked) {
                std::string decoded;
                if (!chunked.decode(piece, decoded)) { close_sock(); return std::unexpected("SSE bad chunk"); }
                if (!parser.feed(decoded, on_event) || chunked.done) break;
            } else if (!parser.feed(piece, on_event)) {
                break;
            }
        }
        if (headers_done && !stop.stop_requested()) (void)parser.finish(on_event);
        close_sock();
        return {};
    }
}
