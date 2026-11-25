// UDP protocol probe suite (NTP / DNS / STUN) over direct UDP or RFC 1928 SOCKS5 UDP ASSOCIATE.
module;
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

module cli.gen_tools;
import std;
import crypto;
import platform.ip_address;
import platform.unique_fd;

namespace cli {
    namespace {
#ifdef _WIN32
        using SockFd = SOCKET;
        constexpr SockFd kInvalidSock = INVALID_SOCKET;
        auto close_sock(SockFd fd) noexcept -> void { if (fd != INVALID_SOCKET) ::closesocket(fd); }
        auto ensure_wsa() noexcept -> void {
            static bool ok = []() noexcept { WSADATA d{}; return ::WSAStartup(MAKEWORD(2, 2), &d) == 0; }();
            (void)ok;
        }
        struct SockGuard {
            SockFd fd = kInvalidSock;
            explicit SockGuard(SockFd f = kInvalidSock) noexcept : fd(f) {}
            ~SockGuard() { close_sock(fd); }
            SockGuard(SockGuard const&) = delete;
            auto operator=(SockGuard const&) -> SockGuard& = delete;
            SockGuard(SockGuard&& o) noexcept : fd(std::exchange(o.fd, kInvalidSock)) {}
            auto operator=(SockGuard&& o) noexcept -> SockGuard& {
                if (this != &o) { close_sock(fd); fd = std::exchange(o.fd, kInvalidSock); }
                return *this;
            }
            [[nodiscard]] auto get() const noexcept -> SockFd { return fd; }
        };
        auto wait_sock(SockFd fd, bool for_write, std::uint32_t ms) -> bool {
            fd_set fds, efds;
            FD_ZERO(&fds); FD_SET(fd, &fds);
            FD_ZERO(&efds); FD_SET(fd, &efds);
            timeval tv{static_cast<long>(ms / 1000u), static_cast<long>((ms % 1000u) * 1000u)};
            return ::select(0, for_write ? nullptr : &fds, for_write ? &fds : nullptr, &efds, &tv) > 0 && !FD_ISSET(fd, &efds);
        }
        auto set_nonblock(SockFd fd, bool nb) -> void { u_long v = nb ? 1 : 0; ::ioctlsocket(fd, FIONBIO, &v); }
        auto is_connect_pending() noexcept -> bool { return ::WSAGetLastError() == WSAEWOULDBLOCK; }
        auto is_retry_io() noexcept -> bool { auto e = ::WSAGetLastError(); return e == WSAEWOULDBLOCK || e == WSAEINTR; }
        constexpr int kSendFlags = 0;
#else
        using SockFd = int;
        constexpr SockFd kInvalidSock = -1;
        struct SockGuard {
            platform::UniqueFd inner;
            explicit SockGuard(int raw = -1) noexcept : inner(raw) {}
            [[nodiscard]] auto get() const noexcept -> int { return inner.get(); }
        };
        auto wait_sock(SockFd fd, bool for_write, std::uint32_t ms) -> bool {
            auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
            short ev = static_cast<short>(for_write ? POLLOUT : POLLIN);
            while (true) {
                auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(end - std::chrono::steady_clock::now()).count();
                if (rem < 0) rem = 0;
                pollfd pfd{fd, ev, 0};
                int rc = ::poll(&pfd, 1, static_cast<int>(rem));
                if (rc < 0 && errno == EINTR) continue;
                return rc > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0 && (pfd.revents & ev) != 0;
            }
        }
        auto set_nonblock(SockFd fd, bool nb) -> void {
            int f = ::fcntl(fd, F_GETFL, 0);
            if (f >= 0) (void)::fcntl(fd, F_SETFL, nb ? (f | O_NONBLOCK) : (f & ~O_NONBLOCK));
        }
        auto is_connect_pending() noexcept -> bool { return errno == EINPROGRESS; }
        auto is_retry_io() noexcept -> bool { return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK; }
#ifdef MSG_NOSIGNAL
        constexpr int kSendFlags = MSG_NOSIGNAL;
#else
        constexpr int kSendFlags = 0;
#endif
#endif
        struct AddrInfoGuard {
            addrinfo* ptr = nullptr;
            ~AddrInfoGuard() { if (ptr) ::freeaddrinfo(ptr); }
        };

        auto json_escape(std::string_view s) -> std::string {
            std::string out = "\"";
            auto cont = [](unsigned char b) noexcept { return (b & 0xC0u) == 0x80u; };
            for (std::size_t i = 0; i < s.size();) {
                auto c = static_cast<unsigned char>(s[i]);
                if (c < 0x80u) {
                    if (c == '"') out += "\\\"";
                    else if (c == '\\') out += "\\\\";
                    else if (c == '\n') out += "\\n";
                    else if (c == '\r') out += "\\r";
                    else if (c == '\t') out += "\\t";
                    else if (c < 0x20u) out += std::format("\\u{:04x}", unsigned(c));
                    else out.push_back(static_cast<char>(c));
                    ++i;
                } else if (c >= 0xC2u && c <= 0xDFu && i + 1 < s.size() && cont(static_cast<unsigned char>(s[i + 1]))) {
                    out.append(s.data() + i, 2); i += 2;
                } else if (c >= 0xE0u && c <= 0xEFu && i + 2 < s.size() &&
                           cont(static_cast<unsigned char>(s[i + 1])) && cont(static_cast<unsigned char>(s[i + 2])) &&
                           !(c == 0xE0u && static_cast<unsigned char>(s[i + 1]) < 0xA0u) &&
                           !(c == 0xEDu && static_cast<unsigned char>(s[i + 1]) >= 0xA0u)) {
                    out.append(s.data() + i, 3); i += 3;
                } else if (c >= 0xF0u && c <= 0xF4u && i + 3 < s.size() &&
                           cont(static_cast<unsigned char>(s[i + 1])) && cont(static_cast<unsigned char>(s[i + 2])) &&
                           cont(static_cast<unsigned char>(s[i + 3])) &&
                           !(c == 0xF0u && static_cast<unsigned char>(s[i + 1]) < 0x90u) &&
                           !(c == 0xF4u && static_cast<unsigned char>(s[i + 1]) >= 0x90u)) {
                    out.append(s.data() + i, 4); i += 4;
                } else { out += "\\ufffd"; ++i; }
            }
            out.push_back('"');
            return out;
        }

        auto lower_ascii(std::string_view s) -> std::string {
            std::string out(s);
            for (char& c : out) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
            return out;
        }

        auto tcp_connect_timed(std::string_view host, std::uint16_t port, std::uint32_t timeout_ms,
                               sockaddr_storage& connected_addr) -> std::expected<SockGuard, std::string> {
            addrinfo hints{};
            hints.ai_socktype = SOCK_STREAM;
            AddrInfoGuard res{};
            std::string h(host), p = std::to_string(port);
            if (::getaddrinfo(h.c_str(), p.c_str(), &hints, &res.ptr) != 0 || !res.ptr)
                return std::unexpected("failed to resolve SOCKS5 proxy host");
            for (auto* ai = res.ptr; ai != nullptr; ai = ai->ai_next) {
                SockGuard sock{::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)};
                if (sock.get() == kInvalidSock) continue;
                set_nonblock(sock.get(), true);
                int rc = ::connect(sock.get(), ai->ai_addr, static_cast<int>(ai->ai_addrlen));
                if (rc != 0 && !is_connect_pending()) continue;
                if (rc != 0) {
                    if (!wait_sock(sock.get(), true, timeout_ms)) continue;
                    int so_err = 0;
                    socklen_t slen = sizeof(so_err);
                    if (::getsockopt(sock.get(), SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &slen) != 0 || so_err != 0)
                        continue;
                }
                std::memcpy(&connected_addr, ai->ai_addr, ai->ai_addrlen);
                return sock;
            }
            return std::unexpected("SOCKS5 TCP connect failed or timed out");
        }

        auto tcp_write_all(SockFd fd, std::span<std::uint8_t const> buf, std::uint32_t timeout_ms) -> bool {
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
            for (std::size_t off = 0; off < buf.size();) {
                auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
                if (rem <= 0 || !wait_sock(fd, true, static_cast<std::uint32_t>(rem))) return false;
                auto n = ::send(fd, reinterpret_cast<char const*>(buf.data() + off), static_cast<int>(buf.size() - off), kSendFlags);
                if (n < 0 && is_retry_io()) continue;
                if (n <= 0) return false;
                off += static_cast<std::size_t>(n);
            }
            return true;
        }

        auto tcp_read_exact(SockFd fd, std::span<std::uint8_t> buf, std::uint32_t timeout_ms) -> bool {
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
            for (std::size_t off = 0; off < buf.size();) {
                auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
                if (rem <= 0 || !wait_sock(fd, false, static_cast<std::uint32_t>(rem))) return false;
                auto n = ::recv(fd, reinterpret_cast<char*>(buf.data() + off), static_cast<int>(buf.size() - off), 0);
                if (n < 0 && is_retry_io()) continue;
                if (n <= 0) return false;
                off += static_cast<std::size_t>(n);
            }
            return true;
        }

        auto build_socks5_udp_packet(std::string_view host, std::uint16_t port,
                                     std::span<std::uint8_t const> payload) -> std::expected<std::vector<std::uint8_t>, std::string> {
            std::vector<std::uint8_t> frame{0x00, 0x00, 0x00};
            if (auto ip = platform::parse_ip_address(host)) {
                frame.push_back(ip->size == 4 ? 0x01u : 0x04u);
                frame.insert(frame.end(), ip->bytes.begin(), ip->bytes.begin() + ip->size);
            } else {
                if (host.empty() || host.size() > 255u) return std::unexpected("invalid UDP target hostname");
                frame.push_back(0x03u);
                frame.push_back(static_cast<std::uint8_t>(host.size()));
                frame.insert(frame.end(), host.begin(), host.end());
            }
            frame.push_back(static_cast<std::uint8_t>(port >> 8));
            frame.push_back(static_cast<std::uint8_t>(port & 0xffu));
            frame.insert(frame.end(), payload.begin(), payload.end());
            return frame;
        }

        auto unwrap_socks5_udp_packet(std::span<std::uint8_t const> frame) -> std::optional<std::span<std::uint8_t const>> {
            if (frame.size() < 4u || frame[0] != 0x00 || frame[1] != 0x00 || frame[2] != 0x00) return std::nullopt;
            std::size_t off = 4u;
            if (frame[3] == 0x01) off += 4u;
            else if (frame[3] == 0x04) off += 16u;
            else if (frame[3] == 0x03) {
                if (off >= frame.size()) return std::nullopt;
                off += 1u + frame[off];
            } else return std::nullopt;
            off += 2u;
            if (off > frame.size()) return std::nullopt;
            return frame.subspan(off);
        }

        auto build_probe_request(std::string_view kind, std::vector<std::uint8_t>& req) -> std::expected<void, std::string> {
            req.clear();
            if (kind == "ntp") {
                req.assign(48u, 0u);
                req[0] = 0x23u; // LI=0, VN=4, Mode=3 (client)
                if (!crypto::random_bytes(std::span(req).subspan(40u, 8u))) return std::unexpected("random_bytes failed");
                return {};
            }
            if (kind == "dns") {
                std::array<std::uint8_t, 2> txid{};
                if (!crypto::random_bytes(txid)) return std::unexpected("random_bytes failed");
                req = {
                    txid[0], txid[1], 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0,
                    0x00, 0x01, 0x00, 0x01
                };
                return {};
            }
            if (kind == "stun") {
                req.assign(20u, 0u);
                req[0] = 0x00; req[1] = 0x01;
                req[4] = 0x21; req[5] = 0x12; req[6] = 0xa4; req[7] = 0x42;
                if (!crypto::random_bytes(std::span(req).subspan(8u, 12u))) return std::unexpected("random_bytes failed");
                return {};
            }
            return std::unexpected("unsupported probe kind: " + std::string(kind));
        }

        auto parse_stun_mapped(std::span<std::uint8_t const> pkt) -> std::optional<std::string> {
            std::size_t off = 20u;
            std::optional<std::string> fallback;
            while (off + 4u <= pkt.size()) {
                std::uint16_t type = static_cast<std::uint16_t>((pkt[off] << 8) | pkt[off + 1]);
                std::uint16_t len = static_cast<std::uint16_t>((pkt[off + 2] << 8) | pkt[off + 3]);
                off += 4u;
                if (off + len > pkt.size()) break;
                if ((type == 0x0020 || type == 0x0001) && len >= 8u) {
                    bool xored = (type == 0x0020);
                    std::uint8_t fam = pkt[off + 1];
                    std::uint16_t port = static_cast<std::uint16_t>((pkt[off + 2] << 8) | pkt[off + 3]);
                    if (xored) port ^= 0x2112u;
                    if (fam == 0x01 && len >= 8u) {
                        std::array<std::uint8_t, 4> a{pkt[off + 4], pkt[off + 5], pkt[off + 6], pkt[off + 7]};
                        if (xored) { a[0] ^= 0x21; a[1] ^= 0x12; a[2] ^= 0xa4; a[3] ^= 0x42; }
                        char buf[INET_ADDRSTRLEN]{};
                        if (::inet_ntop(AF_INET, a.data(), buf, sizeof(buf))) {
                            auto s = std::format("{}:{}", buf, port);
                            if (xored) return s;
                            fallback = std::move(s);
                        }
                    } else if (fam == 0x02 && len >= 20u) {
                        std::array<std::uint8_t, 16> a{};
                        std::copy_n(pkt.begin() + static_cast<std::ptrdiff_t>(off + 4u), 16, a.begin());
                        if (xored) for (std::size_t i = 0; i < 16u; ++i) a[i] ^= pkt[4u + i];
                        char buf[INET6_ADDRSTRLEN]{};
                        if (::inet_ntop(AF_INET6, a.data(), buf, sizeof(buf))) {
                            auto s = std::format("[{}]:{}", buf, port);
                            if (xored) return s;
                            fallback = std::move(s);
                        }
                    }
                }
                off += (len + 3u) & ~3u;
            }
            return fallback;
        }

        auto verify_probe_response(std::string_view kind, std::span<std::uint8_t const> req,
                                   std::span<std::uint8_t const> rx) -> std::optional<std::string> {
            if (kind == "ntp") {
                if (rx.size() < 48u || (rx[0] & 0x07u) != 4u || rx[1] == 0u) return std::nullopt;
                auto orig = rx.subspan(24u, 8u);
                bool orig_nonzero = std::ranges::any_of(orig, [](auto b) { return b != 0u; });
                if (orig_nonzero && !std::ranges::equal(orig, req.subspan(40u, 8u))) return std::nullopt;
                return std::format("stratum={} mode=4", unsigned(rx[1]));
            }
            if (kind == "dns") {
                if (rx.size() < 12u || rx[0] != req[0] || rx[1] != req[1]) return std::nullopt;
                if ((rx[2] & 0x80u) == 0u || (rx[3] & 0x0fu) != 0u) return std::nullopt;
                std::uint16_t ancount = static_cast<std::uint16_t>((rx[6] << 8) | rx[7]);
                if (ancount == 0u) return std::nullopt;
                return std::format("rc=0 answers={}", ancount);
            }
            if (kind == "stun") {
                if (rx.size() < 20u || rx[0] != 0x01 || rx[1] != 0x01) return std::nullopt;
                if (rx[4] != 0x21 || rx[5] != 0x12 || rx[6] != 0xa4 || rx[7] != 0x42) return std::nullopt;
                std::uint16_t msg_len = static_cast<std::uint16_t>((rx[2] << 8) | rx[3]);
                if ((msg_len & 3u) != 0u || 20u + msg_len > rx.size()) return std::nullopt;
                if (!std::ranges::equal(rx.subspan(8u, 12u), req.subspan(8u, 12u))) return std::nullopt;
                auto mapped = parse_stun_mapped(rx.first(20u + msg_len));
                return mapped ? std::optional("mapped=" + *mapped) : std::nullopt;
            }
            return std::nullopt;
        }

        auto resolve_udp_endpoint(std::string_view host, std::uint16_t port,
                                  sockaddr_storage& out_addr, socklen_t& out_len) -> bool {
            addrinfo hints{};
            hints.ai_socktype = SOCK_DGRAM;
            AddrInfoGuard res{};
            std::string h(host), p = std::to_string(port);
            if (::getaddrinfo(h.c_str(), p.c_str(), &hints, &res.ptr) != 0 || !res.ptr) return false;
            std::memcpy(&out_addr, res.ptr->ai_addr, res.ptr->ai_addrlen);
            out_len = static_cast<socklen_t>(res.ptr->ai_addrlen);
            return true;
        }
    }

    auto run_udp_probe(UdpProbeOptions const& opts) -> UdpProbeResult {
        UdpProbeResult res{};
        res.kind = lower_ascii(opts.kind);
        res.via_socks5 = !opts.socks5_proxy.empty();
#ifdef _WIN32
        ensure_wsa();
#endif
        if (res.kind != "ntp" && res.kind != "dns" && res.kind != "stun") { res.error = "unsupported --kind (expected ntp, dns, or stun)"; return res; }
        std::string target_spec = opts.target;
        if (target_spec.empty()) target_spec = (res.kind == "ntp") ? "time.cloudflare.com:123" : (res.kind == "dns" ? "1.1.1.1:53" : "stun.cloudflare.com:3478");
        auto target_hp = platform::split_host_port(target_spec, true);
        if (!target_hp) { res.error = "invalid --target host:port"; return res; }
        std::uint32_t timeout_ms = std::clamp<std::uint32_t>(opts.timeout_ms ? opts.timeout_ms : 3000u, 100u, 30000u);
        std::uint32_t attempts = std::clamp<std::uint32_t>(opts.attempts ? opts.attempts : 2u, 1u, 10u);

        SockGuard ctrl_sock{};
        sockaddr_storage send_addr{};
        socklen_t send_len = 0;

        if (res.via_socks5) {
            auto proxy_hp = platform::split_host_port(opts.socks5_proxy, true);
            if (!proxy_hp) { res.error = "invalid --socks5 host:port"; return res; }
            sockaddr_storage proxy_addr{};
            auto conn = tcp_connect_timed(proxy_hp->host, proxy_hp->port, timeout_ms, proxy_addr);
            if (!conn) { res.error = conn.error(); return res; }
            ctrl_sock = std::move(*conn);

            std::array<std::uint8_t, 3> hello{0x05, 0x01, 0x00};
            std::array<std::uint8_t, 2> hrep{};
            if (!tcp_write_all(ctrl_sock.get(), hello, timeout_ms) || !tcp_read_exact(ctrl_sock.get(), hrep, timeout_ms) || hrep[0] != 0x05 || hrep[1] != 0x00) {
                res.error = "SOCKS5 greeting failed"; return res;
            }
            std::array<std::uint8_t, 10> assoc{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
            std::array<std::uint8_t, 4> rep_hdr{};
            if (!tcp_write_all(ctrl_sock.get(), assoc, timeout_ms) || !tcp_read_exact(ctrl_sock.get(), rep_hdr, timeout_ms) || rep_hdr[0] != 0x05 || rep_hdr[1] != 0x00) {
                res.error = "SOCKS5 UDP ASSOCIATE rejected"; return res;
            }
            if (rep_hdr[3] == 0x01) {
                std::array<std::uint8_t, 6> bnd{};
                if (!tcp_read_exact(ctrl_sock.get(), bnd, timeout_ms)) { res.error = "SOCKS5 truncated reply"; return res; }
                sockaddr_in sin{}; sin.sin_family = AF_INET;
                std::memcpy(&sin.sin_addr, bnd.data(), 4);
                sin.sin_port = htons(static_cast<std::uint16_t>((bnd[4] << 8) | bnd[5]));
                if (sin.sin_addr.s_addr == 0 && proxy_addr.ss_family == AF_INET) sin.sin_addr = reinterpret_cast<sockaddr_in const*>(&proxy_addr)->sin_addr;
                std::memcpy(&send_addr, &sin, sizeof(sin)); send_len = sizeof(sin);
            } else if (rep_hdr[3] == 0x04) {
                std::array<std::uint8_t, 18> bnd{};
                if (!tcp_read_exact(ctrl_sock.get(), bnd, timeout_ms)) { res.error = "SOCKS5 truncated reply"; return res; }
                sockaddr_in6 sin6{}; sin6.sin6_family = AF_INET6;
                std::memcpy(&sin6.sin6_addr, bnd.data(), 16);
                sin6.sin6_port = htons(static_cast<std::uint16_t>((bnd[16] << 8) | bnd[17]));
                if (std::ranges::all_of(std::span(bnd).first<16>(), [](auto b) { return b == 0; }) && proxy_addr.ss_family == AF_INET6)
                    sin6.sin6_addr = reinterpret_cast<sockaddr_in6 const*>(&proxy_addr)->sin6_addr;
                std::memcpy(&send_addr, &sin6, sizeof(sin6)); send_len = sizeof(sin6);
            } else if (rep_hdr[3] == 0x03) {
                std::array<std::uint8_t, 1> dlen{};
                if (!tcp_read_exact(ctrl_sock.get(), dlen, timeout_ms)) { res.error = "SOCKS5 truncated reply"; return res; }
                std::vector<std::uint8_t> dbuf(dlen[0] + 2u);
                if (!tcp_read_exact(ctrl_sock.get(), dbuf, timeout_ms)) { res.error = "SOCKS5 truncated reply"; return res; }
                std::string bhost(reinterpret_cast<char const*>(dbuf.data()), dlen[0]);
                std::uint16_t bport = static_cast<std::uint16_t>((dbuf[dlen[0]] << 8) | dbuf[dlen[0] + 1]);
                if (!resolve_udp_endpoint(bhost, bport, send_addr, send_len)) { res.error = "failed to resolve SOCKS5 relay host"; return res; }
            } else { res.error = "SOCKS5 unknown BND.ATYP"; return res; }
        } else if (!resolve_udp_endpoint(target_hp->host, target_hp->port, send_addr, send_len)) {
            res.error = "failed to resolve UDP probe target"; return res;
        }

        SockGuard udp{::socket(send_addr.ss_family, SOCK_DGRAM, 0)};
        if (udp.get() == kInvalidSock) { res.error = "UDP socket creation failed"; return res; }
        set_nonblock(udp.get(), true);

        for (std::uint32_t att = 1; att <= attempts; ++att) {
            res.attempts = att;
            std::vector<std::uint8_t> req, wire;
            if (auto ok = build_probe_request(res.kind, req); !ok) { res.error = ok.error(); return res; }
            if (res.via_socks5) {
                auto framed = build_socks5_udp_packet(target_hp->host, target_hp->port, req);
                if (!framed) { res.error = framed.error(); return res; }
                wire = std::move(*framed);
            } else wire = req;
            auto t0 = std::chrono::steady_clock::now();
            auto deadline = t0 + std::chrono::milliseconds(timeout_ms);
            if (::sendto(udp.get(), reinterpret_cast<char const*>(wire.data()), static_cast<int>(wire.size()), 0,
                         reinterpret_cast<sockaddr const*>(&send_addr), send_len) < 0) { res.error = "UDP sendto failed"; continue; }
            std::array<std::uint8_t, 2048> rx{};
            while (true) {
                auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
                if (rem <= 0 || !wait_sock(udp.get(), false, static_cast<std::uint32_t>(rem))) break;
                auto n = ::recvfrom(udp.get(), reinterpret_cast<char*>(rx.data()), static_cast<int>(rx.size()), 0, nullptr, nullptr);
                if (n <= 0) continue;
                auto span = std::span<std::uint8_t const>(rx.data(), static_cast<std::size_t>(n));
                if (res.via_socks5) { auto inner = unwrap_socks5_udp_packet(span); if (!inner) continue; span = *inner; }
                if (auto detail = verify_probe_response(res.kind, req, span)) {
                    auto rtt = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
                    res.ok = true; res.rtt_ms = static_cast<std::uint64_t>(rtt < 0 ? 0 : rtt);
                    res.detail = std::move(*detail); res.error.clear();
                    return res;
                }
            }
            res.error = "UDP probe timed out";
        }
        return res;
    }

    auto serialize_udp_probe_json(UdpProbeResult const& r) -> std::string {
        return std::format("{{\"ok\":{},\"kind\":{},\"via_socks5\":{},\"rtt_ms\":{},\"attempts\":{},\"detail\":{},\"error\":{}}}\n",
            r.ok ? "true" : "false", json_escape(r.kind), r.via_socks5 ? "true" : "false",
            r.rtt_ms, r.attempts, json_escape(r.detail), json_escape(r.error));
    }

    auto nexus_tools_udp_probe(int argc, char** argv) -> int {
        constexpr std::string_view usage =
            "usage: nexus tools udp-probe --kind <ntp|dns|stun> [--target <host:port>] "
            "[--socks5 <host:port>] [--timeout-ms 3000] [--attempts 2] [--json]\n";
        if (argc >= 2 && std::string_view(argv[1]) == "--help") { std::cout << usage; return 0; }
        UdpProbeOptions opts{}; bool json_out = false;
        for (int i = 1; i < argc; ++i) {
            std::string_view a = argv[i];
            auto next = [&]() -> std::expected<std::string_view, int> {
                if (i + 1 >= argc || std::string_view(argv[i + 1]).empty()) { std::cerr << "missing value for " << a << '\n'; return std::unexpected(2); }
                return std::string_view(argv[++i]);
            };
            auto parse_u32 = [&](std::string_view s) -> std::expected<std::uint32_t, int> {
                std::uint32_t v = 0; auto [e, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
                if (ec != std::errc{} || e != s.data() + s.size()) { std::cerr << "invalid integer: " << s << '\n'; return std::unexpected(2); }
                return v;
            };
            if (a == "--json") json_out = true;
            else if (a == "--kind") { auto v = next(); if (!v) return v.error(); opts.kind = std::string(*v); }
            else if (a == "--target") { auto v = next(); if (!v) return v.error(); opts.target = std::string(*v); }
            else if (a == "--socks5") { auto v = next(); if (!v) return v.error(); opts.socks5_proxy = std::string(*v); }
            else if (a == "--timeout-ms") { auto v = next(); if (!v) return v.error(); auto n = parse_u32(*v); if (!n) return n.error(); opts.timeout_ms = *n; }
            else if (a == "--attempts") { auto v = next(); if (!v) return v.error(); auto n = parse_u32(*v); if (!n) return n.error(); opts.attempts = *n; }
            else { std::cerr << "unknown option: " << a << '\n' << usage; return 2; }
        }
        if (opts.kind.empty()) { std::cerr << usage; return 2; }
        auto res = run_udp_probe(opts);
        if (json_out) { std::cout << serialize_udp_probe_json(res); return res.ok ? 0 : 1; }
        if (!res.ok) { std::cerr << "udp-probe (" << res.kind << "): " << res.error << '\n'; return 1; }
        std::cout << res.kind << " ok (" << res.rtt_ms << " ms, " << res.detail << ")\n";
        return 0;
    }
}
