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
import cli.stun_rfc5780;
import crypto;
import encoding.json;
import platform.ip_address;
import platform.unique_fd;
import sniff.stun;

extern "C" auto nexus_tools_fetch_entry(int argc, char** argv) -> int;

namespace cli {
    namespace {
#ifdef _WIN32
        using SocketFd = SOCKET;
        constexpr SocketFd kInvalidFd = INVALID_SOCKET;
        auto close_fd(SocketFd fd) noexcept -> void { if (fd != INVALID_SOCKET) ::closesocket(fd); }
        auto ensure_wsa() noexcept -> void {
            static bool initialized = []() noexcept {
                WSADATA data{};
                return ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
            }();
            (void)initialized;
        }
        struct SocketGuard {
            SocketFd fd = kInvalidFd;
            ~SocketGuard() { close_fd(fd); }
            [[nodiscard]] auto get() const noexcept -> SocketFd { return fd; }
        };
#else
        using SocketFd = int;
        constexpr SocketFd kInvalidFd = -1;
        struct SocketGuard {
            platform::UniqueFd inner;
            explicit SocketGuard(int raw = -1) noexcept : inner(raw) {}
            [[nodiscard]] auto get() const noexcept -> int { return inner.get(); }
        };
#endif

        struct AddrInfoGuard {
            addrinfo* ptr = nullptr;
            ~AddrInfoGuard() { if (ptr) ::freeaddrinfo(ptr); }
        };

        auto parse_host_port(std::string_view spec) -> std::optional<std::pair<std::string, std::uint16_t>> {
            auto parsed = platform::split_host_port(spec);
            if (!parsed) return {};
            return std::pair{std::string(parsed->host), parsed->port};
        }

        auto format_stun_mapped(std::span<std::uint8_t const> pkt) -> std::optional<std::string> {
            std::size_t off = 20;
            std::optional<std::string> fallback_mapped;
            while (off + 4 <= pkt.size()) {
                std::uint16_t type = (std::uint16_t(pkt[off]) << 8) | pkt[off + 1];
                std::uint16_t len = (std::uint16_t(pkt[off + 2]) << 8) | pkt[off + 3];
                off += 4;
                if (off + len > pkt.size()) break;
                if ((type == 0x0020 || type == 0x0001) && len >= 8) {
                    bool xored = (type == 0x0020);
                    std::uint8_t fam = pkt[off + 1];
                    std::uint16_t port = (std::uint16_t(pkt[off + 2]) << 8) | pkt[off + 3];
                    if (xored) port ^= 0x2112u;
                    if (fam == 0x01 && len >= 8) {
                        std::array<std::uint8_t, 4> addr{pkt[off + 4], pkt[off + 5], pkt[off + 6], pkt[off + 7]};
                        if (xored) {
                            addr[0] ^= 0x21; addr[1] ^= 0x12; addr[2] ^= 0xa4; addr[3] ^= 0x42;
                        }
                        char buf[INET_ADDRSTRLEN]{};
                        if (::inet_ntop(AF_INET, addr.data(), buf, sizeof(buf))) {
                            auto formatted = std::format("{}:{}", buf, port);
                            if (xored) return formatted;
                            fallback_mapped = std::move(formatted);
                        }
                    } else if (fam == 0x02 && len >= 20) {
                        std::array<std::uint8_t, 16> addr{};
                        std::copy_n(pkt.begin() + static_cast<std::ptrdiff_t>(off + 4), 16, addr.begin());
                        if (xored) {
                            for (std::size_t i = 0; i < 16; ++i) addr[i] ^= pkt[4 + i];
                        }
                        char buf[INET6_ADDRSTRLEN]{};
                        if (::inet_ntop(AF_INET6, addr.data(), buf, sizeof(buf))) {
                            auto formatted = std::format("[{}]:{}", buf, port);
                            if (xored) return formatted;
                            fallback_mapped = std::move(formatted);
                        }
                    }
                }
                off += (len + 3u) & ~3u;
            }
            return fallback_mapped;
        }
    }

    auto probe_tcp_connect(std::string_view host, std::uint16_t port, std::uint32_t timeout_ms)
        -> std::expected<double, std::string> {
#ifdef _WIN32
        ensure_wsa();
#endif
        addrinfo hints{};
        hints.ai_socktype = SOCK_STREAM;
        std::string host_s(host);
        auto port_s = std::to_string(port);
        AddrInfoGuard res{};
        if (::getaddrinfo(host_s.c_str(), port_s.c_str(), &hints, &res.ptr) != 0 || !res.ptr)
            return std::unexpected("DNS resolution failed");

        auto t0 = std::chrono::steady_clock::now();
        for (auto* ai = res.ptr; ai != nullptr; ai = ai->ai_next) {
            SocketGuard sock{::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)};
            if (sock.get() == kInvalidFd) continue;
#ifdef _WIN32
            u_long nb = 1;
            ::ioctlsocket(sock.get(), FIONBIO, &nb);
            int rc = ::connect(sock.get(), ai->ai_addr, static_cast<int>(ai->ai_addrlen));
            if (rc == SOCKET_ERROR && ::WSAGetLastError() != WSAEWOULDBLOCK) continue;
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(sock.get(), &wfds);
            timeval tv{static_cast<long>(timeout_ms / 1000), static_cast<long>((timeout_ms % 1000) * 1000)};
            if (::select(0, nullptr, &wfds, nullptr, &tv) <= 0) continue;
            int so_err = 0; int slen = sizeof(so_err);
            if (::getsockopt(sock.get(), SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&so_err), &slen) != 0 || so_err != 0) continue;
#else
            int flags = ::fcntl(sock.get(), F_GETFL, 0);
            if (flags >= 0) (void)::fcntl(sock.get(), F_SETFL, flags | O_NONBLOCK);
            int rc = ::connect(sock.get(), ai->ai_addr, ai->ai_addrlen);
            if (rc != 0 && errno != EINPROGRESS) continue;
            if (rc != 0) {
                pollfd pfd{sock.get(), POLLOUT, 0};
                if (::poll(&pfd, 1, static_cast<int>(timeout_ms)) <= 0) continue;
                int so_err = 0; socklen_t slen = sizeof(so_err);
                if (::getsockopt(sock.get(), SOL_SOCKET, SO_ERROR, &so_err, &slen) != 0 || so_err != 0) continue;
            }
#endif
            auto t1 = std::chrono::steady_clock::now();
            return std::chrono::duration<double, std::milli>(t1 - t0).count();
        }
        return std::unexpected("TCP connect failed or timed out");
    }

    auto probe_stun_server(std::string_view host, std::uint16_t port, std::uint32_t timeout_ms)
        -> std::expected<std::string, std::string> {
#ifdef _WIN32
        ensure_wsa();
#endif
        addrinfo hints{};
        hints.ai_socktype = SOCK_DGRAM;
        std::string host_s(host);
        auto port_s = std::to_string(port);
        AddrInfoGuard res{};
        if (::getaddrinfo(host_s.c_str(), port_s.c_str(), &hints, &res.ptr) != 0 || !res.ptr)
            return std::unexpected("STUN server resolution failed");

        std::array<std::uint8_t, 20> req{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42};
        if (!crypto::random_bytes(std::span(req).subspan(8, 12)))
            return std::unexpected("random_bytes failed");

        for (auto* ai = res.ptr; ai != nullptr; ai = ai->ai_next) {
            SocketGuard sock{::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)};
            if (sock.get() == kInvalidFd) continue;
            auto t0 = std::chrono::steady_clock::now();
            if (::sendto(sock.get(), reinterpret_cast<char const*>(req.data()), static_cast<int>(req.size()), 0,
                    ai->ai_addr, static_cast<int>(ai->ai_addrlen)) < 0) continue;
#ifdef _WIN32
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sock.get(), &rfds);
            timeval tv{static_cast<long>(timeout_ms / 1000), static_cast<long>((timeout_ms % 1000) * 1000)};
            if (::select(0, &rfds, nullptr, nullptr, &tv) <= 0) continue;
#else
            pollfd pfd{sock.get(), POLLIN, 0};
            if (::poll(&pfd, 1, static_cast<int>(timeout_ms)) <= 0) continue;
#endif
            std::array<std::uint8_t, 1024> rx{};
            auto n = ::recvfrom(sock.get(), reinterpret_cast<char*>(rx.data()), static_cast<int>(rx.size()), 0, nullptr, nullptr);
            if (n < 20) continue;
            auto pkt = std::span(rx).first(static_cast<std::size_t>(n));
            if (!sniff::stun_datagram(pkt) || !std::ranges::equal(pkt.subspan(8, 12), std::span(req).subspan(8, 12))) continue;
            auto mapped = format_stun_mapped(pkt);
            if (!mapped) continue;
            auto rtt = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
            return std::format("{} ({:.2f} ms)", *mapped, rtt);
        }
        return std::unexpected("STUN probe failed or timed out");
    }

    auto nexus_tools_fetch(int argc, char** argv) -> int {
        return ::nexus_tools_fetch_entry(argc, argv);
    }

    auto nexus_tools(int argc, char** argv) -> int {
        auto usage = [] {
            std::cerr << "usage:\n  nexus tools connect <host:port> [--timeout-ms N]\n"
                      << "  nexus tools stun [--server host:port] [--timeout-ms N] [--full] [--json]\n"
                      << "  nexus tools fetch <url> [--config path] [--outbound tag] [--method GET|HEAD|POST] [--body text] [--header \"K: V\"] [--http auto|1.1|2|3] [--timeout-ms N] [--json]\n"
                      << "  nexus tools udp-probe --kind <ntp|dns|stun> [--target host:port] [--socks5 host:port] [--timeout-ms 3000] [--attempts 2] [--json]\n";
        };
        if (argc < 2 || std::string_view(argv[1]) == "--help") { usage(); return argc < 2 ? 2 : 0; }
        std::string_view sub = argv[1];
        if (sub == "udp-probe") return nexus_tools_udp_probe(argc - 1, argv + 1);
        if (sub == "fetch") return nexus_tools_fetch(argc - 1, argv + 1);
        auto parse_u32 = [](std::string_view s) -> std::optional<std::uint32_t> {
            std::uint32_t v = 0;
            auto [end, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
            if (ec != std::errc{} || end != s.data() + s.size() || !v) return std::nullopt;
            return v;
        };
        std::uint32_t timeout_ms = 5000;
        if (sub == "connect") {
            if (argc < 3 || std::string_view(argv[2]) == "--help") {
                std::cerr << "usage: nexus tools connect <host:port> [--timeout-ms N]\n";
                return (argc >= 3 && std::string_view(argv[2]) == "--help") ? 0 : 2;
            }
            auto hp = parse_host_port(argv[2]);
            if (!hp) { std::cerr << "invalid host:port\n"; return 2; }
            for (int i = 3; i < argc; ++i) {
                if (std::string_view(argv[i]) == "--timeout-ms" && i + 1 < argc) {
                    auto v = parse_u32(argv[++i]);
                    if (!v) { std::cerr << "invalid --timeout-ms\n"; return 2; }
                    timeout_ms = *v;
                } else { std::cerr << "unknown option: " << argv[i] << '\n'; return 2; }
            }
            auto rtt = probe_tcp_connect(hp->first, hp->second, timeout_ms);
            if (!rtt) { std::cerr << rtt.error() << '\n'; return 1; }
            std::cout << std::format("connected to {}:{} in {:.2f} ms\n", hp->first, hp->second, *rtt);
            return 0;
        }
        if (sub == "stun") {
            std::string_view srv = "stun.cloudflare.com:3478";
            bool full = false, as_json = false;
            for (int i = 2; i < argc; ++i) {
                std::string_view opt = argv[i];
                if (opt == "--help") {
                    std::cout << "usage: nexus tools stun [--server host:port] [--timeout-ms N] [--full] [--json]\n";
                    return 0;
                }
                if (opt == "--full") { full = true; continue; }
                if (opt == "--json") { as_json = true; continue; }
                if (opt == "--server" && i + 1 < argc) { srv = argv[++i]; continue; }
                if (opt == "--timeout-ms" && i + 1 < argc) {
                    auto v = parse_u32(argv[++i]);
                    if (!v) { std::cerr << "invalid --timeout-ms\n"; return 2; }
                    timeout_ms = *v;
                    continue;
                }
                std::cerr << "unknown stun option: " << opt << '\n';
                return 2;
            }
            auto hp = parse_host_port(srv);
            if (!hp) { std::cerr << "invalid STUN host:port\n"; return 2; }
            if (full) {
                auto rep = stun::probe_nat_behavior(hp->first, hp->second, timeout_ms);
                if (!rep) { std::cerr << rep.error() << '\n'; return 1; }
                std::cout << (as_json ? stun::format_report_json(*rep) : stun::format_report_text(*rep));
                return 0;
            }
            auto res = probe_stun_server(hp->first, hp->second, timeout_ms);
            if (!res) { std::cerr << res.error() << '\n'; return 1; }
            if (as_json) {
                std::cout << std::format("{{\"server\":{},\"result\":{}}}\n",
                    encoding::json_quote(srv), encoding::json_quote(*res));
            } else {
                std::cout << *res << '\n';
            }
            return 0;
        }
        std::cerr << "unknown tools subcommand: " << sub << '\n';
        usage();
        return 2;
    }
}
