module;
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
module control_api.http_socket;

import std;
import platform.ip_address;

namespace control_api {
    namespace {
        struct WsaInitGuard {
            bool ok = false;
            WsaInitGuard() noexcept {
                WSADATA data{};
                ok = ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
            }
        };

        auto ensure_socket_subsystem() noexcept -> bool {
            static WsaInitGuard guard;
            return guard.ok;
        }

        auto to_socket(Fd const& fd) noexcept -> SOCKET {
            return fd.valid() ? static_cast<SOCKET>(fd.native()) : INVALID_SOCKET;
        }

        auto from_socket(SOCKET s) noexcept -> Fd {
            return s != INVALID_SOCKET ? Fd(static_cast<std::uintptr_t>(s)) : Fd{};
        }

        auto configure_socket(SOCKET s) noexcept -> bool {
            if (s == INVALID_SOCKET) return false;
            u_long nonblock = 1;
            return ::ioctlsocket(s, FIONBIO, &nonblock) == 0;
        }
    }

    auto Fd::close() noexcept -> void {
        if (handle_ != kInvalidHandle) {
            ::closesocket(static_cast<SOCKET>(std::exchange(handle_, kInvalidHandle)));
        }
    }

    auto accept_nonblocking(Fd const& listen_fd) noexcept -> Fd {
        SOCKET c = ::accept(to_socket(listen_fd), nullptr, nullptr);
        if (c == INVALID_SOCKET) return Fd{};
        if (!configure_socket(c)) {
            ::closesocket(c);
            return Fd{};
        }
        return from_socket(c);
    }

    auto create_listen_socket(bool ipv6, platform::IpAddress const& parsed_ip, std::uint16_t port)
        -> std::expected<Fd, std::string> {
        if (!ensure_socket_subsystem()) return std::unexpected("control http socket init failed");
        SOCKET raw = ::socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
        Fd fd = from_socket(raw);
        if (!fd.valid() || !configure_socket(to_socket(fd))) return std::unexpected("control http socket failed");
        SOCKET s = to_socket(fd);
        char const one = 1;
        (void)::setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &one, sizeof(one));
        if (ipv6) {
            char const v6only = 1;
            (void)::setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
            sockaddr_in6 addr{};
            addr.sin6_family = AF_INET6;
            addr.sin6_port = platform::host_to_net16(port);
            std::ranges::copy(parsed_ip.bytes, addr.sin6_addr.s6_addr);
            if (::bind(s, reinterpret_cast<sockaddr const*>(&addr), sizeof(addr)) != 0)
                return std::unexpected("control http bind failed");
        } else {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = platform::host_to_net16(port);
            std::copy_n(parsed_ip.bytes.begin(), 4, reinterpret_cast<std::uint8_t*>(&addr.sin_addr));
            if (::bind(s, reinterpret_cast<sockaddr const*>(&addr), sizeof(addr)) != 0)
                return std::unexpected("control http bind failed");
        }
        if (::listen(s, 16) != 0) return std::unexpected("control http listen failed");
        return fd;
    }

    auto recv_nonblocking(Fd const& fd, std::span<char> out, std::size_t& received) noexcept -> SocketIoStatus {
        received = 0;
        int n = ::recv(to_socket(fd), out.data(), static_cast<int>(out.size()), 0);
        if (n > 0) {
            received = static_cast<std::size_t>(n);
            return SocketIoStatus::ok;
        }
        if (n == 0) return SocketIoStatus::closed;
        int err = ::WSAGetLastError();
        return (err == WSAEWOULDBLOCK || err == WSAEINTR) ? SocketIoStatus::would_block : SocketIoStatus::closed;
    }

    auto send_nonblocking(Fd const& fd, std::span<char const> in, std::size_t& sent) noexcept -> SocketIoStatus {
        sent = 0;
        int n = ::send(to_socket(fd), in.data(), static_cast<int>(in.size()), 0);
        if (n > 0) {
            sent = static_cast<std::size_t>(n);
            return SocketIoStatus::ok;
        }
        if (n == 0) return SocketIoStatus::would_block;
        int err = ::WSAGetLastError();
        return (err == WSAEWOULDBLOCK || err == WSAEINTR) ? SocketIoStatus::would_block : SocketIoStatus::closed;
    }
}
