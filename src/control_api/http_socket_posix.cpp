module;
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
module control_api.http_socket;

import std;
import platform.ip_address;

namespace control_api {
    namespace {
        auto to_fd(Fd const& fd) noexcept -> int {
            return fd.valid() ? static_cast<int>(fd.native()) : -1;
        }

        auto from_fd(int raw) noexcept -> Fd {
            return raw >= 0 ? Fd(static_cast<std::uintptr_t>(raw)) : Fd{};
        }

        auto configure_socket(int fd) noexcept -> bool {
            if (fd < 0) return false;
#if defined(__APPLE__) && defined(SO_NOSIGPIPE)
            int one = 1;
            (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
#if !defined(__linux__)
            int flags = ::fcntl(fd, F_GETFL, 0);
            if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) return false;
            int fdflags = ::fcntl(fd, F_GETFD, 0);
            if (fdflags < 0 || ::fcntl(fd, F_SETFD, fdflags | FD_CLOEXEC) < 0) return false;
#endif
            return true;
        }
    }

    auto Fd::close() noexcept -> void {
        if (handle_ != kInvalidHandle) {
            ::close(static_cast<int>(std::exchange(handle_, kInvalidHandle)));
        }
    }

    auto accept_nonblocking(Fd const& listen_fd) noexcept -> Fd {
        int raw = to_fd(listen_fd);
#if defined(__linux__)
        int c = ::accept4(raw, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
        return from_fd(c);
#else
        int c = ::accept(raw, nullptr, nullptr);
        if (c >= 0 && !configure_socket(c)) {
            ::close(c);
            return Fd{};
        }
        return from_fd(c);
#endif
    }

    auto create_listen_socket(bool ipv6, platform::IpAddress const& parsed_ip, std::uint16_t port)
        -> std::expected<Fd, std::string> {
#if defined(__linux__)
        int raw = ::socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
#else
        int raw = ::socket(ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
#endif
        Fd fd = from_fd(raw);
        if (!fd.valid() || !configure_socket(to_fd(fd))) return std::unexpected("control http socket failed");
        int s = to_fd(fd);
        int one = 1;
        (void)::setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (ipv6) {
            (void)::setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
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
        auto n = ::recv(to_fd(fd), out.data(), out.size(), MSG_DONTWAIT);
        if (n > 0) {
            received = static_cast<std::size_t>(n);
            return SocketIoStatus::ok;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return SocketIoStatus::would_block;
        return SocketIoStatus::closed;
    }

    auto send_nonblocking(Fd const& fd, std::span<char const> in, std::size_t& sent) noexcept -> SocketIoStatus {
        sent = 0;
#ifdef MSG_NOSIGNAL
        constexpr int kSendFlags = MSG_DONTWAIT | MSG_NOSIGNAL;
#else
        constexpr int kSendFlags = MSG_DONTWAIT;
#endif
        auto n = ::send(to_fd(fd), in.data(), in.size(), kSendFlags);
        if (n > 0) {
            sent = static_cast<std::size_t>(n);
            return SocketIoStatus::ok;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return SocketIoStatus::would_block;
        return SocketIoStatus::closed;
    }
}
