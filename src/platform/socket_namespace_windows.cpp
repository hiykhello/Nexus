module;
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <netioapi.h>
module platform.socket_options;
import std;
import platform.platform_defaults;

namespace platform {
    namespace {
        auto disable_udp_connreset(int fd) noexcept -> void {
            if (fd < 0) return;
            BOOL enable = FALSE;
            DWORD returned = 0;
            (void)::WSAIoctl(static_cast<SOCKET>(fd), SIO_UDP_CONNRESET, &enable, sizeof(enable),
                             nullptr, 0, &returned, nullptr, nullptr);
        }

        auto bind_interface_non_linux(int fd, std::string_view name, std::uint32_t index,
            bool ipv6) noexcept -> std::error_code {
            ULONG ifidx = index;
            if (!ifidx && !name.empty()) {
                char buf[256]{};
                if (name.size() >= sizeof(buf)) return std::make_error_code(std::errc::invalid_argument);
                std::ranges::copy(name, buf);
                ifidx = ::if_nametoindex(buf);
                if (!ifidx) return std::make_error_code(std::errc::no_such_device);
            }
            if (!ifidx) return {};
            DWORD val = windows_unicast_if_option_value(static_cast<std::uint32_t>(ifidx), ipv6);
            int level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
            int opt = ipv6 ? IPV6_UNICAST_IF : IP_UNICAST_IF;
            if (::setsockopt(static_cast<SOCKET>(fd), level, opt, reinterpret_cast<char const*>(&val), sizeof(val)) != 0)
                return {static_cast<int>(::WSAGetLastError()), std::system_category()};
            return {};
        }
    }

    namespace socket_detail {
        auto set(int, int, int, void const*, unsigned int) noexcept -> std::error_code {
            return std::make_error_code(std::errc::operation_not_supported);
        }

        auto get_raw(int, int, int, void*, unsigned int, std::errc) noexcept -> std::error_code {
            return std::make_error_code(std::errc::operation_not_supported);
        }
    }

    auto open_physical_socket(bool ipv6, bool datagram, bool multipath,
        std::string const& network_namespace) noexcept -> std::expected<int, std::error_code> {
        if (multipath || !network_namespace.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
        SOCKET s = ::socket(ipv6 ? AF_INET6 : AF_INET, datagram ? SOCK_DGRAM : SOCK_STREAM, 0);
        if (s == INVALID_SOCKET)
            return std::unexpected(std::error_code(static_cast<int>(::WSAGetLastError()), std::system_category()));
        u_long nonblock = 1;
        if (::ioctlsocket(s, FIONBIO, &nonblock) != 0) {
            int err = static_cast<int>(::WSAGetLastError());
            ::closesocket(s);
            return std::unexpected(std::error_code(err, std::system_category()));
        }
        int fd = static_cast<int>(s);
        if (datagram) disable_udp_connreset(fd);
        return fd;
    }

    auto close_unadopted_socket(int fd) noexcept -> void {
        if (fd >= 0) (void)::closesocket(static_cast<SOCKET>(fd));
    }

    auto apply_socket_binding(int fd, SocketBinding const& options, bool datagram,
        SocketDeadline) noexcept -> std::error_code {
        if (!options.valid()) return std::make_error_code(std::errc::invalid_argument);
        if (datagram) disable_udp_connreset(fd);
        if (options.routing_mark || !options.network_namespace.empty())
            return std::make_error_code(std::errc::operation_not_supported);
        auto name = options.interface_name();
        if (!name.empty() || options.interface_index) {
            bool ipv6 = options.inet6_bind_address.has_value() && !options.inet4_bind_address.has_value();
            if (auto error = bind_interface_non_linux(fd, name, options.interface_index, ipv6)) return error;
        }
        if (auto error = invoke_protect_fd(fd)) return error;
        return options.protect_path.empty() ? std::error_code{} : std::make_error_code(std::errc::operation_not_supported);
    }

    auto apply_tcp_options(int fd, TcpSocketOptions const& options,
        SocketDeadline deadline) noexcept -> std::error_code {
        if (!options.valid()) return std::make_error_code(std::errc::invalid_argument);
        if (auto error = apply_socket_binding(fd, options.binding, false, deadline)) return error;
        if (options.bind_address_no_port) return std::make_error_code(std::errc::operation_not_supported);
        return {};
    }

    auto tune_tcp_low_latency(int, std::uint32_t) noexcept -> void {}
    auto enable_tcp_quickack(int) noexcept -> void {}
}
