module;
#include <cerrno>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>
module platform.socket_options;
import std;

namespace platform {
    namespace {
        auto socket_is_ipv6(int fd) noexcept -> std::expected<bool, std::error_code> {
            sockaddr_storage local{};
            socklen_t len = sizeof(local);
            if (::getsockname(fd, reinterpret_cast<sockaddr*>(&local), &len) != 0)
                return std::unexpected(std::error_code(errno, std::generic_category()));
            if (local.ss_family == AF_INET6) return true;
            if (local.ss_family == AF_INET) return false;
            return std::unexpected(std::make_error_code(std::errc::address_family_not_supported));
        }

        auto bind_interface_non_linux(int fd, std::string_view name, std::uint32_t index,
            bool ipv6) noexcept -> std::error_code {
            unsigned int ifidx = index;
            if (!ifidx && !name.empty()) {
                char buf[IF_NAMESIZE]{};
                if (name.size() >= sizeof(buf)) return std::make_error_code(std::errc::invalid_argument);
                std::ranges::copy(name, buf);
                ifidx = ::if_nametoindex(buf);
                if (!ifidx) return std::make_error_code(std::errc::no_such_device);
            }
            if (!ifidx) return {};
            int level = ipv6 ? IPPROTO_IPV6 : IPPROTO_IP;
            int opt = ipv6 ? IPV6_BOUND_IF : IP_BOUND_IF;
            if (::setsockopt(fd, level, opt, &ifidx, sizeof(ifidx)) != 0)
                return {errno, std::generic_category()};
            return {};
        }
    }

    namespace socket_detail {
        auto set(int fd, int level, int name, void const* bytes, unsigned int size) noexcept -> std::error_code {
            if (::setsockopt(fd, level, name, bytes, size) == 0) return {};
            return {errno, std::generic_category()};
        }

        auto get_raw(int fd, int level, int name, void* out, unsigned int size,
            std::errc size_error) noexcept -> std::error_code {
            socklen_t actual = size;
            if (::getsockopt(fd, level, name, out, &actual) != 0) return {errno, std::generic_category()};
            if (actual != size) return std::make_error_code(size_error);
            return {};
        }
    }

    auto close_unadopted_socket(int fd) noexcept -> void {
        if (fd >= 0) (void)::close(fd);
    }

    auto open_physical_socket(bool ipv6, bool datagram, bool multipath,
        std::string const& network_namespace) noexcept -> std::expected<int, std::error_code> {
        if (multipath || !network_namespace.empty())
            return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
        int fd = ::socket(ipv6 ? AF_INET6 : AF_INET, datagram ? SOCK_DGRAM : SOCK_STREAM, 0);
        if (fd < 0) return std::unexpected(std::error_code(errno, std::generic_category()));
        int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 || ::fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
            int err = errno;
            ::close(fd);
            return std::unexpected(std::error_code(err, std::generic_category()));
        }
        int one = 1;
        (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        return fd;
    }

    auto apply_socket_binding(int fd, SocketBinding const& options, bool,
        SocketDeadline) noexcept -> std::error_code {
        if (!options.valid()) return std::make_error_code(std::errc::invalid_argument);
        if (options.routing_mark || !options.network_namespace.empty())
            return std::make_error_code(std::errc::operation_not_supported);
        auto name = options.interface_name();
        if (!name.empty() || options.interface_index || options.network) {
            auto ipv6 = socket_is_ipv6(fd);
            if (!ipv6) return ipv6.error();
            std::uint32_t index = options.interface_index;
            if (!index && options.network) {
                index = (*options.network)(*ipv6).first();
                if (!index) return std::make_error_code(std::errc::network_unreachable);
            }
            if (auto error = bind_interface_non_linux(fd, name, index, *ipv6)) return error;
        }
        if (auto error = invoke_protect_fd(fd)) return error;
        return options.protect_path.empty() ? std::error_code{} : std::make_error_code(std::errc::operation_not_supported);
    }

    auto apply_tcp_options(int fd, TcpSocketOptions const& options,
        SocketDeadline deadline) noexcept -> std::error_code {
        if (!options.valid()) return std::make_error_code(std::errc::invalid_argument);
        if (auto error = apply_socket_binding(fd, options.binding, false, deadline)) return error;
        if (options.bind_address_no_port) return std::make_error_code(std::errc::operation_not_supported);
        (void)socket_detail::set(fd, SOL_SOCKET, SO_NOSIGPIPE, 1);
        if (!options.keepalive_configured()) return {};
        auto enabled = options.keepalive.value_or(true);
        if (auto error = socket_detail::set(fd, SOL_SOCKET, SO_KEEPALIVE, enabled ? 1 : 0)) return error;
        if (options.keepalive_idle_seconds) {
            if (auto error = socket_detail::set(fd, IPPROTO_TCP, TCP_KEEPALIVE,
                static_cast<int>(*options.keepalive_idle_seconds))) return error;
        }
        if (options.keepalive_interval_seconds) {
            if (auto error = socket_detail::set(fd, IPPROTO_TCP, TCP_KEEPINTVL,
                static_cast<int>(*options.keepalive_interval_seconds))) return error;
        }
        if (options.keepalive_count) {
            if (auto error = socket_detail::set(fd, IPPROTO_TCP, TCP_KEEPCNT,
                static_cast<int>(*options.keepalive_count))) return error;
        }
        return {};
    }

    auto tune_tcp_low_latency(int fd, std::uint32_t) noexcept -> void {
        if (fd < 0) return;
        (void)socket_detail::set(fd, IPPROTO_TCP, TCP_NODELAY, 1);
        (void)socket_detail::set(fd, SOL_SOCKET, SO_NOSIGPIPE, 1);
    }

    auto enable_tcp_quickack(int) noexcept -> void {}
}
