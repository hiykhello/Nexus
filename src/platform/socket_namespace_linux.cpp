module;
#include <cerrno>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
module platform.socket_options;
import std;
import platform.unique_fd;

namespace platform {
    // Compile-time Linux LP64 ABI constant verification across x86_64 & aarch64.
    static_assert(sizeof(long) == 8 && sizeof(void*) == 8, "Linux socket option boundary requires x86-64 / aarch64 LP64");
    static_assert(AF_INET == 2 && AF_INET6 == 10 && SOL_SOCKET == 1);
    static_assert(IPPROTO_TCP == 6 && TCP_NODELAY == 1 && TCP_QUICKACK == 12 && TCP_USER_TIMEOUT == 18);
    static_assert(SO_REUSEADDR == 2 && SO_KEEPALIVE == 9 && SO_REUSEPORT == 15);
    static_assert(SO_BINDTODEVICE == 25 && SO_MARK == 36 && SO_DOMAIN == 39);
    static_assert(O_CLOEXEC == 524288 && O_NONBLOCK == 2048);
    static_assert(POLLIN == 1 && POLLOUT == 4 && POLLERR == 8 && POLLHUP == 16 && POLLNVAL == 32 && POLLRDHUP == 0x2000);
#if defined(__aarch64__)
    static_assert(O_NOFOLLOW == 32768);
#elif defined(__x86_64__)
    static_assert(O_NOFOLLOW == 131072);
#endif

    namespace {
        auto socket_error() noexcept -> std::error_code { return {errno, std::generic_category()}; }

        using OwnedFd = platform::UniqueFd;

        using Clock = std::chrono::steady_clock;

        auto wait_for_socket(int fd, short events, Clock::time_point deadline) noexcept -> std::error_code {
            pollfd event{fd, events, 0};
            for (;;) {
                auto now = Clock::now();
                if (now >= deadline) return std::make_error_code(std::errc::timed_out);
                auto remaining = std::chrono::ceil<std::chrono::milliseconds>(deadline - now).count();
                int wait_ms = static_cast<int>(std::clamp<std::int64_t>(remaining, 1, 50));
                event.revents = 0;
                auto result = ::poll(&event, 1, wait_ms);
                if (result > 0) {
                    if (event.revents & POLLNVAL) return std::make_error_code(std::errc::bad_file_descriptor);
                    return {};
                }
                if (result < 0 && errno != EINTR) return socket_error();
            }
        }

        auto protect_socket(int fd, std::string const& path, SocketDeadline deadline) noexcept -> std::error_code {
            auto now = Clock::now();
            if (now >= deadline) return std::make_error_code(std::errc::timed_out);
            deadline = std::min(deadline, now + std::chrono::milliseconds(250));
            sockaddr_un address{};
            if (path.size() >= sizeof(address.sun_path)) return std::make_error_code(std::errc::filename_too_long);
            address.sun_family = AF_UNIX;
            std::ranges::copy(path, address.sun_path);
            OwnedFd control(::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0));
            if (!control) return socket_error();
            if (::connect(control.get(), reinterpret_cast<sockaddr const*>(&address), sizeof(address)) < 0) {
                if (errno != EINPROGRESS && errno != EINTR) return socket_error();
                if (auto error = wait_for_socket(control.get(), POLLOUT, deadline)) return error;
                int status = 0;
                socklen_t size = sizeof(status);
                if (::getsockopt(control.get(), SOL_SOCKET, SO_ERROR, &status, &size) < 0) return socket_error();
                if (status) return {status, std::generic_category()};
            }
            char byte = 1;
            iovec payload{&byte, sizeof(byte)};
            alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(fd))> rights{};
            msghdr message{};
            message.msg_iov = &payload;
            message.msg_iovlen = 1;
            message.msg_control = rights.data();
            message.msg_controllen = rights.size();
            auto* header = CMSG_FIRSTHDR(&message);
            header->cmsg_level = SOL_SOCKET;
            header->cmsg_type = SCM_RIGHTS;
            header->cmsg_len = CMSG_LEN(sizeof(fd));
            std::memcpy(CMSG_DATA(header), &fd, sizeof(fd));
            for (;;) {
                if (Clock::now() >= deadline) return std::make_error_code(std::errc::timed_out);
                auto sent = ::sendmsg(control.get(), &message, MSG_NOSIGNAL);
                if (sent == 1) break;
                if (sent >= 0) return std::make_error_code(std::errc::io_error);
                if (errno == EINTR) continue;
                if (errno != EAGAIN && errno != EWOULDBLOCK) return socket_error();
                if (auto error = wait_for_socket(control.get(), POLLOUT, deadline)) return error;
            }
            for (;;) {
                if (Clock::now() >= deadline) return std::make_error_code(std::errc::timed_out);
                auto received = ::recv(control.get(), &byte, sizeof(byte), 0);
                if (received == 1) return {};
                if (received == 0) return std::make_error_code(std::errc::permission_denied);
                if (errno == EINTR) continue;
                if (errno != EAGAIN && errno != EWOULDBLOCK) return socket_error();
                if (auto error = wait_for_socket(control.get(), POLLIN, deadline)) return error;
            }
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
        auto create = [&]() -> std::expected<int, std::error_code> {
            auto fd = ::socket(ipv6 ? AF_INET6 : AF_INET,
                (datagram ? SOCK_DGRAM : SOCK_STREAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, multipath ? IPPROTO_MPTCP : 0);
            if (fd < 0) return std::unexpected(socket_error());
            return fd;
        };
        if (network_namespace.empty()) return create();

        int ns_fd = -1;
        for (int tries = 0; tries < 16; ++tries) {
            ns_fd = ::open(network_namespace.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
            if (ns_fd >= 0 || errno != EINTR) break;
        }
        OwnedFd target(ns_fd);
        if (target.get() < 0) return std::unexpected(socket_error());
        std::expected<int, std::error_code> result = std::unexpected(std::make_error_code(std::errc::io_error));
        // Only this short-lived thread joins the namespace. The executor and
        // its other sockets keep their original namespace even on failure.
        try {
            std::thread creator([&] {
                if (::setns(target.get(), CLONE_NEWNET) < 0) result = std::unexpected(socket_error());
                else result = create();
            });
            creator.join();
        } catch (std::system_error const& failure) {
            return std::unexpected(failure.code());
        } catch (std::bad_alloc const&) {
            return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
        } catch (...) {
            return std::unexpected(std::make_error_code(std::errc::io_error));
        }
        return result;
    }

    auto apply_socket_binding(int fd, SocketBinding const& options, bool datagram,
        SocketDeadline deadline) noexcept -> std::error_code {
        if (!options.valid()) return std::make_error_code(std::errc::invalid_argument);
        using namespace linux_socket_abi;
        auto name = options.interface_name();
        if (!name.empty()) {
            if (auto error = socket_detail::set(fd, socket_level, bind_to_device, name.data(),
                static_cast<unsigned int>(name.size() + 1))) return error;
        }
        auto index = options.interface_index;
        if (options.network) {
            auto family = socket_detail::get<int>(fd, socket_level, socket_domain,
                std::errc::address_family_not_supported);
            if (!family) return family.error();
            if (*family != af_inet && *family != af_inet6)
                return std::make_error_code(std::errc::address_family_not_supported);
            index = (*options.network)(*family == af_inet6).first();
            if (!index) return std::make_error_code(std::errc::network_unreachable);
        }
        if (index) {
            if (auto error = socket_detail::set(fd, socket_level, bind_to_ifindex, static_cast<int>(index)))
                return error;
        }
        if (options.routing_mark) {
            if (auto error = socket_detail::set(fd, socket_level, mark, *options.routing_mark)) return error;
        }
        if (options.reuse_addr) {
            auto value = *options.reuse_addr ? 1 : 0;
            if (auto error = socket_detail::set(fd, socket_level, reuse_addr, value)) return error;
            if (datagram) {
                if (auto error = socket_detail::set(fd, socket_level, reuse_port, value)) return error;
            }
        }
        if (datagram && options.udp_fragment) {
            auto family = socket_detail::get<int>(fd, socket_level, socket_domain,
                std::errc::address_family_not_supported);
            if (!family) return family.error();
            if (*family != af_inet && *family != af_inet6)
                return std::make_error_code(std::errc::address_family_not_supported);
            auto value = *options.udp_fragment ? pmtu_dont : pmtu_do;
            if (auto error = socket_detail::set(fd, ip_level, ip_mtu_discover, value)) return error;
            if (*family == af_inet6) {
                if (auto error = socket_detail::set(fd, ipv6_level, ipv6_mtu_discover, value)) return error;
            }
        }
        if (auto error = invoke_protect_fd(fd)) return error;
        return options.protect_path.empty() ? std::error_code{} : protect_socket(fd, options.protect_path, deadline);
    }

    auto apply_tcp_options(int fd, TcpSocketOptions const& options,
        SocketDeadline deadline) noexcept -> std::error_code {
        if (!options.valid()) return std::make_error_code(std::errc::invalid_argument);
        if (auto error = apply_socket_binding(fd, options.binding, false, deadline)) return error;
        using namespace linux_socket_abi;
        if (options.bind_address_no_port) {
            if (auto error = socket_detail::set(fd, ip_level, bind_address_no_port,
                *options.bind_address_no_port ? 1 : 0)) return error;
        }
        if (!options.keepalive_configured()) return {};
        auto enabled = options.keepalive.value_or(true);
        if (auto error = socket_detail::set(fd, socket_level, keepalive, enabled ? 1 : 0)) return error;
        if (options.keepalive_idle_seconds) {
            if (auto error = socket_detail::set(fd, tcp_level, keepalive_idle,
                static_cast<int>(*options.keepalive_idle_seconds))) return error;
        }
        if (options.keepalive_interval_seconds) {
            if (auto error = socket_detail::set(fd, tcp_level, keepalive_interval,
                static_cast<int>(*options.keepalive_interval_seconds))) return error;
        }
        if (options.keepalive_count) {
            if (auto error = socket_detail::set(fd, tcp_level, keepalive_count,
                static_cast<int>(*options.keepalive_count))) return error;
        }
        return {};
    }

    auto tune_tcp_low_latency(int fd, std::uint32_t user_timeout_ms) noexcept -> void {
        if (fd < 0) return;
        using namespace linux_socket_abi;
        (void)socket_detail::set(fd, tcp_level, tcp_nodelay, 1);
        (void)socket_detail::set(fd, tcp_level, TCP_QUICKACK, 1);
        if (user_timeout_ms > 0) (void)socket_detail::set(fd, tcp_level, tcp_user_timeout, user_timeout_ms);
    }

    auto enable_tcp_quickack(int fd) noexcept -> void {
        if (fd < 0) return;
        (void)socket_detail::set(fd, linux_socket_abi::tcp_level, TCP_QUICKACK, 1);
    }
}
