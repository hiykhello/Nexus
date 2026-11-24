module;
#include <cerrno>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>

module relay:tcp_listener_helpers;
import std;
import corosio;
import :types;

namespace relay::tcp_listener_detail {
    namespace io = ::corosio;

    // Linux accept can report errors from a pending connection or
    // temporary descriptor and kernel buffer exhaustion.
    inline auto transient_accept_error(std::error_code error) noexcept -> bool {
        return error == std::errc::connection_aborted || error == std::errc::interrupted ||
            error == std::errc::network_down || error == std::errc::protocol_error ||
            error == std::errc::no_protocol_option || error == std::errc::host_unreachable ||
            error == std::errc::operation_not_supported || error == std::errc::network_unreachable ||
            error == std::errc::too_many_files_open || error == std::errc::too_many_files_open_in_system ||
            error == std::errc::no_buffer_space || error == std::errc::not_enough_memory ||
            error.default_error_condition() == std::error_condition(EHOSTDOWN, std::generic_category()) ||
            error.default_error_condition() == std::error_condition(ENONET, std::generic_category());
    }

    inline auto accept_nonblock_cloexec(int listener_fd) noexcept -> int {
#if defined(__linux__)
        return ::accept4(listener_fd, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
#else
        int fd = ::accept(listener_fd, nullptr, nullptr);
        if (fd < 0) return -1;
        int fl = ::fcntl(fd, F_GETFL, 0);
        int fdfl = ::fcntl(fd, F_GETFD, 0);
        if (fl < 0 || ::fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0 ||
            fdfl < 0 || ::fcntl(fd, F_SETFD, fdfl | FD_CLOEXEC) < 0) {
            int err = errno;
            ::close(fd);
            errno = err;
            return -1;
        }
#ifdef SO_NOSIGPIPE
        int one = 1;
        (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
        return fd;
#endif
    }

    inline auto listener_endpoint(std::uint16_t port, bool ipv6,
        std::optional<std::array<std::uint8_t, 16>> const& address) -> io::endpoint {
        if (!address)
            return ipv6 ? io::endpoint(io::ipv6_address::loopback(), port)
                        : io::endpoint(io::ipv4_address::loopback(), port);
        if (ipv6) return {io::ipv6_address(*address), port};
        io::ipv4_address::bytes_type bytes{};
        std::copy_n(address->begin(), bytes.size(), bytes.begin());
        return {io::ipv4_address(bytes), port};
    }
}
