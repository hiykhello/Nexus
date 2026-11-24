module;
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

module platform.resolved_bus;
import std;

namespace platform::resolved::socket_detail {
    auto is_eintr(int err) noexcept -> bool { return err == EINTR; }

    auto is_ewouldblock(int err) noexcept -> bool { return err == EAGAIN || err == EWOULDBLOCK; }

    auto err_reset() noexcept -> int { return ECONNRESET; }

    auto close_fd(int& fd) noexcept -> void {
        if (fd >= 0) { ::close(fd); fd = -1; }
    }

    auto open_unix(std::string_view address, int& out_fd, bool& connecting) noexcept -> int {
        if (address.starts_with("unix:path=")) {
            address.remove_prefix(10);
            if (auto comma = address.find(','); comma != address.npos) address = address.substr(0, comma);
        }
        sockaddr_un addr{};
        if (address.size() < 2 || address.front() != '/' ||
            address.size() >= sizeof(addr.sun_path) || address.find('\0') != address.npos) {
            return EINVAL;
        }
        int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0) return errno;
        addr.sun_family = AF_UNIX;
        std::memcpy(addr.sun_path, address.data(), address.size());
        auto const len = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + address.size() + 1);
        if (::connect(fd, reinterpret_cast<sockaddr const*>(&addr), len) == 0) {
            out_fd = fd;
            connecting = false;
            return 0;
        }
        int const err = errno;
        if (err == EINPROGRESS || err == EAGAIN) {
            out_fd = fd;
            connecting = true;
            return 0;
        }
        ::close(fd);
        return err;
    }

    auto check_connect_error(int fd) noexcept -> int {
        int so_err = 0;
        socklen_t len = sizeof(so_err);
        return ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &len) < 0 ? errno : so_err;
    }

    auto send_some(int fd, std::uint8_t const* data, std::size_t len, std::ptrdiff_t& written) noexcept -> int {
#ifdef MSG_NOSIGNAL
        constexpr int kFlags = MSG_NOSIGNAL | MSG_DONTWAIT;
#else
        constexpr int kFlags = MSG_DONTWAIT;
#endif
        written = ::send(fd, data, len, kFlags);
        return written >= 0 ? 0 : errno;
    }

    auto recv_some(int fd, std::uint8_t* data, std::size_t len, std::ptrdiff_t& got) noexcept -> int {
        got = ::recv(fd, data, len, MSG_DONTWAIT);
        return got >= 0 ? 0 : errno;
    }

    auto poll_once(int fd, bool want_read, bool want_write, int timeout_ms, bool& ready) noexcept -> int {
        ready = false;
        short const events = static_cast<short>((want_read ? POLLIN : 0) | (want_write ? POLLOUT : 0));
        pollfd pfd{fd, events, 0};
        int const rc = ::poll(&pfd, 1, timeout_ms);
        if (rc < 0) return errno == EINTR ? 0 : errno;
        if (rc > 0 && (pfd.revents & POLLNVAL)) return EBADF;
        ready = rc > 0 && (pfd.revents & (events | POLLERR | POLLHUP)) != 0;
        return 0;
    }

    auto build_sasl_auth(std::array<std::uint8_t, 96>& out, std::size_t& out_len) noexcept -> void {
        constexpr char kHex[] = "0123456789abcdef";
        constexpr std::string_view kHdr = "AUTH EXTERNAL ";
        std::array<char, 24> uid_dec{};
        auto res = std::to_chars(uid_dec.data(), uid_dec.data() + uid_dec.size(), static_cast<unsigned long>(::geteuid()));
        std::size_t p = 0;
        out[p++] = 0;
        for (char ch : kHdr) out[p++] = static_cast<std::uint8_t>(ch);
        for (char* it = uid_dec.data(); it != res.ptr; ++it) {
            auto const b = static_cast<unsigned>(static_cast<unsigned char>(*it));
            out[p++] = static_cast<std::uint8_t>(kHex[(b >> 4) & 0xFu]);
            out[p++] = static_cast<std::uint8_t>(kHex[b & 0xFu]);
        }
        out[p++] = '\r';
        out[p++] = '\n';
        out_len = p;
    }
}
