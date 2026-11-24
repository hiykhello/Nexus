module;

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

module desktop.ipc_client;

import std;

namespace desktop {
    namespace {
        class UniqueFd {
            int fd_ = -1;
        public:
            UniqueFd() noexcept = default;
            explicit UniqueFd(int fd) noexcept : fd_(fd) {}
            ~UniqueFd() { if (fd_ >= 0) ::close(fd_); }
            UniqueFd(UniqueFd const&) = delete;
            auto operator=(UniqueFd const&) -> UniqueFd& = delete;
            UniqueFd(UniqueFd&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
            auto operator=(UniqueFd&& other) noexcept -> UniqueFd& {
                if (this != &other) {
                    if (fd_ >= 0) ::close(fd_);
                    fd_ = other.fd_;
                    other.fd_ = -1;
                }
                return *this;
            }
            [[nodiscard]] auto get(this UniqueFd const& self) noexcept -> int { return self.fd_; }
        };

        auto connect_unix(sockaddr_un const& addr, socklen_t addr_len, int sock_type,
                          std::chrono::milliseconds timeout, int& err_out) -> UniqueFd {
#ifdef SOCK_CLOEXEC
            UniqueFd fd(::socket(AF_UNIX, sock_type | SOCK_CLOEXEC, 0));
#else
            UniqueFd fd(::socket(AF_UNIX, sock_type, 0));
            if (fd.get() >= 0) (void)::fcntl(fd.get(), F_SETFD, FD_CLOEXEC);
#endif
            if (fd.get() < 0) {
                err_out = errno;
                return {};
            }
#ifdef SO_NOSIGPIPE
            int one = 1;
            (void)::setsockopt(fd.get(), SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
            timeval tv{};
            tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
            tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
            ::setsockopt(fd.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            ::setsockopt(fd.get(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            int rc = 0;
            do {
                rc = ::connect(fd.get(), reinterpret_cast<sockaddr const*>(&addr), addr_len);
            } while (rc != 0 && errno == EINTR);
            if (rc != 0) {
                err_out = errno;
                return {};
            }
            err_out = 0;
            return fd;
        }
    }

    auto IpcClient::request(this IpcClient const& self, std::span<std::string_view const> tokens)
        -> IpcReply {
        auto frame = build_nexus1_frame(tokens);
        if (!frame) return {false, "invalid NEXUS/1 request"};

        sockaddr_un addr{};
        if (self.endpoint_.empty() || self.endpoint_.front() != '/' ||
            self.endpoint_.size() >= sizeof(addr.sun_path)) {
            return {false, "invalid Unix socket endpoint"};
        }
        addr.sun_family = AF_UNIX;
        std::memcpy(addr.sun_path, self.endpoint_.data(), self.endpoint_.size());
        auto const addr_len = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + self.endpoint_.size() + 1);

        int conn_err = 0;
        bool seqpacket = false;
        UniqueFd fd;
#ifdef __linux__
        fd = connect_unix(addr, addr_len, SOCK_SEQPACKET, self.timeout_, conn_err);
        if (fd.get() >= 0) {
            seqpacket = true;
        } else if (conn_err == EPROTOTYPE) {
            fd = connect_unix(addr, addr_len, SOCK_STREAM, self.timeout_, conn_err);
        }
#else
        fd = connect_unix(addr, addr_len, SOCK_STREAM, self.timeout_, conn_err);
#endif
        if (fd.get() < 0) {
            return {false, std::strerror(conn_err ? conn_err : errno)};
        }

#ifdef MSG_NOSIGNAL
        constexpr int kSendFlags = MSG_NOSIGNAL;
#else
        constexpr int kSendFlags = 0;
#endif
        if (seqpacket) {
            ssize_t sn = 0;
            do {
                sn = ::send(fd.get(), frame->data(), frame->size(), kSendFlags);
            } while (sn < 0 && errno == EINTR);
            if (sn != static_cast<ssize_t>(frame->size())) {
                return {false, std::strerror(errno)};
            }
            std::string reply(65536, '\0');
            ssize_t n = 0;
            do {
                n = ::recv(fd.get(), reply.data(), reply.size(), MSG_TRUNC);
            } while (n < 0 && errno == EINTR);
            if (n <= 0) return {false, n == 0 ? "empty control reply" : std::strerror(errno)};
            if (static_cast<std::size_t>(n) > reply.size()) return {false, "reply exceeds 64 KiB limit"};
            reply.resize(static_cast<std::size_t>(n));
            return decode_nexus1_reply(std::move(reply));
        }

        std::size_t sent = 0;
        while (sent < frame->size()) {
            auto n = ::send(fd.get(), frame->data() + sent, frame->size() - sent, kSendFlags);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return {false, std::strerror(errno)};
            sent += static_cast<std::size_t>(n);
        }
        ::shutdown(fd.get(), SHUT_WR);

        std::string reply;
        char buf[4096];
        for (;;) {
            auto n = ::recv(fd.get(), buf, sizeof(buf), 0);
            if (n < 0 && errno == EINTR) continue;
            if (n == 0) break;
            if (n < 0) return {false, std::strerror(errno)};
            if (reply.size() + static_cast<std::size_t>(n) > 65536) return {false, "reply exceeds 64 KiB limit"};
            reply.append(buf, static_cast<std::size_t>(n));
        }
        return decode_nexus1_reply(std::move(reply));
    }
}
