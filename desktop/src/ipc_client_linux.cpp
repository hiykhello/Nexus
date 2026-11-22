module;

#include <cerrno>
#include <cstddef>
#include <cstring>
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
            explicit UniqueFd(int fd) noexcept : fd_(fd) {}
            ~UniqueFd() { if (fd_ >= 0) ::close(fd_); }
            UniqueFd(UniqueFd const&) = delete;
            auto operator=(UniqueFd const&) -> UniqueFd& = delete;
            [[nodiscard]] auto get(this UniqueFd const& self) noexcept -> int { return self.fd_; }
        };
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

        UniqueFd fd(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
        if (fd.get() < 0) return {false, std::strerror(errno)};

        timeval tv{};
        tv.tv_sec = static_cast<time_t>(self.timeout_.count() / 1000);
        tv.tv_usec = static_cast<suseconds_t>((self.timeout_.count() % 1000) * 1000);
        ::setsockopt(fd.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ::setsockopt(fd.get(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        auto const addr_len = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + self.endpoint_.size() + 1);
        if (::connect(fd.get(), reinterpret_cast<sockaddr const*>(&addr), addr_len) != 0) {
            return {false, std::strerror(errno)};
        }

        std::size_t sent = 0;
        while (sent < frame->size()) {
            auto n = ::send(fd.get(), frame->data() + sent, frame->size() - sent, MSG_NOSIGNAL);
            if (n <= 0) return {false, std::strerror(errno)};
            sent += static_cast<std::size_t>(n);
        }
        ::shutdown(fd.get(), SHUT_WR);

        std::string reply;
        char buf[4096];
        for (;;) {
            auto n = ::recv(fd.get(), buf, sizeof(buf), 0);
            if (n == 0) break;
            if (n < 0) return {false, std::strerror(errno)};
            if (reply.size() + static_cast<std::size_t>(n) > 65536) return {false, "reply exceeds 64 KiB limit"};
            reply.append(buf, static_cast<std::size_t>(n));
        }
        return {!reply.empty(), std::move(reply)};
    }
}
