module;
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/uio.h>
#include <unistd.h>
export module logging.fd;
import std;
import logging.sink;

namespace logging {
    export class FileDescriptor {
        int fd_;
    public:
        explicit FileDescriptor(int fd) noexcept : fd_(fd) {}
        FileDescriptor(FileDescriptor&& other) noexcept : fd_(std::exchange(other.fd_, -1)) {}
        auto operator=(this FileDescriptor& self, FileDescriptor&& other) noexcept -> FileDescriptor& {
            std::swap(self.fd_, other.fd_);
            return self;
        }
        ~FileDescriptor() { if (fd_ >= 0) ::close(fd_); }
        auto get(this FileDescriptor const& self) noexcept -> int { return self.fd_; }
    };

    export auto system_error(int error) noexcept -> std::error_code {
        return {error, std::generic_category()};
    }

    namespace {
        class PipeSignal {
            sigset_t set_{};
            sigset_t previous_{};
            int error_ = 0;
            bool pending_ = false;
        public:
            PipeSignal() noexcept {
                sigemptyset(&set_);
                sigaddset(&set_, SIGPIPE);
                error_ = pthread_sigmask(SIG_BLOCK, &set_, &previous_);
                if (error_ == 0) {
                    sigset_t pending{};
                    sigpending(&pending);
                    pending_ = sigismember(&pending, SIGPIPE) == 1;
                }
            }
            ~PipeSignal() { if (error_ == 0) pthread_sigmask(SIG_SETMASK, &previous_, nullptr); }
            auto error(this PipeSignal const& self) noexcept -> int { return self.error_; }
            auto consume(this PipeSignal const& self) noexcept -> void {
                if (self.pending_) return;
#if defined(__linux__)
                timespec now{};
                while (sigtimedwait(&self.set_, nullptr, &now) < 0 && errno == EINTR) {}
#else
                sigset_t pending{};
                if (sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE) == 1) {
                    int signo = 0;
                    (void)sigwait(&self.set_, &signo);
                }
#endif
            }
        };

        auto write_vectors(int fd, std::span<iovec> pending) noexcept -> SinkResult {
            PipeSignal signal;
            if (signal.error()) return std::unexpected(system_error(signal.error()));

            while (!pending.empty()) {
                auto written = ::writev(fd, pending.data(), static_cast<int>(pending.size()));
                if (written < 0) {
                    auto error = errno;
                    if (error == EINTR) continue;
                    if (error == EAGAIN) {
                        pollfd descriptor{fd, POLLOUT, 0};
                        int ready;
                        do { ready = ::poll(&descriptor, 1, -1); } while (ready < 0 && errno == EINTR);
                        if (ready > 0) continue;
                        error = errno;
                    }
                    if (error == EPIPE) signal.consume();
                    return std::unexpected(system_error(error));
                }
                if (written == 0) return std::unexpected(system_error(EIO));
                auto bytes = static_cast<std::size_t>(written);
                while (!pending.empty() && bytes >= pending.front().iov_len) {
                    bytes -= pending.front().iov_len;
                    pending = pending.subspan(1);
                }
                if (!pending.empty()) {
                    auto& next = pending.front();
                    next.iov_base = static_cast<char*>(next.iov_base) + bytes;
                    next.iov_len -= bytes;
                }
            }
            return {};
        }
    }

    export auto write_lines(int fd, std::span<SinkRecord const> lines) noexcept -> SinkResult {
        while (!lines.empty()) {
            std::array<iovec, batch_capacity> vectors;
            auto count = std::min(lines.size(), vectors.size());
            std::size_t used = 0;
            for (auto const& record : lines.first(count)) {
                auto line = record.line;
                if (!line.empty()) vectors[used++] = {const_cast<char*>(line.data()), line.size()};
            }
            if (used != 0) {
                auto result = write_vectors(fd, std::span(vectors).first(used));
                if (!result) return result;
            }
            lines = lines.subspan(count);
        }
        return {};
    }
}
