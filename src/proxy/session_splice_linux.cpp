module;
#include <cerrno>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/continuation.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/tcp_socket.hpp>

module proxy;
import std;

namespace proxy {
    namespace {
        auto close_pipe(SplicePipePool::Pipe& pipe) noexcept -> void {
            if (pipe.fd[0] >= 0) ::close(pipe.fd[0]);
            if (pipe.fd[1] >= 0) ::close(pipe.fd[1]);
            pipe.fd[0] = -1;
            pipe.fd[1] = -1;
        }

        auto splice_unavailable(int error) noexcept -> bool {
            return error == EINVAL || error == ENOSYS || error == EOPNOTSUPP ||
                error == EPERM || error == EACCES;
        }

        // Preserve bytes already removed from TCP when splice is unavailable.
        auto drain_splice_pipe(SplicePipePool::Pipe const& pipe, io::tcp_socket& output,
            Session& session, bool upstream, std::size_t& remaining) -> capy::task<bool> {
            std::array<std::byte, 16384> bytes;
            std::size_t delivered_bytes = 0;
            auto flush = [&]() noexcept {
                if (delivered_bytes) {
                    session.count_traffic(upstream, delivered_bytes);
                    session.touched = Clock::now();
                    delivered_bytes = 0;
                }
            };
            while (remaining && !session.closed) {
                auto size = ::read(pipe.fd[0], bytes.data(), std::min(remaining, bytes.size()));
                if (size < 0 && errno == EINTR) continue;
                if (size <= 0) {
                    flush();
                    co_return false;
                }
                auto buffer = std::span(bytes).first(static_cast<std::size_t>(size));
                remaining -= buffer.size();
                while (!buffer.empty() && !session.closed) {
                    auto [error, written] = co_await output.write_some(
                        capy::const_buffer(buffer.data(), buffer.size()));
                    if (written) delivered_bytes += written;
                    if (error || !written) {
                        flush();
                        co_return false;
                    }
                    buffer = buffer.subspan(written);
                }
            }
            flush();
            co_return !session.closed;
        }

#if BOOST_COROSIO_HAVE_LIBURING
        // On io_uring, Corosio shares one wait_op_ per socket, so the reverse
        // direction may hold wait(read) on output. Writing a single 4 KiB head
        // chunk uses output's independent wr_ SQE to wait for send-buffer space
        // without conflict, then resumes zero-copy kernel splice for the rest.
        auto write_backpressure_head(SplicePipePool::Pipe const& pipe, io::tcp_socket& output,
            Session& session, std::size_t& remaining, std::size_t& burst_delivered)
            -> capy::task<bool> {
            std::array<std::byte, 4096> head;
            auto const want = std::min(remaining, head.size());
            ssize_t got = -1;
            do {
                got = ::read(pipe.fd[0], head.data(), want);
            } while (got < 0 && errno == EINTR);
            if (got <= 0) co_return false;
            remaining -= static_cast<std::size_t>(got);
            auto buffer = std::span(head).first(static_cast<std::size_t>(got));
            while (!buffer.empty() && !session.closed) {
                auto [error, written] = co_await output.write_some(
                    capy::const_buffer(buffer.data(), buffer.size()));
                if (written) burst_delivered += written;
                if (error || !written) co_return false;
                buffer = buffer.subspan(written);
            }
            co_return !session.closed;
        }
#endif
    }

    auto SplicePipePool::acquire() noexcept -> Pipe {
        if (!free_.empty()) {
            auto pipe = free_.back().pipe;
            free_.pop_back();
            return pipe;
        }
        Pipe pipe;
        if (::pipe2(pipe.fd, O_CLOEXEC | O_NONBLOCK) < 0) return {};
#ifdef F_SETPIPE_SZ
        int sized = ::fcntl(pipe.fd[1], F_SETPIPE_SZ, static_cast<int>(kTargetPipeSize));
        if (sized > 0) pipe.capacity = static_cast<std::size_t>(sized);
#endif
        return pipe;
    }

    auto SplicePipePool::release(Pipe pipe, bool clean, std::size_t max_cached,
        Clock::time_point now) noexcept -> void {
        if (!pipe.valid()) return;
        if (clean && free_.size() < max_cached) {
            try {
                free_.push_back({pipe, now});
                return;
            } catch (...) {}
        }
        close_pipe(pipe);
    }

    auto SplicePipePool::reap(Clock::time_point now) noexcept -> void {
        if (free_.empty()) return;
        std::erase_if(free_, [now](Entry& entry) {
            if (now - entry.idle_since >= kIdleTtl) {
                close_pipe(entry.pipe);
                return true;
            }
            return false;
        });
    }

    auto SplicePipePool::clear() noexcept -> void {
        for (auto& entry : free_) close_pipe(entry.pipe);
        free_.clear();
    }

    auto Server::set_tcp_splice_pipes(std::size_t maximum) -> bool {
        if (running || (listener && listener->is_open()) || !workers.empty() || quota.used() != 0) return false;
        if (maximum) {
            struct sigaction action{};
            if (::sigaction(SIGPIPE, nullptr, &action) < 0 || action.sa_handler != SIG_IGN) return false;
            splice_pipes.emplace(maximum);
        } else splice_pipes.reset();
        return true;
    }

    auto relay_splice(Session& session, bool upstream, bool already_ready)
        -> capy::task<std::optional<bool>> {
        auto& input = upstream ? session.client : session.target;
        auto& output = upstream ? session.target : session.client;
        if (!already_ready) {
            auto [ready] = co_await input.wait(io::wait_type::read);
            if (ready || session.closed) co_return false;
        }
        auto lease = session.splice_pipes->try_acquire();
        if (!lease) co_return std::nullopt;
        auto const max_cached = session.splice_pipes->limit();
        auto pipe = session.splice_pipe_pool ? session.splice_pipe_pool->acquire() : SplicePipePool::Pipe{};
        if (!pipe.valid()) co_return std::nullopt;

        std::size_t remaining = 0;
        std::size_t burst_delivered = 0;
        auto flush_accounting = [&]() noexcept {
            if (burst_delivered) {
                session.count_traffic(upstream, burst_delivered);
                session.touched = Clock::now();
                burst_delivered = 0;
            }
        };
        struct PipeGuard {
            SplicePipePool* pool;
            SplicePipePool::Pipe pipe;
            std::size_t const& remaining;
            std::size_t max_cached;
            ~PipeGuard() {
                if (pool) pool->release(pipe, remaining == 0, max_cached, Clock::now());
                else close_pipe(pipe);
            }
        } guard{session.splice_pipe_pool, pipe, remaining, max_cached};

        constexpr auto flags = SPLICE_F_MOVE | SPLICE_F_NONBLOCK;
        auto const chunk = std::min<std::size_t>(pipe.capacity, SplicePipePool::kTargetPipeSize);
        constexpr std::size_t kYieldBurst = 2 * 1024 * 1024;
        std::size_t sent_since_yield = 0;

        while (!session.closed) {
            auto received = ::splice(input.native_handle(), nullptr, pipe.fd[1], nullptr, chunk, flags);
            if (received < 0) {
                auto error = errno;
                if (error == EINTR) continue;
                if (splice_unavailable(error)) {
                    flush_accounting();
                    co_return std::nullopt;
                }
                if (error != EAGAIN) {
                    flush_accounting();
                    co_return false;
                }
                flush_accounting();
                sent_since_yield = 0;
                auto [wait_error] = co_await input.wait(io::wait_type::read);
                if (wait_error) co_return false;
                continue;
            }
            if (received == 0) {
                flush_accounting();
                session.mark_half_closed();
                (void)output.shutdown(io::shutdown_send);
                co_return true;
            }
            remaining = static_cast<std::size_t>(received);
            while (remaining && !session.closed) {
                auto written = ::splice(pipe.fd[0], nullptr, output.native_handle(), nullptr, remaining, flags);
                if (written > 0) {
                    auto size = static_cast<std::size_t>(written);
                    burst_delivered += size;
                    remaining -= size;
                    sent_since_yield += size;
                    continue;
                }
                if (written == 0) {
                    flush_accounting();
                    co_return false;
                }
                auto error = errno;
                if (error == EINTR) continue;
                auto backpressure = error == EAGAIN;
                if (!backpressure && !splice_unavailable(error)) {
                    flush_accounting();
                    co_return false;
                }
                flush_accounting();
                sent_since_yield = 0;
                if (!backpressure) {
                    if (!co_await drain_splice_pipe(pipe, output, session, upstream, remaining)) co_return false;
                    co_return std::nullopt;
                }
#if BOOST_COROSIO_HAVE_LIBURING
                if (!co_await write_backpressure_head(pipe, output, session, remaining, burst_delivered)) {
                    flush_accounting();
                    co_return false;
                }
#else
                auto [wait_error] = co_await output.wait(io::wait_type::write);
                if (wait_error || session.closed) co_return false;
#endif
            }
            if (!session.closed && sent_since_yield >= kYieldBurst) {
                flush_accounting();
                sent_since_yield = 0;
                co_await YieldToExecutor{};
            }
        }
        flush_accounting();
        co_return false;
    }
}
