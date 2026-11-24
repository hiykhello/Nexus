module;
#include <cerrno>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/continuation.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/posix_stream_descriptor.hpp>
#include <boost/corosio/tcp_socket.hpp>

module relay;
import std;

namespace relay {
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
        struct WaitSlotGuard {
            bool* slot = nullptr;
            ~WaitSlotGuard() { if (slot) *slot = false; }
        };

        // Direct async IORING_OP_RECV fallback when the peer direction occupies
        // input's single corosio wait_op_ slot (avoids F_DUPFD_CLOEXEC + POLL_ADD
        // waitqueue contention under multi-stream io_uring workloads).
        auto read_wait_fallback(io::tcp_socket& input, io::tcp_socket& output,
            Session& session, bool upstream, std::size_t& burst_delivered,
            std::size_t& sent_since_yield) -> capy::task<std::optional<bool>> {
            DirectBufferPool::Lease pooled = session.direct_buffers ? session.direct_buffers->try_acquire() : DirectBufferPool::Lease{};
            std::array<std::uint8_t, 16384> small;
            auto* ptr = pooled ? pooled.data() : small.data();
            auto const cap = pooled ? DirectBufferPool::kBufferSize : small.size();
            auto [ec, n] = co_await input.read_some(capy::mutable_buffer(ptr, cap));
            if (ec == capy::cond::eof || (!ec && n == 0)) {
                session.mark_half_closed();
                (void)output.shutdown(io::shutdown_send);
                co_return true;
            }
            if (ec || session.closed) co_return false;
            auto buffer = std::span(ptr, n);
            while (!buffer.empty() && !session.closed) {
                int const out_fd = output.native_handle();
                if (out_fd < 0) co_return false;
#ifdef MSG_NOSIGNAL
                constexpr int kSendFlags = MSG_DONTWAIT | MSG_NOSIGNAL;
#else
                constexpr int kSendFlags = MSG_DONTWAIT;
#endif
                ssize_t written = ::send(out_fd, buffer.data(), buffer.size(), kSendFlags);
                if (written > 0) {
                    auto const w = static_cast<std::size_t>(written);
                    burst_delivered += w;
                    sent_since_yield += w;
                    buffer = buffer.subspan(w);
                    continue;
                }
                if (written < 0 && errno == EINTR) continue;
                if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    if (burst_delivered) {
                        session.count_traffic(upstream, burst_delivered);
                        session.touched = Clock::now();
                        burst_delivered = 0;
                    }
                    sent_since_yield = 0;
                    auto [we, wn] = co_await output.write_some(
                        capy::const_buffer(buffer.data(), buffer.size()));
                    if (wn) {
                        burst_delivered += wn;
                        sent_since_yield += wn;
                        buffer = buffer.subspan(wn);
                    }
                    if (we || !wn || session.closed) co_return false;
                    continue;
                }
                co_return false;
            }
            co_return std::nullopt;
        }

        // Direct async IORING_OP_SEND fallback when the peer coroutine occupies
        // output's single wait_op_ slot; drains up to 128 KiB per async op.
        auto write_backpressure_head(SplicePipePool::Pipe const& pipe, io::tcp_socket& output,
            Session& session, std::size_t& remaining, std::size_t& burst_delivered)
            -> capy::task<bool> {
            DirectBufferPool::Lease pooled = session.direct_buffers ? session.direct_buffers->try_acquire() : DirectBufferPool::Lease{};
            std::array<std::uint8_t, 16384> small;
            auto* ptr = pooled ? pooled.data() : small.data();
            auto const cap = pooled ? DirectBufferPool::kBufferSize : small.size();
            auto const want = std::min(remaining, cap);
            ssize_t got = -1;
            do {
                got = ::read(pipe.fd[0], ptr, want);
            } while (got < 0 && errno == EINTR);
            if (got <= 0) co_return false;
            remaining -= static_cast<std::size_t>(got);
            auto buffer = std::span(ptr, static_cast<std::size_t>(got));
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
        if (sized <= 0) sized = ::fcntl(pipe.fd[1], F_SETPIPE_SZ, static_cast<int>(kFallbackPipeSize));
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
#if BOOST_COROSIO_HAVE_LIBURING
        std::size_t const in_idx = upstream ? 0 : 1;
        std::size_t const out_idx = upstream ? 1 : 0;
#endif
        if (session.closed) co_return false;
        if (!already_ready) {
#if BOOST_COROSIO_HAVE_LIBURING
            if (session.splice_wait_busy[in_idx]) co_return std::nullopt;
            session.splice_wait_busy[in_idx] = true;
            WaitSlotGuard wait_guard{&session.splice_wait_busy[in_idx]};
#endif
            auto [ready] = co_await input.wait(io::wait_type::read);
            if (ready || session.closed) co_return false;
        }
        if (session.closed) co_return false;
        auto lease = session.splice_pipes->try_acquire();
        if (!lease) co_return std::nullopt;
        auto const max_cached = std::min(session.splice_pipes->limit(), session.splice_max_idle_pipes);
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
        constexpr std::size_t kYieldBurst = 256 * 1024;
        std::size_t sent_since_yield = 0;

        while (!session.closed) {
            int const in_fd = input.native_handle();
            if (in_fd < 0) {
                flush_accounting();
                co_return false;
            }
            auto received = ::splice(in_fd, nullptr, pipe.fd[1], nullptr, chunk, flags);
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
#if BOOST_COROSIO_HAVE_LIBURING
                if (!session.splice_wait_busy[in_idx]) {
                    session.splice_wait_busy[in_idx] = true;
                    WaitSlotGuard wait_guard{&session.splice_wait_busy[in_idx]};
                    auto [wait_error] = co_await input.wait(io::wait_type::read);
                    if (wait_error || session.closed) co_return false;
                    continue;
                }
                auto fb = co_await read_wait_fallback(
                    input, output, session, upstream, burst_delivered, sent_since_yield);
                if (fb.has_value()) {
                    flush_accounting();
                    co_return *fb;
                }
                continue;
#else
                auto [wait_error] = co_await input.wait(io::wait_type::read);
                if (wait_error || session.closed) co_return false;
                continue;
#endif
            }
            if (received == 0) {
                flush_accounting();
                session.mark_half_closed();
                (void)output.shutdown(io::shutdown_send);
                co_return true;
            }
            remaining = static_cast<std::size_t>(received);
            while (remaining && !session.closed) {
                int const out_fd = output.native_handle();
                if (out_fd < 0) {
                    flush_accounting();
                    co_return false;
                }
                auto written = ::splice(pipe.fd[0], nullptr, out_fd, nullptr, remaining, flags);
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
                if (!session.splice_wait_busy[out_idx]) {
                    session.splice_wait_busy[out_idx] = true;
                    WaitSlotGuard wait_guard{&session.splice_wait_busy[out_idx]};
                    auto [wait_error] = co_await output.wait(io::wait_type::write);
                    if (wait_error || session.closed) co_return false;
                } else if (!co_await write_backpressure_head(pipe, output, session, remaining, burst_delivered)) {
                    flush_accounting();
                    co_return false;
                }
#else
                auto [wait_error] = co_await output.wait(io::wait_type::write);
                if (wait_error || session.closed) co_return false;
#endif
            }
            auto const active_sessions = session.registry ? session.registry->size() : std::size_t{1};
            auto const yield_limit = active_sessions <= 1 ? (kYieldBurst * 8) :
                                     active_sessions <= 32 ? (kYieldBurst * 4) : kYieldBurst;
            if (!session.closed && sent_since_yield >= yield_limit) {
                flush_accounting();
                sent_since_yield = 0;
                co_await YieldToExecutor{};
            }
        }
        flush_accounting();
        co_return false;
    }
}
