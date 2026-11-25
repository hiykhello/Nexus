// Fast-path direct TCP relay with pooled buffer burst I/O and splice promotion.
module;
#include <cerrno>
#include <sys/socket.h>

module relay;
import :session_internal;
import std;
import capy;
import corosio;
import platform.socket_options;

namespace relay::session_detail {
    namespace {
        enum class DirectOutcome : std::uint8_t { done_eof, failed, promote_splice };

        [[gnu::noinline]] auto relay_direct_buffered(Session& session, bool upstream,
            bool allow_splice) -> capy::task<DirectOutcome> {
            auto& input = upstream ? session.client : session.target;
            auto& output = upstream ? session.target : session.client;
            int const initial_out_fd = output.native_handle();
            if (input.native_handle() < 0 || initial_out_fd < 0) co_return DirectOutcome::failed;
            if (upstream && allow_splice && (!session.direct_tcp_options || !session.direct_tcp_options->configured()))
                platform::tune_tcp_low_latency(initial_out_fd);

            std::array<std::uint8_t, 16384> small_buf;
            DirectBufferPool::Lease large_buf;
            std::size_t total_bytes = 0;
            std::size_t burst_bytes = 0;
            std::size_t since_yield = 0;
            bool try_nonblock_read = upstream;

            constexpr std::size_t kPromoteLargeBytes = 64 * 1024;
            constexpr std::size_t kPromoteSpliceBytes = 16 * 1024;
            constexpr std::size_t kYieldBurstBytes = 2 * 1024 * 1024;

            auto flush_accounting = [&]() noexcept {
                if (burst_bytes) {
                    session.count_traffic(upstream, burst_bytes);
                    session.touched = Clock::now();
                    burst_bytes = 0;
                }
            };

            while (!session.closed) {
                if (allow_splice && session.splice_pipes && !session.direct_shaping.pending() &&
                    total_bytes >= kPromoteSpliceBytes) {
                    flush_accounting();
                    large_buf.reset();
                    co_return DirectOutcome::promote_splice;
                }

                if (!large_buf && total_bytes >= kPromoteLargeBytes && session.direct_buffers) {
                    large_buf = session.direct_buffers->try_acquire();
                }

                auto* ptr = large_buf ? large_buf.data() : small_buf.data();
                auto const cap = large_buf ? DirectBufferPool::kBufferSize : small_buf.size();

                ssize_t received = -1;
                bool need_async_read = !try_nonblock_read;
                if (try_nonblock_read) {
                    int const in_fd = input.native_handle();
                    if (in_fd < 0) {
                        flush_accounting();
                        co_return DirectOutcome::failed;
                    }
                    received = ::recv(in_fd, ptr, cap, MSG_DONTWAIT);
                    if (received < 0) {
                        int const err = errno;
                        if (err == EINTR) continue;
                        if (err != EAGAIN && err != EWOULDBLOCK) {
                            flush_accounting();
                            co_return DirectOutcome::failed;
                        }
                        need_async_read = true;
                    } else if (received == 0) {
                        flush_accounting();
                        session.mark_half_closed();
                        (void)output.shutdown(io::shutdown_send);
                        co_return DirectOutcome::done_eof;
                    }
                }
                if (need_async_read) {
                    flush_accounting();
                    since_yield = 0;
                    auto [ec, n] = co_await input.read_some(capy::mutable_buffer(ptr, cap));
                    if (ec == capy::cond::eof || (!ec && n == 0)) {
                        session.mark_half_closed();
                        (void)output.shutdown(io::shutdown_send);
                        co_return DirectOutcome::done_eof;
                    }
                    if (ec || session.closed) co_return DirectOutcome::failed;
                    received = static_cast<ssize_t>(n);
                    try_nonblock_read = true;
                }

                std::optional<std::vector<std::uint8_t>> shaped;
                auto const* send_ptr = static_cast<std::uint8_t const*>(ptr);
                auto len = static_cast<std::size_t>(received);
                std::size_t prefix_len = 0;
                if (upstream && session.direct_shaping.pending()) {
                    shaped = shape_direct_first_payload(session, std::span(send_ptr, len));
                    if (shaped) {
                        send_ptr = shaped->data();
                        len = shaped->size();
                        prefix_len = std::min<std::size_t>(session.direct_shaping.tcp_prefix_len, len);
                    }
                }
                std::size_t off = 0;
                while (off < len && !session.closed) {
                    std::size_t step = len - off;
                    if (shaped && off < prefix_len) {
                        step = prefix_len - off;
                    } else if (shaped && session.direct_shaping.tls_record_fragment && step >= 5 &&
                        send_ptr[off] == 0x16 && send_ptr[off + 1] == 0x03) {
                        auto rec = std::size_t{5} + ((std::size_t{send_ptr[off + 3]} << 8) | send_ptr[off + 4]);
                        if (rec <= step) step = rec;
                    }
#ifdef MSG_NOSIGNAL
                    constexpr int kDirectSendFlags = MSG_DONTWAIT | MSG_NOSIGNAL;
#else
                    constexpr int kDirectSendFlags = MSG_DONTWAIT;
#endif
                    int const out_fd = output.native_handle();
                    if (out_fd < 0) {
                        flush_accounting();
                        co_return DirectOutcome::failed;
                    }
                    ssize_t written = ::send(out_fd, send_ptr + off, step, kDirectSendFlags);
                    if (written > 0) {
                        auto const w = static_cast<std::size_t>(written);
                        off += w;
                        burst_bytes += w;
                        total_bytes += w;
                        since_yield += w;
                        continue;
                    }
                    if (written < 0 && errno == EINTR) continue;
                    if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        flush_accounting();
                        since_yield = 0;
                        auto [we, wn] = co_await output.write_some(capy::const_buffer(send_ptr + off, step));
                        if (wn) {
                            off += wn;
                            burst_bytes += wn;
                            total_bytes += wn;
                        }
                        if (we || !wn || session.closed) {
                            flush_accounting();
                            co_return DirectOutcome::failed;
                        }
                        continue;
                    }
                    flush_accounting();
                    co_return DirectOutcome::failed;
                }

                if (since_yield >= kYieldBurstBytes && !session.closed) {
                    flush_accounting();
                    since_yield = 0;
                    co_await YieldToExecutor{};
                }
            }
            flush_accounting();
            co_return DirectOutcome::failed;
        }
    }

    auto relay_direct(Session& session, bool upstream) -> capy::task<bool> {
        auto outcome = co_await relay_direct_buffered(session, upstream, true);
        if (outcome != DirectOutcome::promote_splice)
            co_return outcome == DirectOutcome::done_eof;
        // 16 KiB small_buf frame is destroyed before relay_splice begins.
        auto transferred = co_await relay_splice(session, upstream, true);
        if (transferred.has_value()) co_return *transferred;
        if (session.closed) co_return false;
        auto fallback = co_await relay_direct_buffered(session, upstream, false);
        co_return fallback == DirectOutcome::done_eof;
    }
}
