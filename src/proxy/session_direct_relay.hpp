// Fast-path direct TCP relay: zero per-chunk coroutine alloc, adaptive 16->128 KiB
// pooled buffer, non-blocking recv/send burst, batched accounting, hot-flow splice promotion.
#pragma once

        auto relay_direct(Session& session, bool upstream) -> capy::task<bool> {
            auto& input = upstream ? session.client : session.target;
            auto& output = upstream ? session.target : session.client;
            int const in_fd = input.native_handle();
            int const out_fd = output.native_handle();
            if (in_fd < 0 || out_fd < 0) co_return false;
            if (upstream) platform::tune_tcp_low_latency(out_fd);

            std::array<std::uint8_t, 16384> small_buf;
            DirectBufferPool::Lease large_buf;
            std::size_t total_bytes = 0;
            std::size_t burst_bytes = 0;
            std::size_t since_yield = 0;
            bool splice_rejected = false;

            constexpr std::size_t kPromoteLargeBytes = 64 * 1024;
            constexpr std::size_t kPromoteSpliceBytes = 256 * 1024;
            constexpr std::size_t kYieldBurstBytes = 512 * 1024;

            auto flush_accounting = [&]() noexcept {
                if (burst_bytes) {
                    session.count_traffic(upstream, burst_bytes);
                    session.touched = Clock::now();
                    burst_bytes = 0;
                }
            };

            while (!session.closed) {
                if (session.splice_pipes && !splice_rejected && total_bytes >= kPromoteSpliceBytes) {
                    flush_accounting();
                    large_buf.reset();
                    auto transferred = co_await relay_splice(session, upstream, true);
                    if (transferred.has_value()) co_return *transferred;
                    splice_rejected = true;
                }

                if (!large_buf && total_bytes >= kPromoteLargeBytes && session.direct_buffers) {
                    large_buf = session.direct_buffers->try_acquire();
                }

                auto* ptr = large_buf ? large_buf.data() : small_buf.data();
                auto const cap = large_buf ? DirectBufferPool::kBufferSize : small_buf.size();

                ssize_t received = ::recv(in_fd, ptr, cap, MSG_DONTWAIT);
                if (received < 0) {
                    int const err = errno;
                    if (err == EINTR) continue;
                    if (err != EAGAIN && err != EWOULDBLOCK) {
                        flush_accounting();
                        co_return false;
                    }
                    flush_accounting();
                    since_yield = 0;
                    auto [ec, n] = co_await input.read_some(capy::mutable_buffer(ptr, cap));
                    if (ec == capy::cond::eof || (!ec && n == 0)) {
                        session.mark_half_closed();
                        (void)output.shutdown(io::shutdown_send);
                        co_return true;
                    }
                    if (ec || session.closed) co_return false;
                    received = static_cast<ssize_t>(n);
                } else if (received == 0) {
                    flush_accounting();
                    session.mark_half_closed();
                    (void)output.shutdown(io::shutdown_send);
                    co_return true;
                }

                std::optional<std::vector<std::uint8_t>> shaped;
                auto const* send_ptr = static_cast<std::uint8_t const*>(ptr);
                auto len = static_cast<std::size_t>(received);
                if (upstream && session.direct_shaping.pending()) {
                    shaped = shape_direct_first_payload(session, std::span(send_ptr, len));
                    if (shaped) {
                        send_ptr = shaped->data();
                        len = shaped->size();
                    }
                }
                std::size_t off = 0;
                while (off < len && !session.closed) {
                    std::size_t step = len - off;
                    if (shaped && session.direct_shaping.tls_record_fragment && step >= 5 &&
                        send_ptr[off] == 0x16 && send_ptr[off + 1] == 0x03) {
                        auto rec = std::size_t{5} + ((std::size_t{send_ptr[off + 3]} << 8) | send_ptr[off + 4]);
                        if (rec <= step) step = rec;
                    }
                    ssize_t written = ::send(out_fd, send_ptr + off, step, MSG_DONTWAIT | MSG_NOSIGNAL);
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
                            co_return false;
                        }
                        continue;
                    }
                    flush_accounting();
                    co_return false;
                }

                if (since_yield >= kYieldBurstBytes && !session.closed) {
                    flush_accounting();
                    since_yield = 0;
                    co_await YieldToExecutor{};
                }
            }
            flush_accounting();
            co_return false;
        }
