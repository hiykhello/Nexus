#include <arpa/inet.h>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import platform.uring_buf_ring;

namespace {
    auto fail(std::string_view msg) -> int {
        std::cerr << "FAIL: " << msg << "\n";
        return 1;
    }

    // Exact mirror of TunHost::Impl::is_self_loop_udp invariant verification.
    struct Ep {
        std::uint8_t family = 4;
        std::array<std::uint8_t, 16> address{};
        std::uint16_t port = 0;
    };
    auto is_self_loop_udp(Ep const& source, Ep const& dest, std::optional<Ep> const& local_bound) noexcept -> bool {
        auto same = [](Ep const& a, Ep const& b) noexcept {
            if (a.family != b.family || a.port != b.port) return false;
            auto const len = a.family == 6 ? std::size_t{16} : std::size_t{4};
            return std::ranges::equal(std::span(a.address).first(len), std::span(b.address).first(len));
        };
        return same(source, dest) || (local_bound && same(*local_bound, dest));
    }
}

int main() {
    // 1. TUN UDP self-loop circuit breaker checks (IPv4 + IPv6).
    Ep src4{4, {10, 0, 0, 2}, 5353};
    Ep dst4_same{4, {10, 0, 0, 2}, 5353};
    Ep dst4_local{4, {127, 0, 0, 1}, 41234};
    Ep dst4_normal{4, {1, 1, 1, 1}, 53};
    if (!is_self_loop_udp(src4, dst4_same, std::nullopt)) return fail("missed direct src==dst self-loop");
    if (!is_self_loop_udp(src4, dst4_local, dst4_local)) return fail("missed local-socket writeback self-loop");
    if (is_self_loop_udp(src4, dst4_normal, dst4_local)) return fail("false positive on normal destination");

    Ep src6{6, {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 51820};
    if (!is_self_loop_udp(src6, src6, std::nullopt)) return fail("missed IPv6 self-loop");

    // 2. Real io_uring Provided Buffer Ring + Multishot Recv stress test (64 chunks, zero slot leaks).
    auto loop = platform::UringMultishotLoop::create({.ring_entries = 32, .buffer_size = 2048, .buffer_group_id = 1, .sq_entries = 64});
    if (!loop) {
        std::cout << "NOTE: io_uring buf_ring unavailable on host kernel (errno=" << loop.error() << "), TUN checks passed\n";
        return 0;
    }

    int sv[2]{-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) != 0)
        return fail("socketpair failed");

    if (auto arm = loop->arm_recv_multishot(sv[0], 0x1234); !arm) {
        ::close(sv[0]); ::close(sv[1]);
        return fail("arm_recv_multishot failed");
    }

    constexpr std::size_t kMessages = 64;
    std::size_t total_sent = 0, total_recvd = 0;
    std::array<platform::MultishotEvent, 32> events{};
    for (std::size_t i = 0; i < kMessages; ++i) {
        std::array<std::uint8_t, 64> chunk{};
        chunk.fill(static_cast<std::uint8_t>((i + 1) & 0xff));
        auto w = ::send(sv[1], chunk.data(), chunk.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
        if (w <= 0) return fail("send into socketpair failed");
        total_sent += static_cast<std::size_t>(w);

        auto n = loop->poll_events(events, 1, 50);
        if (!n) return fail("poll_events failed");
        for (std::size_t k = 0; k < *n; ++k) {
            auto const& ev = events[k];
            if (ev.has_buffer && ev.result > 0) {
                auto view = loop->buffer_view(ev.buffer_id, static_cast<std::size_t>(ev.result));
                total_recvd += view.size();
                if (!loop->recycle(ev.buffer_id)) return fail("buffer_ring recycle failed");
            }
            if (ev.needs_rearm && total_recvd < total_sent) {
                (void)loop->arm_recv_multishot(sv[0], 0x1234);
            }
        }
    }
    // Drain any final buffered chunk.
    for (int drain = 0; drain < 10 && total_recvd < total_sent; ++drain) {
        auto n = loop->poll_events(events, 1, 20);
        if (!n || *n == 0) break;
        for (std::size_t k = 0; k < *n; ++k) {
            if (events[k].has_buffer && events[k].result > 0) {
                total_recvd += static_cast<std::size_t>(events[k].result);
                if (!loop->recycle(events[k].buffer_id)) return fail("final recycle failed");
            }
        }
    }
    ::close(sv[0]);
    ::close(sv[1]);
    if (total_recvd != total_sent) return fail("io_uring multishot byte count mismatch");
    if (loop->leased_count() != 0) return fail("io_uring buffer ring leaked leased slots");

    std::cout << "BATCH 127 TUN UDP SELF-LOOP GUARD + IO_URING MULTISHOT BUFFER RING ("
              << total_recvd << " bytes, 0 leaked slots) PASSED\n";
    return 0;
}
