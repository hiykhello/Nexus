#include <cerrno>
#include <sys/socket.h>
#include <unistd.h>

import std;
import platform.uring_buf_ring;

namespace {
    auto test_validation_and_budget() -> int {
        // Non-power-of-two ring_entries rejected
        if (platform::UringMultishotLoop::create({.ring_entries = 10})) return 1;
        // Too small buffer rejected
        if (platform::UringMultishotLoop::create({.ring_entries = 8, .buffer_size = 64})) return 2;
        // Over 16 MiB memory budget rejected (4096 * 8192 = 32 MiB)
        if (platform::UringMultishotLoop::create({.ring_entries = 4096, .buffer_size = 8192})) return 3;
        return 0;
    }

    auto test_tcp_multishot_burst_and_reuse() -> int {
        int sv[2]{-1, -1};
        if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) != 0) return 10;

        auto loop = platform::UringMultishotLoop::create({
            .ring_entries = 16,
            .buffer_size = 1024,
            .buffer_group_id = 7,
            .sq_entries = 32,
        });
        if (!loop) { ::close(sv[0]); ::close(sv[1]); return 11; }

        if (!loop->arm_recv_multishot(sv[0], 1001)) {
            ::close(sv[0]); ::close(sv[1]); return 12;
        }

        // Send 200 distinct 256-byte messages (far exceeding 16 ring slots -> proves continuous multishot & buffer recycle!)
        constexpr std::size_t kMessages = 200;
        constexpr std::size_t kChunk = 256;
        std::vector<std::uint8_t> expected;
        expected.reserve(kMessages * kChunk);
        std::vector<std::uint8_t> received;
        received.reserve(kMessages * kChunk);

        std::array<platform::MultishotEvent, 32> events{};
        std::size_t sent = 0;
        while (received.size() < kMessages * kChunk) {
            if (sent < kMessages) {
                std::array<std::uint8_t, kChunk> msg{};
                msg.fill(static_cast<std::uint8_t>(sent & 0xffu));
                auto w = ::send(sv[1], msg.data(), msg.size(), MSG_DONTWAIT);
                if (w == static_cast<ssize_t>(kChunk)) {
                    expected.insert(expected.end(), msg.begin(), msg.end());
                    ++sent;
                }
            }
            auto n = loop->poll_events(events, 1, 100);
            if (!n) { ::close(sv[0]); ::close(sv[1]); return 13; }
            for (std::size_t i = 0; i < *n; ++i) {
                auto const& ev = events[i];
                if (ev.tag != 1001) { ::close(sv[0]); ::close(sv[1]); return 14; }
                if (ev.result > 0 && ev.has_buffer) {
                    auto view = loop->buffer_view(ev.buffer_id, static_cast<std::size_t>(ev.result));
                    received.insert(received.end(), view.begin(), view.end());
                    if (!loop->recycle(ev.buffer_id)) { ::close(sv[0]); ::close(sv[1]); return 15; }
                }
                if (ev.needs_rearm) {
                    if (!loop->arm_recv_multishot(sv[0], 1001)) { ::close(sv[0]); ::close(sv[1]); return 16; }
                }
            }
        }

        auto st = loop->stats();
        ::close(sv[1]);
        (void)loop->cancel_fd(sv[0]);
        (void)loop->poll_events(events, 0, 10);
        ::close(sv[0]);

        if (received != expected) return 17;
        if (loop->leased_count() != 0) return 18;
        if (st.multishot_hits == 0) return 19; // Must actually deliver IORING_CQE_F_MORE!
        if (st.rearms > 10) return 20;         // Far fewer SQE submissions than 200 chunks!
        std::cout << "io_uring multishot stream: chunks=" << kMessages
                  << " cqes=" << st.cqes_total
                  << " multishot_hits=" << st.multishot_hits
                  << " rearms=" << st.rearms
                  << " bytes=" << st.bytes_received << '\n';
        return 0;
    }

    auto test_enobufs_backpressure_and_recovery() -> int {
        int sv[2]{-1, -1};
        if (::socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) != 0) return 30;

        // Tiny 4-buffer ring: intentionally hold all 4 buffers to trigger real kernel -ENOBUFS!
        auto loop = platform::UringMultishotLoop::create({
            .ring_entries = 4,
            .buffer_size = 512,
            .buffer_group_id = 9,
            .sq_entries = 16,
        });
        if (!loop) { ::close(sv[0]); ::close(sv[1]); return 31; }
        if (!loop->arm_recv_multishot(sv[0], 2002)) { ::close(sv[0]); ::close(sv[1]); return 32; }

        // Push 6 datagrams while withholding recycle -> kernel consumes 4 buffers and returns -ENOBUFS on the 5th!
        for (int i = 0; i < 6; ++i) {
            std::array<std::uint8_t, 32> dgram{};
            dgram.fill(static_cast<std::uint8_t>(0x30 + i));
            if (::send(sv[1], dgram.data(), dgram.size(), MSG_DONTWAIT) != 32) {
                ::close(sv[0]); ::close(sv[1]); return 33;
            }
        }

        std::vector<std::uint16_t> held;
        std::array<platform::MultishotEvent, 16> events{};
        bool saw_enobufs = false;
        for (int round = 0; round < 10 && !saw_enobufs; ++round) {
            auto n = loop->poll_events(events, 1, 100);
            if (!n) { ::close(sv[0]); ::close(sv[1]); return 34; }
            for (std::size_t i = 0; i < *n; ++i) {
                if (events[i].has_buffer && events[i].result > 0) held.push_back(events[i].buffer_id);
                if (events[i].result == -ENOBUFS) saw_enobufs = true;
            }
        }
        if (!saw_enobufs || held.size() != 4 || loop->leased_count() != 4) {
            ::close(sv[0]); ::close(sv[1]); return 35;
        }

        // Recycle all 4 buffers and re-arm -> remaining 2 datagrams must arrive cleanly!
        for (auto bid : held) {
            if (!loop->recycle(bid)) { ::close(sv[0]); ::close(sv[1]); return 36; }
        }
        if (loop->leased_count() != 0) { ::close(sv[0]); ::close(sv[1]); return 37; }
        if (!loop->arm_recv_multishot(sv[0], 2002)) { ::close(sv[0]); ::close(sv[1]); return 38; }

        int recovered = 0;
        for (int round = 0; round < 10 && recovered < 2; ++round) {
            auto n = loop->poll_events(events, 1, 100);
            if (!n) { ::close(sv[0]); ::close(sv[1]); return 39; }
            for (std::size_t i = 0; i < *n; ++i) {
                if (events[i].has_buffer && events[i].result == 32) {
                    ++recovered;
                    if (!loop->recycle(events[i].buffer_id)) { ::close(sv[0]); ::close(sv[1]); return 40; }
                }
            }
        }
        auto st = loop->stats();
        (void)loop->cancel_fd(sv[0]);
        (void)loop->poll_events(events, 0, 10);
        ::close(sv[0]);
        ::close(sv[1]);

        if (recovered != 2 || st.enobufs_count == 0 || loop->leased_count() != 0) return 41;
        std::cout << "io_uring ENOBUFS backpressure + recovery passed (enobufs=" << st.enobufs_count
                  << " recovered=" << recovered << ")\n";
        return 0;
    }
}

int main() {
    if (auto rc = test_validation_and_budget(); rc != 0) {
        std::cerr << "validation test failed: " << rc << '\n';
        return rc;
    }
    if (auto rc = test_tcp_multishot_burst_and_reuse(); rc != 0) {
        std::cerr << "multishot stream test failed: " << rc << '\n';
        return rc;
    }
    if (auto rc = test_enobufs_backpressure_and_recovery(); rc != 0) {
        std::cerr << "enobufs recovery test failed: " << rc << '\n';
        return rc;
    }
    std::cout << "ALL BATCH 96C IO_URING PROVIDED BUFFER RING & MULTISHOT RECV TESTS PASSED\n";
    return 0;
}
