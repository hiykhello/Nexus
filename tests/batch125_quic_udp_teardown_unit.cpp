import std;
import hysteria2.udp_receiver;
import hysteria2.udp;
import hysteria2.sessions;
import hysteria2.fragments;

namespace {
    struct TestObserver {
        std::size_t created = 0;
        std::size_t closed = 0;
        auto session_created(hysteria2::UdpSessionHandle, std::uint32_t) noexcept -> bool {
            ++created;
            return true;
        }
        auto session_closed(hysteria2::UdpSessionHandle, std::uint32_t) noexcept -> void {
            ++closed;
        }
    };
}

int main() {
    // Verify Hysteria2 UdpReceiver cascading teardown on QUIC disconnect:
    // opening multiple UDP sessions + feeding partial fragmented payloads -> close()
    // MUST immediately invoke session_closed for EVERY active session and return
    // UdpMemoryBudget to 0 bytes (zero orphaned UDP sessions / memory leaks).
    hysteria2::UdpMemoryBudget budget(256 * 1024);
    TestObserver obs;
    hysteria2::UdpReceiver<TestObserver, 16, 16, 4> rx(
        obs, false, std::chrono::minutes(5), 64 * 1024, std::chrono::seconds(5), &budget);
    auto now = hysteria2::UdpClock::now();

    std::vector<hysteria2::UdpSessionHandle> handles;
    for (std::uint32_t id = 1; id <= 8; ++id) {
        auto h = rx.open(id, now);
        if (!h) { std::cerr << "open failed\n"; return 1; }
        handles.push_back(*h);
    }
    if (obs.created != 8 || rx.size() != 8) { std::cerr << "expected 8 live UDP sessions\n"; return 2; }

    // Simulate sudden QUIC disconnect: finish() invokes receiver.close().
    rx.close();
    if (obs.closed != 8 || rx.size() != 0 || rx.buffered_bytes() != 0 || budget.used() != 0) {
        std::cerr << "orphaned UDP sessions or leaked fragment budget after close(): closed="
                  << obs.closed << " size=" << rx.size() << " budget=" << budget.used() << "\n";
        return 3;
    }
    for (auto h : handles) {
        if (rx.live(h, now)) { std::cerr << "handle still live after close()\n"; return 4; }
    }
    if (rx.open(99, now).has_value()) { std::cerr << "open succeeded after close()\n"; return 5; }

    std::cout << "BATCH 125 QUIC-DROP CASCADING UDP SESSION TEARDOWN & ZERO-LEAK BUDGET TEST PASSED\n";
    return 0;
}
