#include <arpa/inet.h>
#include <cerrno>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

import std;
import platform.socket_options;
import platform.udp_batch;

namespace {
    auto fail(std::string_view msg) -> int {
        std::cerr << "FAIL: " << msg << "\n";
        return 1;
    }

    auto make_loopback_udp(std::uint16_t& port_out) -> int {
        int fd = ::socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) return -1;
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(fd, reinterpret_cast<sockaddr const*>(&addr), sizeof(addr)) != 0) {
            ::close(fd);
            return -1;
        }
        socklen_t len = sizeof(addr);
        if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
            ::close(fd);
            return -1;
        }
        port_out = ntohs(addr.sin_port);
        return fd;
    }
}

int main() {
    // 1. Verify tune_tcp_low_latency sets TCP_NODELAY=1 and TCP_USER_TIMEOUT=20000 on real socket.
    int tcp_fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (tcp_fd < 0) return fail("create tcp socket");
    platform::tune_tcp_low_latency(tcp_fd, 20000);
    int nodelay = 0;
    socklen_t len = sizeof(nodelay);
    if (::getsockopt(tcp_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, &len) != 0 || nodelay != 1) {
        ::close(tcp_fd);
        return fail("TCP_NODELAY was not enabled");
    }
    unsigned int user_to = 0;
    len = sizeof(user_to);
    if (::getsockopt(tcp_fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_to, &len) != 0 || user_to != 20000u) {
        ::close(tcp_fd);
        return fail("TCP_USER_TIMEOUT was not set to 20000ms");
    }
    ::close(tcp_fd);

    // 2. Verify send_udp_batch (sendmmsg) + recv_udp_batch (recvmmsg) 24-packet burst + empty non-blocking poll.
    std::uint16_t rx_port = 0, tx_port = 0;
    int rx_fd = make_loopback_udp(rx_port);
    int tx_fd = make_loopback_udp(tx_port);
    if (rx_fd < 0 || tx_fd < 0) return fail("create loopback udp sockets");

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dst.sin_port = htons(rx_port);

    constexpr std::size_t kBurst = 24;
    std::array<std::array<std::uint8_t, 64>, kBurst> tx_bufs{};
    std::array<platform::UdpSendSlot, kBurst> send_slots{};
    for (std::size_t i = 0; i < kBurst; ++i) {
        tx_bufs[i].fill(static_cast<std::uint8_t>(i + 1));
        send_slots[i] = {reinterpret_cast<sockaddr const*>(&dst), sizeof(dst), tx_bufs[i].data(), 48};
    }
    auto sent = platform::send_udp_batch(tx_fd, send_slots);
    if (!sent || *sent != kBurst) return fail("send_udp_batch did not send full 24-packet burst");

    std::array<std::array<std::uint8_t, 128>, kBurst> rx_bufs{};
    std::array<platform::UdpRecvSlot, kBurst> recv_slots{};
    for (std::size_t i = 0; i < kBurst; ++i) {
        recv_slots[i].data = rx_bufs[i].data();
        recv_slots[i].capacity = rx_bufs[i].size();
    }
    auto got = platform::recv_udp_batch(rx_fd, recv_slots);
    if (!got || *got != kBurst) return fail("recv_udp_batch did not receive all 24 packets");
    for (std::size_t i = 0; i < kBurst; ++i) {
        if (recv_slots[i].received != 48 || recv_slots[i].truncated || rx_bufs[i][0] != static_cast<std::uint8_t>(i + 1)) {
            return fail("batch packet payload mismatch");
        }
    }
    // Ready-only contract: polling empty socket returns 0 immediately (never blocks).
    auto empty = platform::recv_udp_batch(rx_fd, recv_slots);
    if (!empty || *empty != 0) return fail("empty recv_udp_batch should return 0");

    // 3. Verify UdpGsoSender live burst + deterministic EIO fallback with zero packet loss.
    std::vector<std::uint8_t> burst_payload(1200 * 5 + 333);
    for (std::size_t i = 0; i < burst_payload.size(); ++i) {
        burst_payload[i] = static_cast<std::uint8_t>((i * 31u + 7u) & 0xffu);
    }
    platform::UdpGsoSender gso(true);
    auto gso_res = gso.send_segments(tx_fd, reinterpret_cast<sockaddr const*>(&dst), sizeof(dst),
        burst_payload, 1200);
    if (!gso_res || *gso_res != burst_payload.size()) return fail("UdpGsoSender live burst failed");

    std::vector<std::uint8_t> reassembled;
    for (int attempt = 0; attempt < 10 && reassembled.size() < burst_payload.size(); ++attempt) {
        std::array<std::array<std::uint8_t, 2048>, 8> seg_bufs{};
        std::array<platform::UdpRecvSlot, 8> seg_slots{};
        for (std::size_t i = 0; i < 8; ++i) { seg_slots[i].data = seg_bufs[i].data(); seg_slots[i].capacity = 2048; }
        auto r = platform::recv_udp_batch(rx_fd, seg_slots);
        if (!r) return fail("recv after GSO burst failed");
        for (std::size_t i = 0; i < *r; ++i) {
            reassembled.insert(reassembled.end(), seg_bufs[i].begin(), seg_bufs[i].begin() + seg_slots[i].received);
        }
    }
    if (reassembled != burst_payload) return fail("reassembled GSO burst payload mismatch");

    // Simulated EIO fallback test: must latch gso_enabled() == false and deliver all segments via sendmmsg.
    platform::UdpGsoSender gso_fb(true);
    auto always_eio = [](int, sockaddr const*, socklen_t, std::span<std::uint8_t const>, std::uint16_t) noexcept -> int {
        return EIO;
    };
    auto fb_res = gso_fb.send_segments(tx_fd, reinterpret_cast<sockaddr const*>(&dst), sizeof(dst),
        burst_payload, 1200, always_eio);
    if (!fb_res || *fb_res != burst_payload.size() || gso_fb.gso_enabled() || gso_fb.fallback_bursts() != 1) {
        return fail("UdpGsoSender EIO fallback did not disable GSO or lost bytes");
    }
    reassembled.clear();
    for (int attempt = 0; attempt < 10 && reassembled.size() < burst_payload.size(); ++attempt) {
        std::array<std::array<std::uint8_t, 2048>, 8> seg_bufs{};
        std::array<platform::UdpRecvSlot, 8> seg_slots{};
        for (std::size_t i = 0; i < 8; ++i) { seg_slots[i].data = seg_bufs[i].data(); seg_slots[i].capacity = 2048; }
        auto r = platform::recv_udp_batch(rx_fd, seg_slots);
        if (!r) return fail("recv after GSO fallback failed");
        for (std::size_t i = 0; i < *r; ++i) {
            reassembled.insert(reassembled.end(), seg_bufs[i].begin(), seg_bufs[i].begin() + seg_slots[i].received);
        }
    }
    if (reassembled != burst_payload) return fail("reassembled GSO fallback payload mismatch");

    ::close(rx_fd);
    ::close(tx_fd);
    std::cout << "BATCH 123 TCP_NODELAY/TCP_USER_TIMEOUT + RECVMMSG/SENDMMSG + UDP GSO FALLBACK UNIT TESTS PASSED\n";
    return 0;
}
