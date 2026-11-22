module;
#include <sys/socket.h>
export module platform.udp_batch;
import std;

export namespace platform {
    inline constexpr std::size_t kUdpBatchMax = 32;

    struct UdpRecvSlot {
        sockaddr_storage peer{};
        socklen_t peer_len = 0;
        std::uint8_t* data = nullptr;
        std::size_t capacity = 0;
        std::size_t received = 0;
        bool truncated = false;
    };

    struct UdpSendSlot {
        sockaddr const* peer = nullptr;
        socklen_t peer_len = 0;
        std::uint8_t const* data = nullptr;
        std::size_t size = 0;
    };

    // Ready-only batch receive (never waits for full batch): drains up to
    // min(slots.size(), kUdpBatchMax) already-queued datagrams in one syscall.
    [[nodiscard]] auto recv_udp_batch(int fd, std::span<UdpRecvSlot> slots) noexcept
        -> std::expected<std::size_t, std::error_code>;

    // Non-blocking batch send (up to kUdpBatchMax packets per syscall).
    [[nodiscard]] auto send_udp_batch(int fd, std::span<UdpSendSlot const> slots) noexcept
        -> std::expected<std::size_t, std::error_code>;

    // UDP GSO sender with automatic lossless fallback to send_udp_batch on
    // kernels/NICs that return EIO/EINVAL/EOPNOTSUPP/ENOPROTOOPT/EMSGSIZE.
    class UdpGsoSender {
        bool gso_enabled_ = true;
        std::uint64_t gso_bursts_ = 0;
        std::uint64_t fallback_bursts_ = 0;
    public:
        explicit UdpGsoSender(bool enable_gso = true) noexcept : gso_enabled_(enable_gso) {}

        [[nodiscard]] auto gso_enabled(this UdpGsoSender const& self) noexcept -> bool { return self.gso_enabled_; }
        [[nodiscard]] auto gso_bursts(this UdpGsoSender const& self) noexcept -> std::uint64_t { return self.gso_bursts_; }
        [[nodiscard]] auto fallback_bursts(this UdpGsoSender const& self) noexcept -> std::uint64_t {
            return self.fallback_bursts_;
        }

        using SendGsoFn = int (*)(int, sockaddr const*, socklen_t, std::span<std::uint8_t const>, std::uint16_t) noexcept;

        // Sends contiguous equal-peer segments of size `segment_size` (last segment may be smaller).
        // Returns total bytes handed to the kernel; never drops or duplicates segments on GSO fallback.
        [[nodiscard]] auto send_segments(this UdpGsoSender& self, int fd, sockaddr const* peer, socklen_t peer_len,
            std::span<std::uint8_t const> payload, std::uint16_t segment_size,
            SendGsoFn custom_gso = nullptr) noexcept -> std::expected<std::size_t, std::error_code>;
    };
}
