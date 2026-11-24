module;
#include <cerrno>
export module platform.uring_buf_ring;
import std;

export namespace platform {
    struct UringBufRingConfig {
        std::uint32_t ring_entries = 64;
        std::uint32_t buffer_size = 4096;
        std::uint16_t buffer_group_id = 1;
        std::uint32_t sq_entries = 128;
    };

    struct MultishotEvent {
        std::uint64_t tag = 0;
        std::int32_t result = 0;
        std::uint16_t buffer_id = 0;
        bool has_buffer = false;
        bool more_coming = false;
        bool needs_rearm = false;
    };

    struct UringMultishotStats {
        std::uint64_t cqes_total = 0;
        std::uint64_t multishot_hits = 0;
        std::uint64_t enobufs_count = 0;
        std::uint64_t rearms = 0;
        std::uint64_t bytes_received = 0;
        std::uint32_t buffers_leased = 0;
    };

    class UringMultishotLoop {
    public:
        static constexpr std::size_t kMaxMemoryBudget = 16u * 1024u * 1024u;
        [[nodiscard]] static auto create(UringBufRingConfig = {}) -> std::expected<UringMultishotLoop, int> {
            return std::unexpected(EOPNOTSUPP);
        }
        [[nodiscard]] auto arm_recv_multishot(int, std::uint64_t) noexcept -> std::expected<void, int> {
            return std::unexpected(EOPNOTSUPP);
        }
        [[nodiscard]] auto arm_read_multishot(int, std::uint64_t) noexcept -> std::expected<void, int> {
            return std::unexpected(EOPNOTSUPP);
        }
        [[nodiscard]] auto submit() noexcept -> std::expected<void, int> { return std::unexpected(EOPNOTSUPP); }
        [[nodiscard]] auto cancel_fd(int) noexcept -> std::expected<void, int> { return {}; }
        [[nodiscard]] auto poll_events(std::span<MultishotEvent>, std::uint32_t, std::uint32_t) noexcept
            -> std::expected<std::size_t, int> { return std::unexpected(EOPNOTSUPP); }
        [[nodiscard]] auto buffer_view(std::uint16_t, std::size_t) const noexcept -> std::span<std::uint8_t const> {
            return {};
        }
        [[nodiscard]] auto recycle(std::uint16_t) noexcept -> bool { return false; }
        [[nodiscard]] auto ring_fd() const noexcept -> int { return -1; }
        [[nodiscard]] auto ring_entries() const noexcept -> std::uint32_t { return 0; }
        [[nodiscard]] auto buffer_size() const noexcept -> std::uint32_t { return 0; }
        [[nodiscard]] auto leased_count() const noexcept -> std::uint32_t { return 0; }
        [[nodiscard]] auto stats() const noexcept -> UringMultishotStats { return {}; }
    };
}
