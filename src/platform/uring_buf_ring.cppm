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

    // Single-executor io_uring Provided Buffer Ring + Multishot Recv engine.
    // Owns a bounded power-of-2 kernel buffer ring and contiguous backing slab.
    class UringMultishotLoop {
        struct Impl;
        struct ImplDeleter {
            auto operator()(Impl* ptr) const noexcept -> void;
        };
        std::unique_ptr<Impl, ImplDeleter> impl_;

        explicit UringMultishotLoop(std::unique_ptr<Impl, ImplDeleter> impl) noexcept;

    public:
        static constexpr std::size_t kMaxMemoryBudget = 16u * 1024u * 1024u;

        UringMultishotLoop() noexcept = default;
        UringMultishotLoop(UringMultishotLoop&&) noexcept = default;
        auto operator=(UringMultishotLoop&&) noexcept -> UringMultishotLoop& = default;
        UringMultishotLoop(UringMultishotLoop const&) = delete;
        auto operator=(UringMultishotLoop const&) -> UringMultishotLoop& = delete;
        ~UringMultishotLoop() = default;

        [[nodiscard]] static auto create(UringBufRingConfig cfg = {})
            -> std::expected<UringMultishotLoop, int>;

        [[nodiscard]] auto arm_recv_multishot(int fd, std::uint64_t tag) noexcept
            -> std::expected<void, int>;
        [[nodiscard]] auto cancel_fd(int fd) noexcept -> std::expected<void, int>;

        // Submits pending SQEs and harvests up to out.size() CQEs without heap allocation.
        [[nodiscard]] auto poll_events(std::span<MultishotEvent> out,
                                       std::uint32_t wait_nr,
                                       std::uint32_t timeout_ms) noexcept
            -> std::expected<std::size_t, int>;

        // Returns a read-only view of a currently leased buffer slot.
        [[nodiscard]] auto buffer_view(std::uint16_t bid, std::size_t len) const noexcept
            -> std::span<std::uint8_t const>;

        // Returns a leased buffer back to the kernel buffer ring immediately.
        [[nodiscard]] auto recycle(std::uint16_t bid) noexcept -> bool;

        [[nodiscard]] auto ring_entries() const noexcept -> std::uint32_t;
        [[nodiscard]] auto buffer_size() const noexcept -> std::uint32_t;
        [[nodiscard]] auto leased_count() const noexcept -> std::uint32_t;
        [[nodiscard]] auto stats() const noexcept -> UringMultishotStats;
    };
}
