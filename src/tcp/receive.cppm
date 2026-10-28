export module nexus.tcp.receive;
import std;

export namespace nexus::tcp {
    enum class ReceiveError { invalid_capacity };
    enum class FinResult { accepted, duplicate, outside, conflict };
    struct ReceiveResult { std::size_t accepted = 0, duplicate = 0, outside = 0; };
    // Single owner. The fixed window includes unread contiguous data and buffered gaps.
    class ReceiveBuffer {
        std::vector<std::optional<std::uint8_t>> slots_;
        std::uint32_t base_;
        std::size_t head_ = 0, ready_ = 0;
        std::optional<std::uint32_t> fin_;
        ReceiveBuffer(std::uint32_t initial, std::size_t capacity);
    public:
        [[nodiscard]] static auto create(std::uint32_t initial, std::size_t capacity)
            -> std::expected<ReceiveBuffer, ReceiveError>;
        [[nodiscard]] auto insert(std::uint32_t sequence, std::span<std::uint8_t const> data) -> ReceiveResult;
        [[nodiscard]] auto insert_fin(std::uint32_t sequence) noexcept -> FinResult;
        [[nodiscard]] auto read(std::span<std::uint8_t> output) noexcept -> std::size_t;
        [[nodiscard]] auto next() const noexcept -> std::uint32_t;
        [[nodiscard]] auto ready() const noexcept -> std::size_t { return ready_; }
        [[nodiscard]] auto finished() const noexcept -> bool;
        [[nodiscard]] auto window() const noexcept -> std::size_t { return finished() ? 0 : slots_.size() - ready_; }
    };
}
