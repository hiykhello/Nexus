export module tcp.receive;
import std;

export namespace tcp {
    enum class ReceiveError { invalid_capacity };
    enum class FinResult { accepted, duplicate, outside, conflict };
    struct ReceiveResult { std::size_t accepted = 0, duplicate = 0, outside = 0; };
    struct SackBlock { std::uint32_t left = 0, right = 0; };
    // Single owner. Flat byte ring + 16-entry sorted SACK interval table (no per-byte bitmap).
    class ReceiveBuffer {
        std::vector<std::uint8_t> data_;
        std::array<SackBlock, 16> ooo_{};
        std::size_t ooo_len_ = 0;
        std::uint32_t base_ = 0;
        std::size_t head_ = 0, ready_ = 0;
        std::optional<std::uint32_t> fin_;
        ReceiveBuffer(std::uint32_t initial, std::size_t capacity);
        auto write_ring(std::size_t offset, std::span<std::uint8_t const> bytes) noexcept -> void;
    public:
        [[nodiscard]] static auto create(std::uint32_t initial, std::size_t capacity)
            -> std::expected<ReceiveBuffer, ReceiveError>;
        [[nodiscard]] auto insert(std::uint32_t sequence, std::span<std::uint8_t const> data) -> ReceiveResult;
        [[nodiscard]] auto insert_fin(std::uint32_t sequence) noexcept -> FinResult;
        [[nodiscard]] auto read(std::span<std::uint8_t> output) noexcept -> std::size_t;
        auto release_storage() noexcept -> void { std::vector<std::uint8_t>{}.swap(data_); }
        [[nodiscard]] auto next() const noexcept -> std::uint32_t;
        [[nodiscard]] auto ready() const noexcept -> std::size_t { return ready_; }
        [[nodiscard]] auto finished() const noexcept -> bool;
        [[nodiscard]] auto window() const noexcept -> std::size_t { return finished() ? 0 : data_.size() - ready_; }
        // Returns up to 3 RFC 2018 SACK blocks when out-of-order bytes are buffered.
        [[nodiscard]] auto sack_blocks() const noexcept -> std::pair<std::array<SackBlock, 3>, std::size_t>;
    };
}
