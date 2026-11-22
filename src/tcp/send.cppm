export module tcp.send;
import std;

export namespace tcp {
    enum class SendError { invalid_capacity, capacity, invalid_count, invalid_ack, time_reversed, not_due };
    struct SendSlice { std::uint32_t sequence; std::vector<std::uint8_t> bytes; };
    // Single owner; flat circular byte ring replaces std::deque for zero per-byte pop_front overhead.
    class SendBuffer {
        std::vector<std::uint8_t> ring_;
        std::size_t capacity_ = 0, head_ = 0, count_ = 0, sent_ = 0;
        std::uint32_t una_ = 0;
        SendBuffer(std::uint32_t initial, std::size_t capacity)
            : ring_(capacity), capacity_(capacity), una_(initial) {}
        auto copy_range(std::size_t offset, std::size_t length) const -> std::vector<std::uint8_t>;
    public:
        [[nodiscard]] static auto create(std::uint32_t initial, std::size_t capacity)
            -> std::expected<SendBuffer, SendError>;
        [[nodiscard]] auto enqueue(std::span<std::uint8_t const> bytes) -> std::expected<void, SendError>;
        [[nodiscard]] auto unsent(std::size_t maximum) const -> SendSlice;
        [[nodiscard]] auto retransmit(std::size_t maximum) const -> SendSlice;
        [[nodiscard]] auto mark_sent(std::size_t count) noexcept -> std::expected<void, SendError>;
        [[nodiscard]] auto acknowledge(std::uint32_t acknowledgement) noexcept -> std::expected<std::size_t, SendError>;
        [[nodiscard]] auto una() const noexcept -> std::uint32_t { return una_; }
        [[nodiscard]] auto next() const noexcept -> std::uint32_t { return una_ + static_cast<std::uint32_t>(sent_); }
        [[nodiscard]] auto queued() const noexcept -> std::size_t { return count_; }
        [[nodiscard]] auto available() const noexcept -> std::size_t { return capacity_ - count_; }
        [[nodiscard]] auto in_flight() const noexcept -> std::size_t { return sent_; }
    };
    // RFC 6298 dynamic SRTT/RTTVAR RTO with Karn's algorithm + 3-DupACK fast retransmit.
    class TimedSend {
        SendBuffer buffer_;
        std::uint64_t now_ = 0, rto_ = 1000, base_rto_ = 1000;
        std::uint64_t srtt_ms_ = 0, rttvar_ms_ = 0;
        std::uint32_t rtt_seq_ = 0;
        std::uint64_t rtt_sent_at_ = 0;
        unsigned dup_acks_ = 0;
        bool initialized_ = false, rtt_valid_ = false, rtt_tracking_ = false, fast_retransmit_ = false;
        std::optional<std::uint64_t> deadline_;
        explicit TimedSend(SendBuffer buffer) : buffer_(std::move(buffer)) {}
        auto advance(std::uint64_t now) noexcept -> std::expected<void, SendError>;
        auto arm(std::uint64_t now) noexcept -> void;
        auto observe_rtt(std::uint64_t sample_ms) noexcept -> void;
    public:
        [[nodiscard]] static auto create(std::uint32_t initial, std::size_t capacity) -> std::expected<TimedSend, SendError>;
        [[nodiscard]] auto enqueue(std::span<std::uint8_t const> bytes) -> std::expected<void, SendError> { return buffer_.enqueue(bytes); }
        [[nodiscard]] auto unsent(std::size_t maximum) const -> SendSlice { return buffer_.unsent(maximum); }
        [[nodiscard]] auto retransmit(std::size_t maximum) const -> SendSlice { return buffer_.retransmit(maximum); }
        [[nodiscard]] auto sent(std::size_t count, std::uint64_t now) noexcept -> std::expected<void, SendError>;
        [[nodiscard]] auto acknowledge(std::uint32_t ack, std::uint64_t now) noexcept -> std::expected<std::size_t, SendError>;
        [[nodiscard]] auto due(std::uint64_t now, std::size_t maximum) -> std::expected<std::optional<SendSlice>, SendError>;
        [[nodiscard]] auto retransmitted(std::uint64_t now) noexcept -> std::expected<void, SendError>;
        [[nodiscard]] auto deadline() const noexcept -> std::optional<std::uint64_t> { return deadline_; }
        [[nodiscard]] auto rto() const noexcept -> std::uint64_t { return rto_; }
        [[nodiscard]] auto srtt_ms() const noexcept -> std::optional<std::uint64_t> { return rtt_valid_ ? std::optional{srtt_ms_} : std::nullopt; }
        [[nodiscard]] auto fast_retransmit_pending() const noexcept -> bool { return fast_retransmit_; }
        [[nodiscard]] auto next() const noexcept -> std::uint32_t { return buffer_.next(); }
        [[nodiscard]] auto una() const noexcept -> std::uint32_t { return buffer_.una(); }
        [[nodiscard]] auto in_flight() const noexcept -> std::size_t { return buffer_.in_flight(); }
        [[nodiscard]] auto queued() const noexcept -> std::size_t { return buffer_.queued(); }
        [[nodiscard]] auto available() const noexcept -> std::size_t { return buffer_.available(); }
    };
}
