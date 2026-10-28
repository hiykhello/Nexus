export module nexus.tcp.send;
import std;

export namespace nexus::tcp {
    enum class SendError { invalid_capacity, capacity, invalid_count, invalid_ack, time_reversed, not_due };
    struct SendSlice { std::uint32_t sequence; std::vector<std::uint8_t> bytes; };
    // Single owner; queued bytes remain owned until cumulatively acknowledged.
    class SendBuffer {
        std::deque<std::uint8_t> bytes_;
        std::size_t capacity_, sent_ = 0;
        std::uint32_t una_;
        SendBuffer(std::uint32_t initial, std::size_t capacity) : capacity_(capacity), una_(initial) {}
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
        [[nodiscard]] auto queued() const noexcept -> std::size_t { return bytes_.size(); }
        [[nodiscard]] auto available() const noexcept -> std::size_t { return capacity_ - bytes_.size(); }
        [[nodiscard]] auto in_flight() const noexcept -> std::size_t { return sent_; }
    };
    // Fixed initial RTO with exponential backoff; caller commits actual transmissions.
    class TimedSend {
        SendBuffer buffer_;
        std::uint64_t now_ = 0, rto_ = 1000;
        bool initialized_ = false;
        std::optional<std::uint64_t> deadline_;
        explicit TimedSend(SendBuffer buffer) : buffer_(std::move(buffer)) {}
        auto advance(std::uint64_t now) noexcept -> std::expected<void, SendError>;
        auto arm(std::uint64_t now) noexcept -> void;
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
        [[nodiscard]] auto next() const noexcept -> std::uint32_t { return buffer_.next(); }
        [[nodiscard]] auto una() const noexcept -> std::uint32_t { return buffer_.una(); }
        [[nodiscard]] auto in_flight() const noexcept -> std::size_t { return buffer_.in_flight(); }
        [[nodiscard]] auto queued() const noexcept -> std::size_t { return buffer_.queued(); }
        [[nodiscard]] auto available() const noexcept -> std::size_t { return buffer_.available(); }
    };
}
