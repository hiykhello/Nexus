export module nexus.tls.record_stream;
import std;

export namespace nexus::tls {
    enum class RecordStreamError { invalid_header, record_too_large, truncated, invalid_state };
    enum class RecordFraming { plaintext, ciphertext, handshake_ciphertext };
    struct FramedRecord {
        std::vector<std::uint8_t> bytes;
    };
    struct RecordFeed {
        std::size_t consumed = 0;
        std::optional<FramedRecord> record;
    };
    // A single-owner stream decoder; one record is returned per feed, including its header.
    // Feed the unconsumed suffix again, possibly after changing the protection epoch.
    class RecordStream {
        std::vector<std::uint8_t> pending_;
        std::size_t target_ = 5;
        bool failed_ = false;
        bool finished_ = false;
    public:
        RecordStream() = default;
        RecordStream(RecordStream const&) = delete;
        auto operator=(RecordStream const&) -> RecordStream& = delete;
        RecordStream(RecordStream&& other) noexcept;
        auto operator=(RecordStream&& other) noexcept -> RecordStream&;
        // mode must remain unchanged until the current record is complete.
        // Failure releases partial input. On exception consumption is unknown.
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input, RecordFraming mode) -> std::expected<RecordFeed,RecordStreamError>;
        [[nodiscard]] auto finish() -> std::expected<void,RecordStreamError>;
        [[nodiscard]] auto pending_bytes() const noexcept -> std::size_t { return pending_.size(); }
    private:
        std::optional<RecordFraming> mode_;
    };
}
