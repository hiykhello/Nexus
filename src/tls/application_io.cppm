export module nexus.tls.application_io;
export import nexus.tls.client_flight;
import nexus.tls.record_stream;
import std;
export namespace nexus::tls {
    enum class ApplicationIoError { invalid_state, invalid_input, record_error, truncated, key_update_required };
    struct ApplicationIoFeed { std::size_t consumed=0; std::optional<ApplicationEvent> event; };
    // Single-owner bounded record adapter. One outbound record may be pending at a time.
    class ApplicationIo {
        std::optional<ApplicationRecords> records_;
        RecordStream input_;
        crypto::Bytes output_;
        std::size_t offset_=0;
        bool failed_=false, peer_closed_=false, input_finished_=false, response_pending_=false;
        auto fail(ApplicationIoError error) -> std::unexpected<ApplicationIoError>;
        auto enqueue(std::expected<crypto::Bytes,RecordError>&& result) -> std::expected<void,ApplicationIoError>;
    public:
        explicit ApplicationIo(ApplicationRecords&& records) noexcept;
        ApplicationIo(ApplicationIo const&)=delete;
        auto operator=(ApplicationIo const&) -> ApplicationIo& = delete;
        ApplicationIo(ApplicationIo&&) noexcept;
        auto operator=(ApplicationIo&&) noexcept -> ApplicationIo&;
        // Borrowed until the next non-const operation; asynchronous writes must own their buffer.
        [[nodiscard]] auto pending_output() const noexcept -> std::span<std::uint8_t const>;
        [[nodiscard]] auto input_blocked() const noexcept -> bool { return response_pending_; }
        [[nodiscard]] auto max_write_size() const noexcept -> std::size_t { return records_ ? records_->max_write_size() : 0; }
        [[nodiscard]] auto written(std::size_t count) -> std::expected<void,ApplicationIoError>;
        // Data must fit the negotiated limit; a rejected size does not consume a nonce.
        // key_update_required preserves one record for KeyUpdate or close_notify.
        [[nodiscard]] auto send(std::span<std::uint8_t const> data) -> std::expected<void,ApplicationIoError>;
        [[nodiscard]] auto request_key_update(bool request_peer_update) -> std::expected<void,ApplicationIoError>;
        [[nodiscard]] auto close_notify() -> std::expected<void,ApplicationIoError>;
        // Stops at one record boundary. A deferred KeyUpdate response applies input backpressure
        // until prior output is fully written; the response precedes subsequent application writes.
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input) -> std::expected<ApplicationIoFeed,ApplicationIoError>;
        [[nodiscard]] auto finish_input() -> std::expected<void,ApplicationIoError>;
        auto cancel() noexcept -> void;
    };
}
