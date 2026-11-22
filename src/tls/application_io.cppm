export module tls.application_io;
export import tls.client_flight;
import tls.record_stream;
import std;
export namespace tls {
    enum class ApplicationIoError { invalid_state, invalid_input, record_error, truncated, key_update_required, record_overflow };
    struct ApplicationIoFeed { std::size_t consumed=0; std::optional<ApplicationEvent> event; };
    // Single-owner bounded record adapter. One outbound record may be pending at a time.
    class ApplicationIo {
        std::optional<ApplicationRecords> records_;
        RecordStream input_;
        crypto::Bytes output_;
        std::size_t offset_=0;
        bool failed_=false, peer_closed_=false, input_finished_=false, response_pending_=false, input_detached_=false, output_detached_=false;
        bool overflow_=false, overflow_alert_queued_=false, overflow_alert_written_=false;
        auto fail(ApplicationIoError error) -> std::unexpected<ApplicationIoError>;
        auto overflow_failure() -> std::unexpected<ApplicationIoError>;
        auto enqueue(std::expected<crypto::Bytes,RecordError>&& result) -> std::expected<void,ApplicationIoError>;
    public:
        explicit ApplicationIo(ApplicationRecords&& records) noexcept;
        ApplicationIo(ApplicationIo const&)=delete;
        auto operator=(ApplicationIo const&) -> ApplicationIo& = delete;
        ApplicationIo(ApplicationIo&&) noexcept;
        auto operator=(ApplicationIo&&) noexcept -> ApplicationIo&;
        // Borrowed until the next non-const operation; asynchronous writes must own their buffer.
        [[nodiscard]] auto overflow() const noexcept -> bool { return overflow_; }
        [[nodiscard]] auto overflow_alert_written() const noexcept -> bool { return overflow_alert_written_; }
        [[nodiscard]] auto pending_output() const noexcept -> std::span<std::uint8_t const>;
        [[nodiscard]] auto input_blocked() const noexcept -> bool { return response_pending_ || overflow_; }
        [[nodiscard]] auto output_detached() const noexcept -> bool { return output_detached_; }
        [[nodiscard]] auto max_write_size() const noexcept -> std::size_t { return records_ && !overflow_ ? records_->max_write_size() : 0; }
        [[nodiscard]] auto written(std::size_t count) -> std::expected<void,ApplicationIoError>;
        // Data must fit the negotiated limit; a rejected size does not consume a nonce.
        // key_update_required preserves one record for KeyUpdate or close_notify.
        [[nodiscard]] auto send(std::span<std::uint8_t const> data) -> std::expected<void,ApplicationIoError>;
        [[nodiscard]] auto request_key_update(bool request_peer_update) -> std::expected<void,ApplicationIoError>;
        [[nodiscard]] auto close_notify() -> std::expected<void,ApplicationIoError>;
        // Stops at one record boundary. A deferred KeyUpdate response applies input backpressure
        // until prior output is fully written; the response precedes subsequent application writes.
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input) -> std::expected<ApplicationIoFeed,ApplicationIoError>;
        // Detach only between authenticated records. Outbound TLS remains usable.
        [[nodiscard]] auto detach_input() noexcept -> bool;
        // No TLS output may remain queued, including a KeyUpdate response.
        [[nodiscard]] auto detach_output() noexcept -> bool;
        [[nodiscard]] auto can_handoff_ktls_tx() const noexcept -> bool;
        [[nodiscard]] auto can_handoff_ktls_rx() const noexcept -> bool;
        [[nodiscard]] auto ktls_algorithm() const noexcept -> std::optional<crypto::Aead> {
            return records_ ? records_->ktls_algorithm() : std::nullopt;
        }
        [[nodiscard]] auto take_ktls_tx() -> std::optional<ApplicationRecords::KtlsDirectionHandoff>;
        [[nodiscard]] auto take_ktls_rx() -> std::optional<ApplicationRecords::KtlsDirectionHandoff>;
        [[nodiscard]] auto finish_input() -> std::expected<void,ApplicationIoError>;
        auto cancel() noexcept -> void;
    };
}
