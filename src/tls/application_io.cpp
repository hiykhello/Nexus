module tls.application_io;
import std;
namespace tls {
    ApplicationIo::ApplicationIo(ApplicationRecords&& records) noexcept : records_(std::move(records)) {}
    ApplicationIo::ApplicationIo(ApplicationIo&& o) noexcept : records_(std::move(o.records_)), input_(std::move(o.input_)), output_(std::move(o.output_)), offset_(o.offset_), failed_(o.failed_), peer_closed_(o.peer_closed_), input_finished_(o.input_finished_), response_pending_(o.response_pending_), input_detached_(o.input_detached_), output_detached_(o.output_detached_), overflow_(o.overflow_), overflow_alert_queued_(o.overflow_alert_queued_), overflow_alert_written_(o.overflow_alert_written_) { o.cancel(); }
    auto ApplicationIo::operator=(ApplicationIo&& o) noexcept -> ApplicationIo& {
        if (this!=&o) { records_=std::move(o.records_); input_=std::move(o.input_); output_=std::move(o.output_); offset_=o.offset_; failed_=o.failed_; peer_closed_=o.peer_closed_; input_finished_=o.input_finished_; response_pending_=o.response_pending_; input_detached_=o.input_detached_; output_detached_=o.output_detached_; overflow_=o.overflow_; overflow_alert_queued_=o.overflow_alert_queued_; overflow_alert_written_=o.overflow_alert_written_; o.cancel(); } return *this;
    }
    auto ApplicationIo::cancel() noexcept -> void {
        failed_=true; records_.reset(); input_=RecordStream{}; crypto::Bytes{}.swap(output_); offset_=0;
    }
    auto ApplicationIo::fail(ApplicationIoError error) -> std::unexpected<ApplicationIoError> { cancel(); return std::unexpected(error); }
    auto ApplicationIo::overflow_failure() -> std::unexpected<ApplicationIoError> {
        overflow_=true;response_pending_=false;
        if (output_.empty()) {
            auto alert=records_->take_overflow_alert();
            if (!alert) return fail(ApplicationIoError::record_error);
            output_=std::move(*alert);offset_=0;overflow_alert_queued_=true;
        }
        return std::unexpected(ApplicationIoError::record_overflow);
    }
    auto ApplicationIo::enqueue(std::expected<crypto::Bytes,RecordError>&& result) -> std::expected<void,ApplicationIoError> {
        if (!result) {
            if (result.error()==RecordError::key_usage_limit) return std::unexpected(ApplicationIoError::key_update_required);
            if (result.error()==RecordError::invalid_input) return std::unexpected(ApplicationIoError::invalid_input);
            if (result.error()==RecordError::invalid_state) return std::unexpected(ApplicationIoError::invalid_state);
            return fail(ApplicationIoError::record_error);
        }
        output_=std::move(*result); offset_=0; return {};
    }
    auto ApplicationIo::pending_output() const noexcept -> std::span<std::uint8_t const> { return std::span{output_}.subspan(offset_); }
    auto ApplicationIo::written(std::size_t count) -> std::expected<void,ApplicationIoError> {
        if (failed_ || output_.empty()) return std::unexpected(ApplicationIoError::invalid_state);
        if (count>output_.size()-offset_) return std::unexpected(ApplicationIoError::invalid_input);
        try {
        offset_+=count;
        if (offset_==output_.size()) {
            crypto::Bytes{}.swap(output_); offset_=0;
            if (overflow_) {
                if (overflow_alert_queued_) overflow_alert_written_=true;
                else {
                    auto alert=records_->take_overflow_alert();
                    if (!alert) return fail(ApplicationIoError::record_error);
                    output_=std::move(*alert);overflow_alert_queued_=true;
                }
            } else if (response_pending_) {
                response_pending_=false; auto response=records_->key_update(false);
                if (!response) return fail(ApplicationIoError::record_error);
                output_=std::move(*response);
            }
        }
        return {};
        } catch (...) { cancel(); throw; }
    }
    auto ApplicationIo::send(std::span<std::uint8_t const> data) -> std::expected<void,ApplicationIoError> {
        if (failed_ || overflow_ || output_detached_ || !output_.empty()) return std::unexpected(ApplicationIoError::invalid_state);
        try { return enqueue(records_->seal(data)); } catch (...) { cancel(); throw; }
    }
    auto ApplicationIo::request_key_update(bool request) -> std::expected<void,ApplicationIoError> {
        if (failed_ || overflow_ || output_detached_ || !output_.empty()) return std::unexpected(ApplicationIoError::invalid_state);
        try { return enqueue(records_->key_update(request)); } catch (...) { cancel(); throw; }
    }
    auto ApplicationIo::close_notify() -> std::expected<void,ApplicationIoError> {
        if (failed_ || overflow_ || output_detached_ || !output_.empty()) return std::unexpected(ApplicationIoError::invalid_state);
        try { return enqueue(records_->close_notify()); } catch (...) { cancel(); throw; }
    }
    auto ApplicationIo::feed(std::span<std::uint8_t const> bytes) -> std::expected<ApplicationIoFeed,ApplicationIoError> {
        if (failed_ || overflow_ || peer_closed_ || input_finished_ || input_detached_) return std::unexpected(ApplicationIoError::invalid_state);
        if (response_pending_) return ApplicationIoFeed{};
        try {
        auto framed=input_.feed(bytes,records_->tls12() ? RecordFraming::tls12_gcm : RecordFraming::ciphertext);
        if (!framed) {
            if (framed.error()==RecordStreamError::record_too_large && records_->signal_overflow()) return overflow_failure();
            return fail(ApplicationIoError::record_error);
        }
        ApplicationIoFeed out{framed->consumed,{}}; if (!framed->record) return out;
        auto event=records_->open_event(framed->record->bytes);
        if (!event && event.error()==RecordError::record_overflow) return overflow_failure();
        if (!event) return fail(ApplicationIoError::record_error);
        if (event->kind==ApplicationEventKind::key_update_requested) {
            if (output_detached_) return fail(ApplicationIoError::invalid_state);
            if (!output_.empty()) response_pending_=true;
            else { auto response=records_->key_update(false); if (!response) return fail(ApplicationIoError::record_error); output_=std::move(*response); offset_=0; }
        }
        if (event->kind==ApplicationEventKind::close_notify) peer_closed_=true;
        if (event->kind==ApplicationEventKind::fatal_alert) cancel();
        out.event=std::move(*event); return out;
        } catch (...) { cancel(); throw; }
    }
    auto ApplicationIo::detach_input() noexcept -> bool {
        if (failed_ || overflow_ || peer_closed_ || input_finished_ || input_detached_ || response_pending_ || input_.pending_bytes()) return false;
        input_detached_=true; return true;
    }
    auto ApplicationIo::detach_output() noexcept -> bool {
        if (failed_ || overflow_ || output_detached_ || response_pending_ || !output_.empty()) return false;
        output_detached_=true; return true;
    }
    auto ApplicationIo::can_handoff_ktls_tx() const noexcept -> bool {
        return !failed_ && !overflow_ && !output_detached_ && !response_pending_ &&
            output_.empty() && records_ && records_->can_handoff_tx();
    }
    auto ApplicationIo::can_handoff_ktls_rx() const noexcept -> bool {
        return !failed_ && !overflow_ && !peer_closed_ && !input_finished_ && !input_detached_ &&
            !response_pending_ && !input_.pending_bytes() && records_ && records_->can_handoff_rx();
    }
    auto ApplicationIo::take_ktls_tx() -> std::optional<ApplicationRecords::KtlsDirectionHandoff> {
        if (!can_handoff_ktls_tx()) return {};
        auto out = records_->take_ktls_tx();
        if (!out) return {};
        output_detached_ = true;
        return out;
    }
    auto ApplicationIo::take_ktls_rx() -> std::optional<ApplicationRecords::KtlsDirectionHandoff> {
        if (!can_handoff_ktls_rx()) return {};
        auto out = records_->take_ktls_rx();
        if (!out) return {};
        input_detached_ = true;
        return out;
    }
    auto ApplicationIo::finish_input() -> std::expected<void,ApplicationIoError> {
        if (failed_ || input_finished_ || input_detached_) return std::unexpected(ApplicationIoError::invalid_state);
        if (!input_.finish() || !peer_closed_ || !records_->finish_input()) return fail(ApplicationIoError::truncated);
        input_finished_=true; return {};
    }
}
