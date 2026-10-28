module nexus.tls.application_io;
import std;
namespace nexus::tls {
    ApplicationIo::ApplicationIo(ApplicationRecords&& records) noexcept : records_(std::move(records)) {}
    ApplicationIo::ApplicationIo(ApplicationIo&& o) noexcept : records_(std::move(o.records_)), input_(std::move(o.input_)), output_(std::move(o.output_)), offset_(o.offset_), failed_(o.failed_), peer_closed_(o.peer_closed_), input_finished_(o.input_finished_), response_pending_(o.response_pending_) { o.cancel(); }
    auto ApplicationIo::operator=(ApplicationIo&& o) noexcept -> ApplicationIo& {
        if (this!=&o) { records_=std::move(o.records_); input_=std::move(o.input_); output_=std::move(o.output_); offset_=o.offset_; failed_=o.failed_; peer_closed_=o.peer_closed_; input_finished_=o.input_finished_; response_pending_=o.response_pending_; o.cancel(); } return *this;
    }
    auto ApplicationIo::cancel() noexcept -> void {
        failed_=true; records_.reset(); input_=RecordStream{}; crypto::Bytes{}.swap(output_); offset_=0;
    }
    auto ApplicationIo::fail(ApplicationIoError error) -> std::unexpected<ApplicationIoError> { cancel(); return std::unexpected(error); }
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
        offset_+=count;
        if (offset_==output_.size()) {
            output_.clear(); offset_=0;
            if (response_pending_) {
                response_pending_=false; auto response=records_->key_update(false);
                if (!response) return fail(ApplicationIoError::record_error);
                output_=std::move(*response);
            }
        }
        return {};
    }
    auto ApplicationIo::send(std::span<std::uint8_t const> data) -> std::expected<void,ApplicationIoError> {
        if (failed_ || !output_.empty()) return std::unexpected(ApplicationIoError::invalid_state); return enqueue(records_->seal(data));
    }
    auto ApplicationIo::request_key_update(bool request) -> std::expected<void,ApplicationIoError> {
        if (failed_ || !output_.empty()) return std::unexpected(ApplicationIoError::invalid_state); return enqueue(records_->key_update(request));
    }
    auto ApplicationIo::close_notify() -> std::expected<void,ApplicationIoError> {
        if (failed_ || !output_.empty()) return std::unexpected(ApplicationIoError::invalid_state); return enqueue(records_->close_notify());
    }
    auto ApplicationIo::feed(std::span<std::uint8_t const> bytes) -> std::expected<ApplicationIoFeed,ApplicationIoError> {
        if (failed_ || peer_closed_ || input_finished_) return std::unexpected(ApplicationIoError::invalid_state);
        if (response_pending_) return ApplicationIoFeed{};
        auto framed=input_.feed(bytes,RecordFraming::ciphertext); if (!framed) return fail(ApplicationIoError::record_error);
        ApplicationIoFeed out{framed->consumed,{}}; if (!framed->record) return out;
        auto event=records_->open_event(framed->record->bytes); if (!event) return fail(ApplicationIoError::record_error);
        if (event->kind==ApplicationEventKind::key_update_requested) {
            if (!output_.empty()) response_pending_=true;
            else { auto response=records_->key_update(false); if (!response) return fail(ApplicationIoError::record_error); output_=std::move(*response); offset_=0; }
        }
        if (event->kind==ApplicationEventKind::close_notify) peer_closed_=true;
        if (event->kind==ApplicationEventKind::fatal_alert) cancel();
        out.event=std::move(*event); return out;
    }
    auto ApplicationIo::finish_input() -> std::expected<void,ApplicationIoError> {
        if (failed_ || input_finished_) return std::unexpected(ApplicationIoError::invalid_state);
        if (!input_.finish() || !peer_closed_ || !records_->finish_input()) return fail(ApplicationIoError::truncated);
        input_finished_=true; return {};
    }
}
