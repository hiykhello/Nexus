module tls.application_io;
import std;
namespace tls {
    ApplicationIo::ApplicationIo(ApplicationRecords&& records) noexcept : records_(std::move(records)) {}
    ApplicationIo::ApplicationIo(ApplicationIo&& o) noexcept : records_(std::move(o.records_)), input_(std::move(o.input_)), output_(std::move(o.output_)), offset_(o.offset_), failed_(o.failed_), peer_closed_(o.peer_closed_), input_finished_(o.input_finished_), response_pending_(o.response_pending_), input_detached_(o.input_detached_), output_detached_(o.output_detached_), overflow_(o.overflow_), overflow_alert_queued_(o.overflow_alert_queued_), overflow_alert_written_(o.overflow_alert_written_), external_output_busy_(o.external_output_busy_) { o.cancel(); }
    auto ApplicationIo::operator=(ApplicationIo&& o) noexcept -> ApplicationIo& {
        if (this!=&o) { records_=std::move(o.records_); input_=std::move(o.input_); output_=std::move(o.output_); offset_=o.offset_; failed_=o.failed_; peer_closed_=o.peer_closed_; input_finished_=o.input_finished_; response_pending_=o.response_pending_; input_detached_=o.input_detached_; output_detached_=o.output_detached_; overflow_=o.overflow_; overflow_alert_queued_=o.overflow_alert_queued_; overflow_alert_written_=o.overflow_alert_written_; external_output_busy_=o.external_output_busy_; o.cancel(); } return *this;
    }
    auto ApplicationIo::cancel() noexcept -> void {
        failed_=true; external_output_busy_=false; records_.reset(); input_=RecordStream{}; crypto::Bytes{}.swap(output_); offset_=0;
    }
    auto ApplicationIo::fail(ApplicationIoError error) -> std::unexpected<ApplicationIoError> { cancel(); return std::unexpected(error); }
    auto ApplicationIo::overflow_failure() -> std::unexpected<ApplicationIoError> {
        overflow_=true;response_pending_=false;
        if (!output_busy()) {
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
    auto ApplicationIo::handle_opened_event(ApplicationEvent const& event) -> std::expected<void,ApplicationIoError> {
        if (event.kind==ApplicationEventKind::key_update_requested) {
            if (output_detached_) return fail(ApplicationIoError::invalid_state);
            if (output_busy()) response_pending_=true;
            else { auto response=records_->key_update(false); if (!response) return fail(ApplicationIoError::record_error); output_=std::move(*response); offset_=0; }
        } else if (event.kind==ApplicationEventKind::close_notify) {
            peer_closed_=true;
        } else if (event.kind==ApplicationEventKind::fatal_alert) {
            cancel();
        }
        return {};
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
        if (failed_ || overflow_ || output_detached_ || output_busy()) return std::unexpected(ApplicationIoError::invalid_state);
        try { return enqueue(records_->seal(data)); } catch (...) { cancel(); throw; }
    }
    auto ApplicationIo::seal_batch_into(std::span<std::uint8_t const> data, std::span<std::uint8_t> dest)
        -> std::expected<SealBatchResult,ApplicationIoError> {
        if (failed_ || overflow_ || output_detached_ || output_busy() || !records_)
            return std::unexpected(ApplicationIoError::invalid_state);
        if (data.empty()) return std::unexpected(ApplicationIoError::invalid_input);
        auto const limit=max_write_size();
        if (!limit) return std::unexpected(ApplicationIoError::invalid_state);
        auto const overhead=records_->sealed_record_size(0);
        if (dest.size()<=overhead) return std::unexpected(ApplicationIoError::invalid_input);
        auto const batch_len=std::min(data.size(),std::size_t{65536});
        try {
            std::size_t consumed=0, wire_off=0;
            while (consumed<batch_len) {
                auto const avail=dest.size()-wire_off;
                if (avail<=overhead) break;
                auto const wanted=std::min(limit,batch_len-consumed);
                if (avail<wanted+overhead && consumed>0) break;
                auto const chunk=std::min(wanted,avail-overhead);
                auto sealed=records_->seal_into(data.subspan(consumed,chunk),dest.subspan(wire_off));
                if (!sealed) {
                    if (sealed.error()==RecordError::key_usage_limit) {
                        if (consumed>0) break;
                        return std::unexpected(ApplicationIoError::key_update_required);
                    }
                    return fail(sealed.error()==RecordError::invalid_input ? ApplicationIoError::invalid_input : ApplicationIoError::record_error);
                }
                consumed+=chunk;
                wire_off+=*sealed;
            }
            external_output_busy_=true;
            return SealBatchResult{consumed,wire_off};
        } catch (...) { cancel(); throw; }
    }
    auto ApplicationIo::seal_batch_into(std::span<std::uint8_t const> data, crypto::Bytes& dest)
        -> std::expected<std::size_t,ApplicationIoError> {
        if (failed_ || overflow_ || output_detached_ || output_busy() || !records_)
            return std::unexpected(ApplicationIoError::invalid_state);
        if (data.empty()) return std::unexpected(ApplicationIoError::invalid_input);
        auto const limit=max_write_size();
        if (!limit) return std::unexpected(ApplicationIoError::invalid_state);
        auto const batch_len=std::min(data.size(),std::size_t{65536});
        auto const overhead=records_->sealed_record_size(0);
        auto const max_records=(batch_len+limit-1)/limit;
        try {
            dest.resize(batch_len+max_records*overhead);
            auto res=seal_batch_into(data,std::span<std::uint8_t>{dest});
            if (!res) { dest.clear(); return std::unexpected(res.error()); }
            dest.resize(res->wire_size);
            return res->consumed;
        } catch (...) { dest.clear(); cancel(); throw; }
    }
    auto ApplicationIo::finish_external_output() -> std::expected<void,ApplicationIoError> {
        if (failed_ || !external_output_busy_) return std::unexpected(ApplicationIoError::invalid_state);
        external_output_busy_=false;
        try {
            if (overflow_) {
                if (!overflow_alert_queued_) {
                    auto alert=records_->take_overflow_alert();
                    if (!alert) return fail(ApplicationIoError::record_error);
                    output_=std::move(*alert); offset_=0; overflow_alert_queued_=true;
                }
            } else if (response_pending_) {
                response_pending_=false;
                auto response=records_->key_update(false);
                if (!response) return fail(ApplicationIoError::record_error);
                output_=std::move(*response); offset_=0;
            }
            return {};
        } catch (...) { cancel(); throw; }
    }
    auto ApplicationIo::request_key_update(bool request) -> std::expected<void,ApplicationIoError> {
        if (failed_ || overflow_ || output_detached_ || output_busy()) return std::unexpected(ApplicationIoError::invalid_state);
        try { return enqueue(records_->key_update(request)); } catch (...) { cancel(); throw; }
    }
    auto ApplicationIo::close_notify() -> std::expected<void,ApplicationIoError> {
        if (failed_ || overflow_ || output_detached_ || output_busy()) return std::unexpected(ApplicationIoError::invalid_state);
        try { return enqueue(records_->close_notify()); } catch (...) { cancel(); throw; }
    }
    auto ApplicationIo::has_complete_buffered_record(std::span<std::uint8_t const> bytes) const noexcept -> bool {
        if (input_.pending_bytes()!=0 || bytes.size()<5) return false;
        auto const len=(std::size_t{bytes[3]}<<8)|bytes[4];
        return bytes.size()>=5+len;
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
        if (auto side=handle_opened_event(*event); !side) return std::unexpected(side.error());
        out.event=std::move(*event); return out;
        } catch (...) { cancel(); throw; }
    }
    auto ApplicationIo::feed_into(std::span<std::uint8_t const> bytes, std::span<std::uint8_t> plaintext_out)
        -> std::expected<ApplicationIoFeedInto,ApplicationIoError> {
        if (failed_ || overflow_ || peer_closed_ || input_finished_ || input_detached_) return std::unexpected(ApplicationIoError::invalid_state);
        if (response_pending_) return ApplicationIoFeedInto{};
        try {
            auto const overhead=records_->read_overhead();
            if (input_.pending_bytes()==0 && bytes.size()>=5) {
                bool const tls12=records_->tls12();
                auto const type=bytes[0];
                auto const length=(std::size_t{bytes[3]}<<8)|bytes[4];
                if (bytes[1]!=3 || bytes[2]!=3 ||
                    (tls12 ? (type<21 || type>23 || length<16) : (type!=23 || length<17))) {
                    return fail(ApplicationIoError::record_error);
                }
                auto const maximum=tls12 ? 16408u : 16640u;
                if (length>maximum) {
                    if (records_->signal_overflow()) return overflow_failure();
                    return fail(ApplicationIoError::record_error);
                }
                auto const needed=(5+length>overhead) ? (5+length-overhead) : std::size_t{0};
                if (bytes.size()>=5+length && plaintext_out.size()>=needed) {
                    auto opened=records_->open_data_into(bytes.first(5+length),plaintext_out);
                    if (!opened && opened.error()==RecordError::record_overflow) return overflow_failure();
                    if (!opened) {
                        if (opened.error()!=RecordError::invalid_input) return fail(ApplicationIoError::record_error);
                    } else {
                        if (opened->event) {
                            if (auto side=handle_opened_event(*opened->event); !side) return std::unexpected(side.error());
                            return ApplicationIoFeedInto{5+length,0,std::move(opened->event)};
                        }
                        return ApplicationIoFeedInto{5+length,opened->data_size,std::nullopt};
                    }
                }
            }
            auto framed=input_.feed(bytes,records_->tls12() ? RecordFraming::tls12_gcm : RecordFraming::ciphertext);
            if (!framed) {
                if (framed.error()==RecordStreamError::record_too_large && records_->signal_overflow()) return overflow_failure();
                return fail(ApplicationIoError::record_error);
            }
            if (!framed->record) return ApplicationIoFeedInto{framed->consumed,0,std::nullopt};
            auto const rec_bytes=std::span<std::uint8_t const>{framed->record->bytes};
            if (rec_bytes.size()>=overhead && plaintext_out.size()>=rec_bytes.size()-overhead) {
                auto opened=records_->open_data_into(rec_bytes,plaintext_out);
                if (!opened && opened.error()==RecordError::record_overflow) return overflow_failure();
                if (opened) {
                    if (opened->event) {
                        if (auto side=handle_opened_event(*opened->event); !side) return std::unexpected(side.error());
                        return ApplicationIoFeedInto{framed->consumed,0,std::move(opened->event)};
                    }
                    return ApplicationIoFeedInto{framed->consumed,opened->data_size,std::nullopt};
                }
                if (opened.error()!=RecordError::invalid_input) return fail(ApplicationIoError::record_error);
            }
            auto event=records_->open_event(rec_bytes);
            if (!event && event.error()==RecordError::record_overflow) return overflow_failure();
            if (!event) return fail(ApplicationIoError::record_error);
            if (auto side=handle_opened_event(*event); !side) return std::unexpected(side.error());
            return ApplicationIoFeedInto{framed->consumed,0,std::move(*event)};
        } catch (...) { cancel(); throw; }
    }
    auto ApplicationIo::detach_input() noexcept -> bool {
        if (failed_ || overflow_ || peer_closed_ || input_finished_ || input_detached_ || response_pending_ || input_.pending_bytes()) return false;
        input_detached_=true; return true;
    }
    auto ApplicationIo::detach_output() noexcept -> bool {
        if (failed_ || overflow_ || output_detached_ || response_pending_ || output_busy()) return false;
        output_detached_=true; return true;
    }
    auto ApplicationIo::can_handoff_ktls_tx() const noexcept -> bool {
        return !failed_ && !overflow_ && !output_detached_ && !response_pending_ &&
            !output_busy() && records_ && records_->can_handoff_tx();
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
