module nexus.tls.record_stream;
import std;

namespace nexus::tls {
    RecordStream::RecordStream(RecordStream&& other) noexcept
        : pending_(std::move(other.pending_)), target_(other.target_), failed_(other.failed_), finished_(other.finished_), mode_(other.mode_) {
        other.failed_=true;
    }
    auto RecordStream::operator=(RecordStream&& other) noexcept -> RecordStream& {
        if (this != &other) {
            pending_=std::move(other.pending_); target_=other.target_; failed_=other.failed_; finished_=other.finished_; mode_=other.mode_;
            other.failed_=true;
        }
        return *this;
    }
    auto RecordStream::feed(std::span<std::uint8_t const> input, RecordFraming mode) -> std::expected<RecordFeed,RecordStreamError> {
        if (failed_ || finished_) return std::unexpected(RecordStreamError::invalid_state);
        if (mode_ && *mode_ != mode) { failed_=true; std::vector<std::uint8_t>{}.swap(pending_); return std::unexpected(RecordStreamError::invalid_state); }
        try {
        RecordFeed out;
        if (!input.empty() && !mode_) { pending_.reserve(5); mode_=mode; }
        while (out.consumed<input.size()) {
            auto count=std::min(target_-pending_.size(),input.size()-out.consumed);
            pending_.insert(pending_.end(),input.begin()+static_cast<std::ptrdiff_t>(out.consumed),input.begin()+static_cast<std::ptrdiff_t>(out.consumed+count));
            out.consumed+=count;
            if (pending_.size()<target_) break;
            if (target_==5) {
                auto type=pending_[0]; auto length=(std::size_t{pending_[3]}<<8)|pending_[4];
                if (((mode==RecordFraming::ciphertext || mode==RecordFraming::handshake_ciphertext) &&
                     (pending_[1]!=3 || pending_[2]!=3 || ((type!=23 || length<17) && !(mode==RecordFraming::handshake_ciphertext && type==20 && length==1)))) ||
                    (mode==RecordFraming::plaintext && ((type!=20 && type!=21 && type!=22 && type!=23) || pending_[1]!=3 || pending_[2]>3))) {
                    failed_=true; std::vector<std::uint8_t>{}.swap(pending_); return std::unexpected(RecordStreamError::invalid_header);
                }
                if (length>(mode==RecordFraming::plaintext ? 16384u : 16640u)) { failed_=true; std::vector<std::uint8_t>{}.swap(pending_); return std::unexpected(RecordStreamError::record_too_large); }
                target_=5+length;
                if (target_!=5) { pending_.reserve(target_); continue; }
            }
            out.record=FramedRecord{std::move(pending_)}; pending_.clear(); target_=5; mode_.reset();
            break;
        }
        return out;
        } catch (...) { failed_=true; std::vector<std::uint8_t>{}.swap(pending_); throw; }
    }
    auto RecordStream::finish() -> std::expected<void,RecordStreamError> {
        if (failed_ || finished_) return std::unexpected(RecordStreamError::invalid_state);
        finished_=true;
        if (!pending_.empty()) { failed_=true; std::vector<std::uint8_t>{}.swap(pending_); return std::unexpected(RecordStreamError::truncated); }
        return {};
    }
}
