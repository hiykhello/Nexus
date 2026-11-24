module shadowsocks.frame;
import std;
import shadowsocks.chunk;
namespace shadowsocks {
    namespace {
        auto frame_error(ChunkError error) -> FrameError {
            return error==ChunkError::authentication_failed ? FrameError::authentication : FrameError::crypto;
        }
    }
    auto FrameEncoder::encode_wire(std::span<std::uint8_t const> payload) -> std::expected<std::span<std::uint8_t const>,FrameError> {
        if (!active_) return std::unexpected(FrameError::closed);
        active_=false;
        if (payload.size()>65535) return std::unexpected(FrameError::invalid_length);
        auto const total = std::size_t{18} + payload.size() + 16;
        if (wire_cap_ < total) {
            auto const next_cap = std::max(total, total <= 4096 ? std::size_t{4096} : std::size_t{65569});
            wire_ = std::make_unique_for_overwrite<std::uint8_t[]>(next_cap);
            wire_cap_ = next_cap;
        }
        std::array<std::uint8_t,2> length{static_cast<std::uint8_t>(payload.size()>>8),static_cast<std::uint8_t>(payload.size())};
        auto first=cipher_.process_to(length, std::span(wire_.get(), 18));
        if (!first || *first != 18) return std::unexpected(first ? FrameError::crypto : frame_error(first.error()));
        auto second=cipher_.process_to(payload, std::span(wire_.get() + 18, payload.size() + 16));
        if (!second) return std::unexpected(frame_error(second.error()));
        active_=true;
        return std::span<std::uint8_t const>(wire_.get(), 18 + *second);
    }
    auto FrameEncoder::encode(std::span<std::uint8_t const> payload) -> std::expected<std::vector<std::uint8_t>,FrameError> {
        auto wire = encode_wire(payload);
        if (!wire) return std::unexpected(wire.error());
        return std::vector<std::uint8_t>(wire->begin(), wire->end());
    }
    auto FrameDecoder::feed_span(std::span<std::uint8_t const> input, std::span<std::uint8_t> direct_out,
        std::vector<std::uint8_t>& overflow_out) -> std::expected<FrameSpanStep,FrameError> {
        if (!active_) return std::unexpected(FrameError::closed);
        active_=false;
        std::size_t consumed=0;
        while (consumed<input.size()) {
            std::span<std::uint8_t const> chunk;
            if (buffer_.empty() && input.size()-consumed>=needed_) {
                chunk=input.subspan(consumed,needed_);
                consumed+=needed_;
            } else {
                auto count=std::min(needed_-buffer_.size(),input.size()-consumed);
                buffer_.insert(buffer_.end(),input.begin()+consumed,input.begin()+consumed+count);
                consumed+=count;
                if (buffer_.size()!=needed_) break;
                chunk=buffer_;
            }
            if (length_) {
                std::array<std::uint8_t,2> plain_len{};
                auto written=cipher_.process_to(chunk,plain_len);
                buffer_.clear();
                if (!written) return std::unexpected(frame_error(written.error()));
                if (*written!=2) return std::unexpected(FrameError::crypto);
                needed_=((static_cast<std::size_t>(plain_len[0])<<8)|plain_len[1])+16;
                length_=false;
            } else {
                auto const plain_size = needed_ - 16;
                if (plain_size <= direct_out.size()) {
                    auto written=cipher_.process_to(chunk, direct_out.first(plain_size));
                    buffer_.clear();
                    if (!written) return std::unexpected(frame_error(written.error()));
                    needed_=18; length_=true; active_=true;
                    return FrameSpanStep{consumed,*written,true,false};
                }
                if (overflow_out.size() < plain_size) overflow_out.resize(plain_size);
                auto written=cipher_.process_to(chunk, std::span(overflow_out).first(plain_size));
                buffer_.clear();
                if (!written) { overflow_out.clear(); return std::unexpected(frame_error(written.error())); }
                overflow_out.resize(*written);
                needed_=18; length_=true; active_=true;
                return FrameSpanStep{consumed,0,true,true};
            }
        }
        active_=true;
        return FrameSpanStep{consumed,0,false,false};
    }
    auto FrameDecoder::feed_into(std::span<std::uint8_t const> input, std::vector<std::uint8_t>& out)
        -> std::expected<FrameIntoStep,FrameError> {
        auto step=feed_span(input, {}, out);
        if (!step) return std::unexpected(step.error());
        if (step->has_frame) {
            if (!step->has_overflow) out.clear();
            return FrameIntoStep{step->consumed, true};
        }
        return FrameIntoStep{step->consumed, false};
    }
    auto FrameDecoder::feed(std::span<std::uint8_t const> input) -> std::expected<FrameStep,FrameError> {
        std::vector<std::uint8_t> plain;
        auto step=feed_into(input,plain);
        if (!step) return std::unexpected(step.error());
        if (step->has_payload) return FrameStep{step->consumed,std::move(plain)};
        return FrameStep{step->consumed,std::nullopt};
    }
    auto FrameDecoder::finish() -> std::expected<void,FrameError> {
        if (!active_) return std::unexpected(FrameError::closed);
        active_=false;
        if (!length_ || !buffer_.empty()) return std::unexpected(FrameError::truncated);
        return {};
    }
}
