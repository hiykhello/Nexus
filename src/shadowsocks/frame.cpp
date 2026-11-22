module shadowsocks.frame;
import std;
import shadowsocks.chunk;
namespace shadowsocks {
    namespace {
        auto frame_error(ChunkError error) -> FrameError {
            return error==ChunkError::authentication_failed ? FrameError::authentication : FrameError::crypto;
        }
    }
    auto FrameEncoder::encode(std::span<std::uint8_t const> payload) -> std::expected<std::vector<std::uint8_t>,FrameError> {
        if (!active_) return std::unexpected(FrameError::closed);
        active_=false;
        if (payload.size()>65535) return std::unexpected(FrameError::invalid_length);
        std::array<std::uint8_t,2> length{static_cast<std::uint8_t>(payload.size()>>8),static_cast<std::uint8_t>(payload.size())};
        auto first=cipher_.process(length); if (!first) return std::unexpected(frame_error(first.error()));
        auto second=cipher_.process(payload); if (!second) return std::unexpected(frame_error(second.error()));
        first->reserve(first->size()+second->size()); first->insert(first->end(),second->begin(),second->end());
        active_=true; return std::move(*first);
    }
    auto FrameDecoder::feed(std::span<std::uint8_t const> input) -> std::expected<FrameStep,FrameError> {
        if (!active_) return std::unexpected(FrameError::closed);
        active_=false;
        std::size_t consumed=0;
        while (consumed<input.size()) {
            auto count=std::min(needed_-buffer_.size(),input.size()-consumed);
            buffer_.insert(buffer_.end(),input.begin()+consumed,input.begin()+consumed+count); consumed+=count;
            if (buffer_.size()!=needed_) break;
            auto plain=cipher_.process(buffer_);
            if (!plain) return std::unexpected(frame_error(plain.error()));
            buffer_.clear();
            if (length_) {
                if (plain->size()!=2) return std::unexpected(FrameError::crypto);
                needed_=((static_cast<std::size_t>((*plain)[0])<<8)|(*plain)[1])+16; length_=false;
            } else {
                needed_=18; length_=true; active_=true;
                return FrameStep{consumed,std::move(*plain)};
            }
        }
        active_=true; return FrameStep{consumed,std::nullopt};
    }
    auto FrameDecoder::finish() -> std::expected<void,FrameError> {
        if (!active_) return std::unexpected(FrameError::closed);
        active_=false;
        if (!length_ || !buffer_.empty()) return std::unexpected(FrameError::truncated);
        return {};
    }
}
