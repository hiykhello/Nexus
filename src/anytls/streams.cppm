export module anytls.streams;
import std;
import anytls;

export namespace anytls {
    enum class StreamError { closed,full,exhausted,invalid,duplicate,backpressure };
    enum class PushResult { queued,discarded,backpressure };
    struct StreamLimits {
        std::size_t max_streams=64,per_stream_bytes=65535,total_bytes=1024*1024;
        std::size_t per_stream_frames=64,total_frames=256;
        auto valid() const noexcept -> bool {
            return max_streams && max_streams<=64 && per_stream_bytes && per_stream_bytes<=1024*1024 &&
                total_bytes>=per_stream_bytes && total_bytes<=16*1024*1024 &&
                per_stream_frames && per_stream_frames<=256 && total_frames>=per_stream_frames && total_frames<=4096;
        }
    };
    // One executor owns the table. Handles are numeric and IDs never wrap or
    // repeat within a TLS session. Frame payload is copied only after limits
    // admit it; on backpressure the decoder retains that same frame.
    class StreamTable {
        struct Stream {
            std::uint32_t id=0;
            std::deque<std::vector<std::uint8_t>> pending;
            std::size_t buffered=0,offset=0;
            bool ended=false,acknowledged=false,rejected=false;
        };
        std::array<Stream,64> streams_;
        StreamLimits limits_;
        std::size_t count_=0,buffered_=0,queued_=0;
        std::uint64_t next_=1;
        std::uint32_t highest_=0;
        bool closed_=false;
        auto find(std::uint32_t id) noexcept -> Stream* {
            if (!id) return nullptr;
            for (auto& stream:streams_) if (stream.id==id) return &stream;
            return nullptr;
        }
        auto find(std::uint32_t id) const noexcept -> Stream const* {
            if (!id) return nullptr;
            for (auto const& stream:streams_) if (stream.id==id) return &stream;
            return nullptr;
        }
    public:
        explicit StreamTable(StreamLimits limits={}) : limits_(limits) {
            if (!limits.valid()) throw std::invalid_argument("invalid AnyTLS stream limits");
        }
        StreamTable(StreamTable const&)=delete;
        auto operator=(StreamTable const&) -> StreamTable& = delete;
        auto open() noexcept -> std::expected<std::uint32_t,StreamError> {
            if (closed_) return std::unexpected(StreamError::closed);
            if (next_>std::numeric_limits<std::uint32_t>::max()) return std::unexpected(StreamError::exhausted);
            auto id=static_cast<std::uint32_t>(next_);
            auto accepted=accept(id);
            if (!accepted) return std::unexpected(accepted.error());
            next_=std::uint64_t(id)+1; return id;
        }
        auto accept(std::uint32_t id) noexcept -> std::expected<void,StreamError> {
            if (closed_) return std::unexpected(StreamError::closed);
            if (!id) return std::unexpected(StreamError::invalid);
            if (id<=highest_) return std::unexpected(StreamError::duplicate);
            if (count_>=limits_.max_streams) return std::unexpected(StreamError::full);
            for (auto& stream:streams_) if (!stream.id) {
                stream.id=id; highest_=id; ++count_;
                next_=std::max(next_,std::uint64_t(id)+1); return {};
            }
            return std::unexpected(StreamError::full);
        }
        auto push(std::uint32_t id,std::span<std::uint8_t const> payload) -> PushResult {
            auto* stream=find(id);
            if (closed_ || !stream || stream->ended || stream->rejected || payload.empty()) return PushResult::discarded;
            if (payload.size()>limits_.per_stream_bytes || stream->buffered>limits_.per_stream_bytes-payload.size() ||
                payload.size()>limits_.total_bytes || buffered_>limits_.total_bytes-payload.size() ||
                stream->pending.size()>=limits_.per_stream_frames || queued_>=limits_.total_frames) return PushResult::backpressure;
            stream->pending.emplace_back(payload.begin(),payload.end());
            stream->buffered+=payload.size(); buffered_+=payload.size(); ++queued_; return PushResult::queued;
        }
        auto read(std::uint32_t id,std::span<std::uint8_t> output) noexcept -> std::expected<std::size_t,StreamError> {
            auto* stream=find(id);
            if (!stream) return std::unexpected(StreamError::invalid);
            if (stream->rejected || closed_) return std::unexpected(StreamError::closed);
            if (output.empty()) return 0;
            if (stream->pending.empty()) return stream->ended ? std::expected<std::size_t,StreamError>{0} : std::unexpected(StreamError::backpressure);
            auto& bytes=stream->pending.front();
            auto count=std::min(output.size(),bytes.size()-stream->offset);
            std::copy_n(bytes.begin()+stream->offset,count,output.begin());
            stream->offset+=count; stream->buffered-=count; buffered_-=count;
            if (stream->offset==bytes.size()) { stream->pending.pop_front(); stream->offset=0; --queued_; }
            return count;
        }
        auto finish(std::uint32_t id) noexcept -> bool {
            auto* stream=find(id);
            if (!stream) return false;
            stream->ended=true; return true;
        }
        auto acknowledge(std::uint32_t id,bool success=true) noexcept -> bool {
            auto* stream=find(id);
            if (!stream || stream->ended || closed_) return false;
            stream->acknowledged=success;
            if (!success) {
                stream->rejected=true; stream->ended=true;
                buffered_-=stream->buffered; queued_-=stream->pending.size(); stream->pending.clear(); stream->buffered=stream->offset=0;
            }
            return true;
        }
        auto acknowledged(std::uint32_t id) const noexcept -> bool { auto* stream=find(id); return stream && stream->acknowledged; }
        auto rejected(std::uint32_t id) const noexcept -> bool { auto* stream=find(id); return stream && stream->rejected; }
        auto writable(std::uint32_t id) const noexcept -> bool { auto* stream=find(id); return !closed_ && stream && !stream->ended && !stream->rejected; }
        auto release(std::uint32_t id) noexcept -> bool {
            auto* stream=find(id);
            if (!stream) return false;
            buffered_-=stream->buffered; queued_-=stream->pending.size(); stream->pending.clear();
            stream->id=0; stream->buffered=stream->offset=0; stream->ended=stream->acknowledged=stream->rejected=false;
            --count_; return true;
        }
        auto close() noexcept -> void {
            closed_=true;
            for (auto& stream:streams_) { stream.pending.clear(); stream.buffered=stream.offset=0; stream.ended=true; }
            buffered_=queued_=0;
        }
        auto size() const noexcept -> std::size_t { return count_; }
        auto buffered() const noexcept -> std::size_t { return buffered_; }
        auto buffered(std::uint32_t id) const noexcept -> std::size_t { auto* stream=find(id); return stream ? stream->buffered : 0; }
        auto exhausted() const noexcept -> bool { return next_>std::numeric_limits<std::uint32_t>::max(); }
        auto max_frame_payload() const noexcept -> std::size_t { return std::min(limits_.per_stream_bytes,limits_.total_bytes); }
    };
}
