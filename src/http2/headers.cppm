export module nexus.http2.headers;
import std;

export namespace nexus::http2 {
    struct Header {
        std::string name;
        std::string value;
        auto operator==(Header const&) const -> bool = default;
    };

    enum class HeaderResult { accepted, limit_exceeded, allocation_failed, invalid_state };

    // One header block is decoded at a time by nghttp2, even across CONTINUATION frames.
    // The owner must consume the block at frame completion and discard it on stream failure.
    class HeaderBlock {
        std::size_t max_fields_;
        std::size_t max_bytes_;
        std::size_t bytes_ = 0;
        std::int32_t stream_ = 0;
        std::vector<Header> fields_;
    public:
        HeaderBlock(std::size_t max_fields, std::size_t max_bytes)
            : max_fields_(max_fields), max_bytes_(max_bytes) {}

        void begin(std::int32_t stream) noexcept {
            discard(); stream_ = stream;
        }
        void discard() noexcept { std::vector<Header>{}.swap(fields_); bytes_ = 0; stream_ = 0; }
        auto stream() const noexcept -> std::int32_t { return stream_; }
        auto fields() const noexcept -> std::span<Header const> { return fields_; }
        // Logical charge, not allocator consumption or vector/string capacity.
        auto memory_charge() const noexcept -> std::size_t { return bytes_ + fields_.size() * sizeof(Header); }
        auto add(std::int32_t stream, std::string_view name, std::string_view value) noexcept -> HeaderResult {
            if (stream <= 0 || stream != stream_) return HeaderResult::invalid_state;
            if (fields_.size() >= max_fields_ || name.size() > max_bytes_ - bytes_ ||
                value.size() > max_bytes_ - bytes_ - name.size()) return HeaderResult::limit_exceeded;
            auto remaining=std::numeric_limits<std::size_t>::max()-memory_charge();
            if (sizeof(Header)>remaining || name.size()>remaining-sizeof(Header) ||
                value.size()>remaining-sizeof(Header)-name.size()) return HeaderResult::limit_exceeded;
            try {
                fields_.push_back({std::string(name), std::string(value)});
                bytes_ += name.size() + value.size();
                return HeaderResult::accepted;
            } catch (...) { return HeaderResult::allocation_failed; }
        }
    };
}
