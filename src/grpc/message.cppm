export module grpc.message;
import std;

export namespace grpc {
    inline constexpr std::size_t max_message_bytes=4*1024*1024,max_hunk_bytes=1024*1024;
    enum class MessageStatus { incomplete,accepted,malformed,compressed,too_large,truncated,closed };
    struct Varint { MessageStatus status=MessageStatus::incomplete; std::size_t consumed=0; std::uint64_t value=0; };
    auto read_varint(std::span<std::uint8_t const> input) noexcept -> Varint;
    auto append_varint(std::vector<std::uint8_t>& output,std::uint64_t value) -> void;
    namespace message_detail {
        auto skip(std::span<std::uint8_t const> input,std::uint32_t field,unsigned wire,unsigned depth,std::size_t& fields) noexcept -> std::optional<std::size_t>;
    }
    struct HunkResult { MessageStatus status; std::span<std::uint8_t const> data; };
    // Parse a complete protobuf Hunk. Missing bytes data is empty; repeated
    // singular field 1 follows protobuf's last-value rule. Unknown fields are
    // skipped within bounded field/depth limits, not exposed as tunnel data.
    auto parse_hunk(std::span<std::uint8_t const> input,std::size_t data_limit=max_hunk_bytes) noexcept -> HunkResult;
    auto encode_message(std::span<std::uint8_t const> data,std::size_t data_limit=max_hunk_bytes)
        -> std::expected<std::vector<std::uint8_t>,MessageStatus>;
    struct MessageFeed { MessageStatus status=MessageStatus::incomplete; std::size_t consumed=0; };
    // One retained, validated Hunk. Arbitrary DATA/transport fragments may
    // cross both length layers; later messages remain with the caller.
    class MessageDecoder {
        std::array<std::uint8_t,5> header_{};
        std::size_t header_size_=0,size_=0,wire_limit_,data_limit_;
        std::vector<std::uint8_t> message_;
        std::span<std::uint8_t const> data_;
        MessageStatus status_=MessageStatus::incomplete;
    public:
        explicit MessageDecoder(std::size_t wire_limit=max_message_bytes,std::size_t data_limit=max_hunk_bytes) noexcept
            : wire_limit_(std::min(wire_limit,max_message_bytes)),data_limit_(std::min(data_limit,max_hunk_bytes)) {}
        MessageDecoder(MessageDecoder const&)=delete;
        auto operator=(MessageDecoder const&) -> MessageDecoder& = delete;
        auto feed(std::span<std::uint8_t const> input) -> MessageFeed;
        auto data() const noexcept -> std::optional<std::span<std::uint8_t const>>;
        auto wire_size() const noexcept -> std::size_t { return header_.size()+size_; }
        auto at_boundary() const noexcept -> bool { return status_==MessageStatus::incomplete && !header_size_; }
        auto consume() noexcept -> bool;
        auto finish() noexcept -> MessageStatus;
        auto close() noexcept -> void;
    };
}

module :private;

namespace grpc {
    auto read_varint(std::span<std::uint8_t const> input) noexcept -> Varint {
        std::uint64_t value=0;
        for (std::size_t index=0;index<std::min(input.size(),std::size_t{10});++index) {
            auto byte=input[index];
            if (index==9 && byte>1) return {MessageStatus::malformed};
            value|=std::uint64_t(byte&127)<<(7*index);
            if (!(byte&128)) return {MessageStatus::accepted,index+1,value};
        }
        return {input.size()>=10 ? MessageStatus::malformed : MessageStatus::incomplete};
    }
    auto append_varint(std::vector<std::uint8_t>& output,std::uint64_t value) -> void {
        while (value>=128) { output.push_back(static_cast<std::uint8_t>(value)|128); value>>=7; }
        output.push_back(static_cast<std::uint8_t>(value));
    }
    namespace message_detail {
        auto skip(std::span<std::uint8_t const> input,std::uint32_t field,unsigned wire,unsigned depth,std::size_t& fields) noexcept -> std::optional<std::size_t> {
            if (wire==0) { auto value=read_varint(input); return value.status==MessageStatus::accepted ? std::optional{value.consumed} : std::nullopt; }
            if (wire==1 || wire==5) { auto size=wire==1 ? 8u : 4u; return input.size()>=size ? std::optional<std::size_t>{size} : std::nullopt; }
            if (wire==2) {
                auto length=read_varint(input);
                if (length.status!=MessageStatus::accepted || length.value>input.size()-length.consumed) return {};
                return length.consumed+static_cast<std::size_t>(length.value);
            }
            if (wire!=3 || depth>=16) return {};
            std::size_t offset=0;
            while (offset<input.size()) {
                if (++fields>256) return {};
                auto tag=read_varint(input.subspan(offset));
                if (tag.status!=MessageStatus::accepted || !(tag.value>>3) || (tag.value>>3)>0x1fffffff) return {};
                offset+=tag.consumed;
                auto number=static_cast<std::uint32_t>(tag.value>>3); auto type=unsigned(tag.value&7);
                if (type==4) return number==field ? std::optional{offset} : std::nullopt;
                auto consumed=skip(input.subspan(offset),number,type,depth+1,fields);
                if (!consumed) return {};
                offset+=*consumed;
            }
            return {};
        }
    }
    auto parse_hunk(std::span<std::uint8_t const> input,std::size_t data_limit) noexcept -> HunkResult {
        std::span<std::uint8_t const> data;
        std::size_t offset=0,fields=0;
        while (offset<input.size()) {
            if (++fields>256) return {MessageStatus::too_large,{}};
            auto tag=read_varint(input.subspan(offset));
            if (tag.status!=MessageStatus::accepted || !(tag.value>>3) || (tag.value>>3)>0x1fffffff) return {MessageStatus::malformed,{}};
            offset+=tag.consumed;
            auto number=static_cast<std::uint32_t>(tag.value>>3); auto wire=unsigned(tag.value&7);
            if (number==1) {
                if (wire!=2) return {MessageStatus::malformed,{}};
                auto length=read_varint(input.subspan(offset));
                if (length.status!=MessageStatus::accepted || length.value>input.size()-offset-length.consumed) return {MessageStatus::malformed,{}};
                if (length.value>data_limit) return {MessageStatus::too_large,{}};
                offset+=length.consumed; data=input.subspan(offset,static_cast<std::size_t>(length.value)); offset+=data.size();
            } else {
                auto consumed=message_detail::skip(input.subspan(offset),number,wire,0,fields);
                if (!consumed) return {MessageStatus::malformed,{}};
                offset+=*consumed;
            }
        }
        return {MessageStatus::accepted,data};
    }
    auto encode_message(std::span<std::uint8_t const> data,std::size_t data_limit)
        -> std::expected<std::vector<std::uint8_t>,MessageStatus> {
        if (data.size()>data_limit || data.size()>max_hunk_bytes) return std::unexpected(MessageStatus::too_large);
        auto length=data.size();
        std::size_t varint=1;
        for (auto value=length;value>=128;value>>=7) ++varint;
        auto body=data.empty() ? 0 : 1+varint+length;
        if (body>max_message_bytes) return std::unexpected(MessageStatus::too_large);
        std::vector<std::uint8_t> result;
        result.reserve(5+body); result.push_back(0);
        for (auto shift:{24,16,8,0}) result.push_back(static_cast<std::uint8_t>(body>>shift));
        if (!data.empty()) { result.push_back(10); append_varint(result,length); result.insert(result.end(),data.begin(),data.end()); }
        return result;
    }
    auto MessageDecoder::feed(std::span<std::uint8_t const> input) -> MessageFeed {
        if (status_!=MessageStatus::incomplete) return {status_,0};
        std::size_t consumed=0;
        if (header_size_<header_.size()) {
            consumed=std::min(header_.size()-header_size_,input.size());
            std::copy_n(input.begin(),consumed,header_.begin()+header_size_); header_size_+=consumed;
            if (header_size_<header_.size()) return {status_,consumed};
            if (header_[0]) { status_=header_[0]==1 ? MessageStatus::compressed : MessageStatus::malformed; return {status_,consumed}; }
            size_=(std::uint32_t(header_[1])<<24)|(std::uint32_t(header_[2])<<16)|(std::uint32_t(header_[3])<<8)|header_[4];
            if (size_>wire_limit_) { status_=MessageStatus::too_large; return {status_,consumed}; }
            message_.reserve(size_);
        }
        auto copied=std::min(size_-message_.size(),input.size()-consumed);
        message_.insert(message_.end(),input.begin()+consumed,input.begin()+consumed+copied); consumed+=copied;
        if (message_.size()<size_) return {status_,consumed};
        auto hunk=parse_hunk(message_,data_limit_);
        status_=hunk.status;
        if (status_==MessageStatus::accepted) data_=hunk.data;
        return {status_,consumed};
    }
    auto MessageDecoder::data() const noexcept -> std::optional<std::span<std::uint8_t const>> {
        if (status_!=MessageStatus::accepted) return {}; return data_;
    }
    auto MessageDecoder::consume() noexcept -> bool {
        if (status_!=MessageStatus::accepted) return false;
        message_.clear(); data_={}; size_=header_size_=0; status_=MessageStatus::incomplete; return true;
    }
    auto MessageDecoder::finish() noexcept -> MessageStatus {
        if (status_!=MessageStatus::incomplete) return status_;
        if (at_boundary()) return MessageStatus::accepted;
        return status_=MessageStatus::truncated;
    }
    auto MessageDecoder::close() noexcept -> void { status_=MessageStatus::closed; data_={}; message_.clear(); }
}
