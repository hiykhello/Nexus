export module anytls;
export import net.datagram_frame;
import std;

export namespace anytls {
    using Key=std::array<std::uint8_t,32>;
    using Address=net::ProxyAddress;
    enum class Command : std::uint8_t {
        waste=0,syn=1,push=2,fin=3,settings=4,alert=5,padding=6,
        syn_ack=7,heart_request=8,heart_response=9,server_settings=10
    };
    enum class Status { incomplete,accepted,too_large,invalid_key,closed };
    inline constexpr std::size_t header_size=7,max_payload=65535;
    struct Header { Command command; std::uint32_t stream; std::uint16_t length; };
    struct Frame { Header header; std::span<std::uint8_t const> payload; };
    struct FeedResult { Status status=Status::incomplete; std::size_t consumed=0; };
    inline auto parse_header(std::span<std::uint8_t const> input) noexcept -> std::optional<Header> {
        if (input.size()<header_size) return {};
        return Header{static_cast<Command>(input[0]),(std::uint32_t(input[1])<<24)|(std::uint32_t(input[2])<<16)|
            (std::uint32_t(input[3])<<8)|input[4],static_cast<std::uint16_t>((std::uint16_t(input[5])<<8)|input[6])};
    }
    inline auto append_header(std::vector<std::uint8_t>& output,Header header) -> void {
        output.push_back(static_cast<std::uint8_t>(header.command));
        for (auto shift:{24,16,8,0}) output.push_back(static_cast<std::uint8_t>(header.stream>>shift));
        output.push_back(static_cast<std::uint8_t>(header.length>>8)); output.push_back(static_cast<std::uint8_t>(header.length));
    }
    inline auto encode_frame(Command command,std::uint32_t stream,std::span<std::uint8_t const> payload={})
        -> std::expected<std::vector<std::uint8_t>,Status> {
        if (payload.size()>max_payload) return std::unexpected(Status::too_large);
        std::vector<std::uint8_t> output;
        output.reserve(header_size+payload.size());
        append_header(output,{command,stream,static_cast<std::uint16_t>(payload.size())});
        output.insert(output.end(),payload.begin(),payload.end()); return output;
    }
    // Exactly one retained frame. Its borrowed payload remains valid until
    // consume/close; bytes from the following frame stay with the caller.
    // Unknown commands are framed too, allowing the session to discard them.
    class FrameDecoder {
        std::array<std::uint8_t,header_size> header_{};
        std::size_t size_=0,limit_;
        std::optional<Header> parsed_;
        std::vector<std::uint8_t> payload_;
        Status status_=Status::incomplete;
    public:
        explicit FrameDecoder(std::size_t limit=max_payload) noexcept : limit_(std::min(limit,max_payload)) {}
        FrameDecoder(FrameDecoder const&)=delete;
        auto operator=(FrameDecoder const&) -> FrameDecoder& = delete;
        auto feed(std::span<std::uint8_t const> input) -> FeedResult {
            if (status_!=Status::incomplete) return {status_,0};
            auto copied=std::min(header_size-size_,input.size());
            std::copy_n(input.begin(),copied,header_.begin()+size_); size_+=copied;
            auto consumed=copied;
            if (size_<header_size) return {Status::incomplete,consumed};
            if (!parsed_) {
                parsed_=parse_header(header_);
                if (parsed_->length>limit_) { status_=Status::too_large; return {status_,consumed}; }
                payload_.reserve(parsed_->length);
            }
            auto amount=std::min(std::size_t(parsed_->length)-payload_.size(),input.size()-consumed);
            payload_.insert(payload_.end(),input.begin()+consumed,input.begin()+consumed+amount); consumed+=amount;
            if (payload_.size()==parsed_->length) status_=Status::accepted;
            return {status_,consumed};
        }
        auto frame() const noexcept -> std::optional<Frame> {
            if (status_!=Status::accepted) return {};
            return Frame{*parsed_,payload_};
        }
        auto consume() noexcept -> bool {
            if (status_!=Status::accepted) return false;
            size_=0; parsed_.reset(); payload_.clear(); status_=Status::incomplete; return true;
        }
        auto at_boundary() const noexcept -> bool { return status_==Status::incomplete && !size_; }
        auto close() noexcept -> void { status_=Status::closed; payload_.clear(); }
    };
    inline auto encode_authentication(std::span<std::uint8_t const> key,std::size_t padding)
        -> std::expected<std::vector<std::uint8_t>,Status> {
        if (key.size()!=32) return std::unexpected(Status::invalid_key);
        if (padding>65535) return std::unexpected(Status::too_large);
        std::vector<std::uint8_t> output(34+padding);
        std::ranges::copy(key,output.begin());
        output[32]=static_cast<std::uint8_t>(padding>>8); output[33]=static_cast<std::uint8_t>(padding);
        return output;
    }
    // Authentication padding is skipped without retaining or allocating it.
    class AuthenticationDecoder {
        std::array<std::uint8_t,34> input_{};
        std::size_t size_=0,remaining_=0,limit_;
        Status status_=Status::incomplete;
    public:
        explicit AuthenticationDecoder(std::size_t limit=65535) noexcept : limit_(std::min(limit,std::size_t{65535})) {}
        ~AuthenticationDecoder() {
            volatile std::uint8_t* secret=input_.data();
            for (std::size_t i=0;i<input_.size();++i) secret[i]=0;
        }
        AuthenticationDecoder(AuthenticationDecoder const&)=delete;
        auto operator=(AuthenticationDecoder const&) -> AuthenticationDecoder& = delete;
        auto feed(std::span<std::uint8_t const> input) noexcept -> FeedResult {
            if (status_!=Status::incomplete) return {status_,0};
            std::size_t consumed=0;
            if (size_<input_.size()) {
                consumed=std::min(input_.size()-size_,input.size());
                std::copy_n(input.begin(),consumed,input_.begin()+size_); size_+=consumed;
                if (size_<input_.size()) return {Status::incomplete,consumed};
                remaining_=(std::size_t(input_[32])<<8)|input_[33];
                if (remaining_>limit_) { status_=Status::too_large; return {status_,consumed}; }
            }
            auto skipped=std::min(remaining_,input.size()-consumed);
            remaining_-=skipped; consumed+=skipped;
            if (!remaining_) status_=Status::accepted;
            return {status_,consumed};
        }
        auto key() const noexcept -> std::optional<std::span<std::uint8_t const,32>> {
            if (status_!=Status::accepted) return {};
            return std::span(input_).first<32>();
        }
        auto close() noexcept -> void { status_=Status::closed; }
    };
}
