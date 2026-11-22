export module tailscale.derp;
import std;

export namespace tailscale::derp {
    using Key=std::array<std::uint8_t,32>;
    inline constexpr std::size_t header_size=5,key_size=32,nonce_size=24,box_overhead=16;
    inline constexpr std::size_t max_packet_size=65536,max_frame_size=1024*1024,max_client_info_size=256*1024;
    inline constexpr std::array<std::uint8_t,8> magic{0x44,0x45,0x52,0x50,0xf0,0x9f,0x94,0x91};
    inline constexpr unsigned protocol_version=2;
    enum class Type : std::uint8_t {
        server_key=0x01,client_info=0x02,server_info=0x03,send_packet=0x04,recv_packet=0x05,
        keep_alive=0x06,note_preferred=0x07,peer_gone=0x08,peer_present=0x09,forward_packet=0x0a,
        watch_connections=0x10,close_peer=0x11,ping=0x12,pong=0x13,health=0x14,restarting=0x15
    };
    enum class Error { incomplete,too_large,invalid,wrong_type,truncated,closed };
    struct Header { Type type; std::uint32_t length; };
    struct Frame { Type type; std::span<std::uint8_t const> payload; };
    struct Feed { std::size_t consumed=0; std::optional<Error> error; bool ready=false; };
    inline auto known(Type type) noexcept -> bool {
        switch (type) {
        case Type::server_key: case Type::client_info: case Type::server_info: case Type::send_packet:
        case Type::recv_packet: case Type::keep_alive: case Type::note_preferred: case Type::peer_gone:
        case Type::peer_present: case Type::forward_packet: case Type::watch_connections: case Type::close_peer:
        case Type::ping: case Type::pong: case Type::health: case Type::restarting: return true;
        }
        return false;
    }
    inline auto parse_header(std::span<std::uint8_t const> bytes) noexcept -> std::expected<Header,Error> {
        if (bytes.size()<header_size) return std::unexpected(Error::incomplete);
        return Header{static_cast<Type>(bytes[0]),(std::uint32_t(bytes[1])<<24)|(std::uint32_t(bytes[2])<<16)|
            (std::uint32_t(bytes[3])<<8)|bytes[4]};
    }
    inline auto encode_header(Type type,std::size_t size) noexcept -> std::expected<std::array<std::uint8_t,5>,Error> {
        if (size>max_frame_size) return std::unexpected(Error::too_large);
        auto count=static_cast<std::uint32_t>(size);
        return std::array<std::uint8_t,5>{static_cast<std::uint8_t>(type),static_cast<std::uint8_t>(count>>24),
            static_cast<std::uint8_t>(count>>16),static_cast<std::uint8_t>(count>>8),static_cast<std::uint8_t>(count)};
    }
    inline auto payload_limit(Type type) noexcept -> std::size_t {
        switch (type) {
        case Type::client_info: return max_client_info_size;
        case Type::send_packet: case Type::recv_packet: return key_size+max_packet_size;
        case Type::forward_packet: return key_size*2+max_packet_size;
        default: return max_frame_size;
        }
    }
    inline auto encode_frame(Type type,std::span<std::uint8_t const> payload) -> std::expected<std::vector<std::uint8_t>,Error> {
        if (payload.size()>payload_limit(type)) return std::unexpected(Error::too_large);
        auto header=encode_header(type,payload.size());
        if (!header) return std::unexpected(header.error());
        std::vector<std::uint8_t> result;
        result.reserve(header_size+payload.size());
        result.insert(result.end(),header->begin(),header->end());
        result.insert(result.end(),payload.begin(),payload.end());
        return result;
    }
    // One retained frame, independent of I/O and authentication. Returned views
    // borrow until consume()/close(); trailing input belongs to the caller.
    class Decoder {
        std::array<std::uint8_t,header_size> header_{};
        std::size_t header_bytes_=0,limit_;
        std::optional<Header> parsed_;
        std::vector<std::uint8_t> payload_;
        std::optional<Error> failure_;
        bool ready_=false,closed_=false;
    public:
        explicit Decoder(std::size_t limit=max_frame_size) noexcept : limit_(std::min(limit,max_frame_size)) {}
        Decoder(Decoder const&)=delete;
        auto operator=(Decoder const&) -> Decoder& = delete;
        auto feed(std::span<std::uint8_t const> bytes) -> Feed {
            if (closed_) return {0,Error::closed};
            if (failure_) return {0,failure_};
            if (ready_) return {0,{},true};
            auto amount=std::min(header_size-header_bytes_,bytes.size());
            std::copy_n(bytes.begin(),amount,header_.begin()+header_bytes_);
            header_bytes_+=amount;
            if (header_bytes_<header_size) return {amount};
            if (!parsed_) {
                auto parsed=parse_header(header_);
                parsed_=*parsed;
                if (parsed_->length>std::min(limit_,payload_limit(parsed_->type))) {
                    failure_=Error::too_large; return {amount,failure_};
                }
                payload_.reserve(parsed_->length);
            }
            auto copied=std::min(std::size_t(parsed_->length)-payload_.size(),bytes.size()-amount);
            payload_.insert(payload_.end(),bytes.begin()+amount,bytes.begin()+amount+copied);
            ready_=payload_.size()==parsed_->length;
            return {amount+copied,{},ready_};
        }
        auto frame() const noexcept -> std::optional<Frame> {
            if (!ready_ || closed_ || failure_) return {};
            return Frame{parsed_->type,payload_};
        }
        auto consume() noexcept -> bool {
            if (!ready_ || closed_ || failure_) return false;
            ready_=false; header_bytes_=0; parsed_.reset(); payload_.clear(); return true;
        }
        auto finish() noexcept -> std::expected<void,Error> {
            if (closed_) return std::unexpected(Error::closed);
            if (failure_) return std::unexpected(*failure_);
            if (!ready_ && header_bytes_) { failure_=Error::truncated; return std::unexpected(*failure_); }
            return {};
        }
        auto at_boundary() const noexcept -> bool { return !closed_ && !failure_ && !ready_ && !header_bytes_; }
        auto retained_bytes() const noexcept -> std::size_t { return payload_.size(); }
        auto close() noexcept -> void { closed_=true; payload_.clear(); ready_=false; }
    };
}

