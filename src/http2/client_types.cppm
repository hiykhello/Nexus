export module http2.client_types;
import std;
import http2.headers;

export namespace http2 {
    struct FieldView { std::string_view name,value; };
    enum class ClientError { state,limit,allocation,http2,headers,reset,unprocessed,truncated,goaway,canceled,transport,timeout };
    struct ClientFailure { ClientError error; int code=0; std::int32_t stream=0; auto operator==(ClientFailure const&) const -> bool = default; };
    struct StreamTicket { std::uint32_t slot=0,generation=0; std::int32_t id=0; auto operator==(StreamTicket const&) const -> bool = default; };
    struct BodyView { std::span<std::uint8_t const> bytes; bool end_stream=true; };
    struct Goaway { std::int32_t last_id=std::numeric_limits<std::int32_t>::max(); std::uint32_t code=0; };
    struct ClientLimits {
        std::size_t stream_window=65535,connection_window=0,header_fields=100,header_bytes=8192;
        std::size_t library_bytes=4*1024*1024,shared_bytes=8*1024*1024;
        std::size_t outbound_ack=64,encoder_table=4096;
        std::size_t max_body_chunk=2*1024*1024;
        std::uint32_t decoder_table=4096;
        std::size_t outbound_queue_limit=5000;
    };
    struct ResponseView {
        unsigned status=0;
        std::span<Header const> headers,trailers;
        bool local_end=false,remote_end=false,closed=false,body_released=false;
        std::optional<ClientFailure> failure;
    };
    namespace detail {
        class InputRing {
            std::unique_ptr<std::uint8_t[]> bytes_;
            std::size_t capacity_=0,head_=0,size_=0;
        public:
            explicit InputRing(std::size_t capacity) : bytes_(std::make_unique_for_overwrite<std::uint8_t[]>(capacity)),capacity_(capacity) {}
            auto size() const noexcept -> std::size_t { return size_; }
            auto capacity() const noexcept -> std::size_t { return capacity_; }
            auto append(std::span<std::uint8_t const> input) noexcept -> bool {
                if (input.size()>capacity_-size_) return false;
                auto end=(head_+size_)%capacity_,first=std::min(input.size(),capacity_-end);
                if (first) std::memcpy(bytes_.get()+end,input.data(),first);
                if (first<input.size()) std::memcpy(bytes_.get(),input.data()+first,input.size()-first);
                size_+=input.size(); return true;
            }
            auto peek() const noexcept -> std::span<std::uint8_t const> { return {bytes_.get()+head_,std::min(size_,capacity_-head_)}; }
            auto consume(std::size_t count) noexcept -> bool {
                if (count>size_) return false;
                head_=(head_+count)%capacity_; size_-=count; return true;
            }
            auto discard() noexcept -> void { head_=size_=0; }
        };
        inline auto header_charge(std::span<Header const> fields) noexcept -> std::size_t {
            std::size_t result=fields.size()*sizeof(Header);
            for (auto const& field:fields) result+=field.name.size()+field.value.size();
            return result;
        }
        struct ClientStream {
            std::int32_t id=0;
            InputRing input;
            std::vector<Header> headers,trailers;
            std::span<std::uint8_t const> body;
            std::size_t body_offset=0,body_reserved=0,received=0,provided=0;
            std::optional<std::size_t> request_length,response_length;
            std::optional<ClientFailure> failure;
            unsigned status=0,hints=0;
            bool head=false,no_body=false,headers_sent=false,end_requested=false,deferred=false;
            bool local_end=false,remote_end=false,closed=false,cancel_requested=false;
            ClientStream(std::size_t capacity,BodyView initial)
                : input(capacity),body(initial.bytes),body_reserved(initial.bytes.size()),provided(initial.bytes.size()),end_requested(initial.end_stream) {}
            auto release_body() noexcept -> void { body={}; body_offset=body_reserved=0; }
            auto charge() const noexcept -> std::size_t { return input.capacity()+header_charge(headers)+header_charge(trailers)+body_reserved; }
        };
    }
}
