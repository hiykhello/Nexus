export module http.connect;
import std;
import http.header;

export namespace http {
    inline constexpr std::size_t max_connect_header_bytes = max_header_bytes;
    inline constexpr std::size_t max_connect_fields = max_header_fields;

    enum class ConnectStatus { incomplete, accepted, malformed, unsupported, too_large, expectation_failed };
    enum class HostKind { domain, ipv4, ipv6 };
    struct ConnectRequest {
        ConnectStatus status = ConnectStatus::incomplete;
        std::size_t consumed = 0;
        HostKind kind = HostKind::domain;
        std::string host;
        std::array<std::uint8_t, 16> address{};
        std::uint16_t port = 0;
    };

    // Shared strict host:port semantics for protocol business destinations.
    // This consumes one complete authority, with no header or transport I/O.
    [[nodiscard]] auto parse_destination_authority(std::string_view input) -> ConnectRequest;

    // Input remains owned by the caller. Only bytes through the empty line
    // are consumed; subsequent bytes are the start of the tunnel.
    [[nodiscard]] auto parse_connect(std::string_view input) -> ConnectRequest;

    enum class HeaderBoundaryStatus { incomplete, complete, too_large };
    // The caller retains and resubmits the unchanged cumulative header.
    // Only the newly appended suffix and three preceding bytes are scanned.
    class HeaderBoundary {
        std::size_t scan_=0;
    public:
        [[nodiscard]] auto inspect(std::string_view input) noexcept -> HeaderBoundaryStatus {
            auto end=input.find("\r\n\r\n",std::min(scan_,input.size()));
            if (end!=input.npos)
                return end+4<=max_connect_header_bytes ? HeaderBoundaryStatus::complete : HeaderBoundaryStatus::too_large;
            if (input.size()>=max_connect_header_bytes) return HeaderBoundaryStatus::too_large;
            scan_=input.size()>3 ? input.size()-3 : 0;
            return HeaderBoundaryStatus::incomplete;
        }
    };

    enum class ConnectEvent { need_more, accepted, rejected, truncated };
    struct ConnectStep { ConnectEvent event; std::size_t consumed=0; };
    // One CONNECT header; the caller keeps the input until it is accepted or
    // rejected. Accepted consumes only the header, leaving tunnel bytes intact.
    class ConnectDecoder {
        enum class State { header, complete, failed, truncated } state_=State::header;
        HeaderBoundary boundary_;
        ConnectRequest request_;
    public:
        [[nodiscard]] auto request() const noexcept -> ConnectRequest const& { return request_; }
        [[nodiscard]] auto feed(std::string_view input) -> ConnectStep;
        [[nodiscard]] auto finish() noexcept -> ConnectStep;
    };
}

export namespace http {
    struct ForwardRequest {
        ConnectStatus status = ConnectStatus::incomplete;
        ConnectRequest destination;
        std::size_t consumed = 0;
        std::uint64_t body_length = 0;
        bool chunked = false;
        bool head = false;
        std::string wire;
    };
    struct ForwardResponse {
        ConnectStatus status = ConnectStatus::incomplete;
        std::size_t consumed = 0;
        std::optional<std::uint64_t> body_length;
        bool chunked = false;
        bool informational = false;
        std::string wire;
        unsigned status_code=0;
        bool identity_encoding=true;
        bool persistent=false;
    };
    [[nodiscard]] auto parse_forward_request(std::string_view input) -> ForwardRequest;
    [[nodiscard]] auto parse_forward_response(std::string_view input, bool head) -> ForwardResponse;
}

export namespace http {
    enum class ChunkOutput { framed, payload };
    enum class ChunkStatus { incomplete, complete, malformed };
    struct ChunkResult { ChunkStatus status; std::size_t consumed; };
    // Consumes only one message. Output contains validated framing and body;
    // trailers are checked and discarded. Buffers remain bounded per call.
    class ChunkDecoder {
        enum class State { size, data, data_cr, data_lf, trailer, complete, failed };
        State state = State::size;
        std::string line;
        std::uint64_t remaining = 0;
        std::size_t trailer_bytes = 0, trailer_fields = 0;
        ChunkOutput output_mode_;
    public:
        explicit ChunkDecoder(ChunkOutput output_mode=ChunkOutput::framed) noexcept : output_mode_(output_mode) {}
        // Reports the exact input prefix consumed, preserving any following message.
        auto consume_some(std::string_view input, std::string& output) -> ChunkResult;
        auto consume(std::string_view input, std::string& output) -> ChunkStatus;
    };

    enum class BodyMode { fixed, chunked, close_delimited };
    enum class BodyEvent { need_more, data, complete, malformed, truncated };
    struct BodyStep {
        BodyEvent event;
        std::size_t consumed=0;
        // Fixed and close-delimited bytes borrow input; normalized chunked
        // bytes borrow the caller's output buffer until its next modification.
        std::string_view wire;
    };
    // One bounded message body, independent of header policy and I/O. For a
    // close-delimited body finish() must only be called on authenticated EOF.
    class BodyDecoder {
        enum class State { active, complete, failed } state_;
        BodyMode mode_;
        std::uint64_t remaining_=0;
        ChunkDecoder chunk_;
    public:
        explicit BodyDecoder(BodyMode mode,std::uint64_t length=0,ChunkOutput output=ChunkOutput::framed) noexcept
            : state_(mode!=BodyMode::fixed && mode!=BodyMode::chunked && mode!=BodyMode::close_delimited ? State::failed :
                     mode==BodyMode::fixed && !length ? State::complete : State::active),mode_(mode),remaining_(length),chunk_(output) {}
        [[nodiscard]] auto mode() const noexcept -> BodyMode { return mode_; }
        [[nodiscard]] auto complete() const noexcept -> bool { return state_==State::complete; }
        [[nodiscard]] auto next_read_size() const noexcept -> std::size_t {
            return state_==State::active && mode_==BodyMode::fixed ?
                static_cast<std::size_t>(std::min<std::uint64_t>(remaining_,max_connect_header_bytes)) : max_connect_header_bytes;
        }
        [[nodiscard]] auto feed(std::string_view input,std::string& chunk_output) -> BodyStep {
            chunk_output.clear();
            if (state_==State::complete) return {BodyEvent::complete};
            if (state_==State::failed) return {BodyEvent::malformed};
            input=input.substr(0,max_connect_header_bytes);
            if (mode_==BodyMode::chunked) {
                auto result=chunk_.consume_some(input,chunk_output);
                if (result.status==ChunkStatus::malformed) {
                    state_=State::failed;
                    return {BodyEvent::malformed,result.consumed};
                }
                if (result.status==ChunkStatus::complete) state_=State::complete;
                return {state_==State::complete ? BodyEvent::complete :
                        chunk_output.empty() ? BodyEvent::need_more : BodyEvent::data,
                        result.consumed,chunk_output};
            }
            if (mode_==BodyMode::fixed) {
                auto n=static_cast<std::size_t>(std::min<std::uint64_t>(remaining_,input.size()));
                remaining_-=n;
                if (!remaining_) state_=State::complete;
                return {state_==State::complete ? BodyEvent::complete : n ? BodyEvent::data : BodyEvent::need_more,
                        n,input.substr(0,n)};
            }
            if (mode_==BodyMode::close_delimited)
                return {input.empty() ? BodyEvent::need_more : BodyEvent::data,input.size(),input};
            state_=State::failed;
            return {BodyEvent::malformed};
        }
        [[nodiscard]] auto finish() noexcept -> BodyStep {
            if (state_==State::complete) return {BodyEvent::complete};
            if (state_==State::failed) return {BodyEvent::malformed};
            if (mode_==BodyMode::close_delimited) {
                state_=State::complete;
                return {BodyEvent::complete};
            }
            state_=State::failed;
            return {BodyEvent::truncated};
        }
    };

    enum class RequestEvent { need_more, header, data, complete, malformed, truncated };
    struct RequestStep {
        RequestEvent event;
        std::size_t consumed = 0;
        // Header borrows the decoder's request; fixed data borrows input; chunked
        // data borrows the caller's output buffer. Consume it before changing the
        // corresponding owner or calling feed() again.
        std::string_view wire;
    };
    // One HTTP/1.1 forward-proxy request. While the header is incomplete the
    // caller retains and resubmits it; body steps consume at most 16 KiB and
    // only this message. finish() marks premature EOF as truncated.
    class RequestDecoder {
        enum class State { header, body, complete, failed } state_=State::header;
        HeaderBoundary boundary_;
        ForwardRequest request_;
        BodyDecoder body_{BodyMode::fixed};
    public:
        [[nodiscard]] auto request() const noexcept -> ForwardRequest const& { return request_; }
        [[nodiscard]] auto complete() const noexcept -> bool { return state_==State::complete; }
        [[nodiscard]] auto next_read_size() const noexcept -> std::size_t {
            return state_==State::body ? body_.next_read_size() : max_connect_header_bytes;
        }
        // chunk_output is cleared each call and owns normalized chunk framing.
        [[nodiscard]] auto feed(std::string_view input,std::string& chunk_output) -> RequestStep;
        [[nodiscard]] auto finish() -> RequestStep;
    };

    enum class ResponseEvent { need_more, header, data, complete, malformed, truncated };
    struct ResponseStep {
        ResponseEvent event;
        std::size_t consumed = 0;
        std::string wire;
        bool informational = false;
        unsigned status_code=0;
        std::optional<std::uint64_t> content_length;
        bool identity_encoding=true;
    };
    // One response, including at most eight interim responses. Output uses the existing
    // proxy rewriting rules, including normalized chunked framing. Input beyond the
    // response is left untouched. Each step consumes at most 16 KiB.
    class ResponseDecoder {
        enum class State { header, body, complete, failed } state_ = State::header;
        bool head_;
        bool frame_close_;
        ChunkOutput chunk_output_;
        std::string header_;
        std::size_t informational_ = 0;
        BodyDecoder body_{BodyMode::fixed};
        bool persistent_=false;
    public:
        [[nodiscard]] auto reusable() const noexcept -> bool {
            return state_==State::complete && persistent_ && body_.mode()!=BodyMode::close_delimited;
        }

        // For an HTTP/1.1 client, optionally convert close-delimited bodies to
        // chunked framing; finish() emits the terminator only on authenticated EOF.
        explicit ResponseDecoder(bool head=false,bool frame_close=false,ChunkOutput output=ChunkOutput::framed)
            :head_(head),frame_close_(frame_close && output==ChunkOutput::framed),chunk_output_(output) {}
        [[nodiscard]] auto feed(std::string_view input) -> ResponseStep;
        // Only pass an authenticated transport EOF; premature EOF is truncated.
        [[nodiscard]] auto finish() -> ResponseStep;
    };
}
