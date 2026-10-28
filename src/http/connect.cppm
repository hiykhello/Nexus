export module nexus.http.connect;
import std;

export namespace nexus::http {
    inline constexpr std::size_t max_connect_header_bytes = 16384;
    inline constexpr std::size_t max_connect_fields = 100;

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

    // Input remains owned by the caller. Only bytes through the empty line
    // are consumed; subsequent bytes are the start of the tunnel.
    [[nodiscard]] auto parse_connect(std::string_view input) -> ConnectRequest;
}

export namespace nexus::http {
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
    };
    [[nodiscard]] auto parse_forward_request(std::string_view input) -> ForwardRequest;
    [[nodiscard]] auto parse_forward_response(std::string_view input, bool head) -> ForwardResponse;
}

export namespace nexus::http {
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
    public:
        // Reports the exact input prefix consumed, preserving any following message.
        auto consume_some(std::string_view input, std::string& output) -> ChunkResult;
        auto consume(std::string_view input, std::string& output) -> ChunkStatus;
    };

    enum class ResponseEvent { need_more, header, data, complete, malformed, truncated };
    struct ResponseStep {
        ResponseEvent event;
        std::size_t consumed = 0;
        std::string wire;
        bool informational = false;
    };
    // One response, including at most eight interim responses. Output uses the existing
    // proxy rewriting rules, including normalized chunked framing. Input beyond the
    // response is left untouched. Each step consumes at most 16 KiB.
    class ResponseDecoder {
        enum class State { header, fixed, chunked, close, complete, failed } state_ = State::header;
        bool head_;
        bool frame_close_;
        std::string header_;
        std::uint64_t remaining_ = 0;
        std::size_t informational_ = 0;
        ChunkDecoder chunk_;
    public:
        // For an HTTP/1.1 client, optionally convert close-delimited bodies to
        // chunked framing; finish() emits the terminator only on authenticated EOF.
        explicit ResponseDecoder(bool head = false, bool frame_close = false) : head_(head), frame_close_(frame_close) {}
        [[nodiscard]] auto feed(std::string_view input) -> ResponseStep;
        // Only pass an authenticated transport EOF; premature EOF is truncated.
        [[nodiscard]] auto finish() -> ResponseStep;
    };
}
