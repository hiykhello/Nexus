export module nexus.tls.client_hello_stream;
export import nexus.tls.hello;
import nexus.tls.handshake;
import nexus.tls.record_stream;
import std;

export namespace nexus::tls {
    enum class ClientHelloStreamError { invalid_state, invalid_record, invalid_message, truncated };
    struct ClientHelloFeed {
        std::size_t consumed = 0;
        std::optional<ClientHello> hello;
        // Exact handshake encoding, including its four-byte header, for the transcript.
        std::vector<std::uint8_t> message;
        bool compatibility_ccs = false;
    };
    // Receives one initial ClientHello; no retry, early data or PSK policy is implied.
    class ClientHelloStream {
        enum class State { reading, complete, failed } state_=State::reading;
        RecordStream records_;
        HandshakeDecoder messages_;
        bool allow_ccs_=false, ccs_seen_=false;
        explicit ClientHelloStream(HandshakeDecoder&& messages, bool allow_ccs) noexcept;
    public:
        [[nodiscard]] static auto create(std::size_t max_body_size=65535, bool allow_ccs=false) -> std::expected<ClientHelloStream,ClientHelloStreamError>;
        ClientHelloStream(ClientHelloStream const&)=delete;
        auto operator=(ClientHelloStream const&) -> ClientHelloStream& = delete;
        ClientHelloStream(ClientHelloStream&&) noexcept;
        auto operator=(ClientHelloStream&&) noexcept -> ClientHelloStream&;
        // Consumes at most one record; the caller retains the unconsumed suffix.
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input) -> std::expected<ClientHelloFeed,ClientHelloStreamError>;
        [[nodiscard]] auto finish_input() -> std::expected<void,ClientHelloStreamError>;
    };
}
