export module nexus.tls.server_hello_stream;
export import nexus.tls.server_hello;
import nexus.tls.handshake;
import nexus.tls.record_stream;
import std;

export namespace nexus::tls {
    enum class ServerHelloStreamError { invalid_state, invalid_record, invalid_message, invalid_retry, truncated };
    struct ServerHelloFeed {
        std::size_t consumed = 0;
        std::optional<std::vector<std::uint8_t>> message;
        bool retry = false;
    };
    // Reassembles one ServerHello per phase. Caller must send ClientHello2 before resume_retry().
    class ServerHelloStream {
        enum class State { first, retry_pending, final, complete, failed } state_=State::first;
        RecordStream records_;
        HandshakeDecoder messages_;
        explicit ServerHelloStream(HandshakeDecoder&& messages) noexcept;
    public:
        [[nodiscard]] static auto create() -> std::expected<ServerHelloStream,ServerHelloStreamError>;
        ServerHelloStream(ServerHelloStream const&)=delete;
        auto operator=(ServerHelloStream const&) -> ServerHelloStream& = delete;
        ServerHelloStream(ServerHelloStream&& other) noexcept;
        auto operator=(ServerHelloStream&& other) noexcept -> ServerHelloStream&;
        // Stops at a record boundary; resubmit unconsumed input to the next epoch.
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input) -> std::expected<ServerHelloFeed,ServerHelloStreamError>;
        [[nodiscard]] auto resume_retry() -> std::expected<void,ServerHelloStreamError>;
        [[nodiscard]] auto finish_input() -> std::expected<void,ServerHelloStreamError>;
    };
}
