export module nexus.tls.server_handshake_io;
export import nexus.tls.server_flight;
import nexus.tls.client_hello_stream;
import nexus.tls.record_stream;
import std;
export namespace nexus::tls {
    enum class ServerHandshakeIoError { invalid_state, invalid_argument, time_reversed, timeout, canceled, protocol_error };
    struct ServerHandshakeIoFeed { std::size_t consumed=0; };
    // Single owner; monotonic milliseconds, absolute deadline. No socket operations.
    class ServerHandshakeIo {
        enum class State { hello, retry_output, retry_hello, output, finished, complete, failed } state_=State::hello;
        std::optional<ServerCredential> credential_;
        std::optional<ClientHelloStream> hello_;
        std::optional<ServerFlight> flight_;
        RecordStream records_;
        crypto::Bytes server_hello_;
        crypto::Bytes first_hello_, retry_hello_;
        std::size_t record_=0, offset_=0;
        bool ccs_seen_=false, encrypted_seen_=false;
        std::uint64_t now_, deadline_;
        ServerHandshakeIo(ServerCredential&& credential, ClientHelloStream&& hello, std::uint64_t now, std::uint64_t deadline) noexcept;
        auto fail(ServerHandshakeIoError error) -> std::unexpected<ServerHandshakeIoError>;
        auto check_time(std::uint64_t now) -> std::expected<void,ServerHandshakeIoError>;
    public:
        ServerHandshakeIo(ServerHandshakeIo const&)=delete;
        auto operator=(ServerHandshakeIo const&) -> ServerHandshakeIo& = delete;
        ServerHandshakeIo(ServerHandshakeIo&&) noexcept;
        auto operator=(ServerHandshakeIo&&) noexcept -> ServerHandshakeIo&;
        [[nodiscard]] static auto create(ServerCredential&& credential, std::uint64_t now, std::uint64_t deadline) -> std::expected<ServerHandshakeIo,ServerHandshakeIoError>;
        [[nodiscard]] auto pending_output() const noexcept -> std::span<std::uint8_t const>;
        [[nodiscard]] auto written(std::size_t count, std::uint64_t now) -> std::expected<void,ServerHandshakeIoError>;
        // Stops at one record boundary. Returns zero while output is pending or after completion.
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input, std::uint64_t now) -> std::expected<ServerHandshakeIoFeed,ServerHandshakeIoError>;
        [[nodiscard]] auto tick(std::uint64_t now) -> std::expected<void,ServerHandshakeIoError>;
        [[nodiscard]] auto cancel() -> std::expected<void,ServerHandshakeIoError>;
        [[nodiscard]] auto finish_input(std::uint64_t now) -> std::expected<void,ServerHandshakeIoError>;
        [[nodiscard]] auto complete() const noexcept -> bool { return state_==State::complete; }
        [[nodiscard]] auto deadline() const noexcept -> std::uint64_t { return deadline_; }
        [[nodiscard]] auto take_application_records() -> std::expected<ApplicationRecords,ServerHandshakeIoError>;
    };
}
