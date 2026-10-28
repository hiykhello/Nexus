export module nexus.tls.client_handshake_io;
export import nexus.tls.client_session_handshake;
import std;
export namespace nexus::tls {
    enum class ClientHandshakeIoError { invalid_state, invalid_argument, time_reversed, timeout, canceled, protocol_error, authentication_failed };
    struct ClientHandshakeIoFeed { std::size_t consumed=0; };
    // Single-owner nonblocking adapter. Time is monotonic milliseconds; deadline is absolute.
    class ClientHandshakeIo {
        enum class State { active, complete, failed } state_=State::active;
        std::optional<ClientSessionHandshake> handshake_;
        crypto::Bytes output_;
        std::size_t offset_=0;
        bool finished_output_=false;
        std::uint64_t now_, deadline_;
        ClientHandshakeIo(ClientSessionHandshake&& handshake, crypto::Bytes&& output, std::uint64_t now, std::uint64_t deadline) noexcept;
        auto check_time(std::uint64_t now) -> std::expected<void,ClientHandshakeIoError>;
        auto fail(ClientHandshakeIoError error) -> std::unexpected<ClientHandshakeIoError>;
    public:
        ClientHandshakeIo(ClientHandshakeIo const&)=delete;
        auto operator=(ClientHandshakeIo const&) -> ClientHandshakeIo& = delete;
        ClientHandshakeIo(ClientHandshakeIo&&) noexcept;
        auto operator=(ClientHandshakeIo&&) noexcept -> ClientHandshakeIo&;
        [[nodiscard]] static auto create(ClientSessionHandshake&& handshake, std::uint64_t now, std::uint64_t deadline) -> std::expected<ClientHandshakeIo,ClientHandshakeIoError>;
        // Borrowed until the next non-const operation. Writes may complete in arbitrary pieces.
        [[nodiscard]] auto pending_output() const noexcept -> std::span<std::uint8_t const>;
        [[nodiscard]] auto written(std::size_t count, std::uint64_t now) -> std::expected<void,ClientHandshakeIoError>;
        // Returns zero consumption while output is pending or after the handshake completes.
        // An exception while processing input invalidates the adapter and clears pending output.
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input, std::uint64_t now) -> std::expected<ClientHandshakeIoFeed,ClientHandshakeIoError>;
        [[nodiscard]] auto tick(std::uint64_t now) -> std::expected<void,ClientHandshakeIoError>;
        [[nodiscard]] auto cancel() -> std::expected<void,ClientHandshakeIoError>;
        [[nodiscard]] auto finish_input(std::uint64_t now) -> std::expected<void,ClientHandshakeIoError>;
        [[nodiscard]] auto complete() const noexcept -> bool { return state_==State::complete; }
        [[nodiscard]] auto deadline() const noexcept -> std::uint64_t { return deadline_; }
        [[nodiscard]] auto negotiated() const noexcept -> EncryptedExtensions const*;
        [[nodiscard]] auto take_application_records() -> std::expected<ApplicationRecords,ClientHandshakeIoError>;
    };
}
