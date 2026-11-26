export module tls.client_handshake_io;
export import tls.client_session_handshake;
import tls.tls12_client;
import tls.psk_client_policy;
import tls.record_stream;
import std;
export namespace tls {
    enum class ClientHandshakeIoError { invalid_state, invalid_argument, time_reversed, timeout, canceled, protocol_error, authentication_failed, crypto_error };
    struct ClientHandshakeIoFeed { std::size_t consumed=0; };
    // Single-owner nonblocking adapter. Time is monotonic milliseconds; deadline is absolute.
    class ClientHandshakeIo {
        enum class State { active, complete, failed } state_=State::active;
        std::optional<ClientSessionHandshake> handshake_;
        std::unique_ptr<Tls12Client> legacy_;
        std::unique_ptr<PskClientPolicy<>> recovery_;
        struct VersionProbe {
            RecordStream records;
            crypto::Bytes prefix,body;
        };
        std::unique_ptr<VersionProbe> probe_;
        auto feed_selected(std::span<std::uint8_t const>) -> std::expected<ClientHandshakeIoFeed,ClientHandshakeIoError>;
        auto feed_probe(std::span<std::uint8_t const>) -> std::expected<ClientHandshakeIoFeed,ClientHandshakeIoError>;

        crypto::Bytes output_;
        std::size_t offset_=0;
        bool finished_output_=false, overflow_output_=false;
        std::uint64_t now_, deadline_;
        ClientHandshakeIo(ClientSessionHandshake&& handshake, crypto::Bytes&& output, std::uint64_t now, std::uint64_t deadline) noexcept;
        ClientHandshakeIo(std::unique_ptr<Tls12Client>,crypto::Bytes&&,std::uint64_t,std::uint64_t) noexcept;
        auto check_time(std::uint64_t now) -> std::expected<void,ClientHandshakeIoError>;
        auto fail(ClientHandshakeIoError error) -> std::unexpected<ClientHandshakeIoError>;
    public:
        ClientHandshakeIo(ClientHandshakeIo const&)=delete;
        auto operator=(ClientHandshakeIo const&) -> ClientHandshakeIo& = delete;
        ClientHandshakeIo(ClientHandshakeIo&&) noexcept;
        auto operator=(ClientHandshakeIo&&) noexcept -> ClientHandshakeIo&;
        [[nodiscard]] static auto create(ClientSessionHandshake&& handshake, std::uint64_t now, std::uint64_t deadline) -> std::expected<ClientHandshakeIo,ClientHandshakeIoError>;
        [[nodiscard]] static auto create(Tls12Client&& handshake,std::uint64_t now,std::uint64_t deadline)
            -> std::expected<ClientHandshakeIo,ClientHandshakeIoError>;
        [[nodiscard]] static auto create(ClientHello hello,std::span<std::uint16_t const> groups,
            std::span<crypto::Bytes const> anchors,PeerNameKind kind,std::span<std::uint8_t const> peer_name,
            std::int64_t verification_time,std::uint64_t now,std::uint64_t deadline,std::span<std::uint8_t const> target={},std::span<std::array<std::uint8_t,32> const> pins={},quic::EchConfig const* ech=nullptr)
            -> std::expected<ClientHandshakeIo,ClientHandshakeIoError>;
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
