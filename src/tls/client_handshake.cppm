export module nexus.tls.client_handshake;
export import nexus.tls.client_flight;
import nexus.tls.handshake;
import nexus.tls.record_stream;
import std;

export namespace nexus::tls {
    enum class ClientHandshakeError { invalid_state, invalid_configuration, invalid_hello, invalid_record, invalid_message, authentication_failed };
    struct ClientHandshakeFeed {
        std::size_t consumed = 0;
        std::optional<crypto::Bytes> client_finished_record;
    };
    // Starts after ServerHello; caller sends Hello messages and handles plaintext records.
    // Retry entry points validate the complete sequence after the final ServerHello arrives.
    // Feed arbitrary ciphertext stream chunks; after client_finished_record is returned, send it
    // before sending application records. Remaining input belongs to the application epoch.
    // An exception while processing input invalidates the handshake.
    class ClientHandshake {
        enum class State { extensions, certificate, signature, finished, complete, failed } state_=State::extensions;
        ClientFlight flight_;
        RecordStream records_;
        HandshakeDecoder decoder_;
        std::vector<crypto::Bytes> anchors_;
        crypto::Bytes name_;
        PeerNameKind kind_;
        std::int64_t time_;
        std::optional<EncryptedExtensions> negotiated_;
        ClientHandshake(ClientFlight&& flight, HandshakeDecoder&& decoder, std::vector<crypto::Bytes>&& anchors,
            crypto::Bytes&& name, PeerNameKind kind, std::int64_t time) noexcept;
        static auto setup(ClientFlight&& flight, std::span<std::span<std::uint8_t const> const> anchors,
            PeerNameKind kind, std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<ClientHandshake,ClientHandshakeError>;
    public:
        ClientHandshake(ClientHandshake const&)=delete;
        auto operator=(ClientHandshake const&) -> ClientHandshake& = delete;
        ClientHandshake(ClientHandshake&& other) noexcept;
        auto operator=(ClientHandshake&& other) noexcept -> ClientHandshake&;
        [[nodiscard]] static auto create_x25519(std::span<std::uint8_t const> client_hello, std::span<std::uint8_t const> server_hello,
            crypto::X25519Private&& key, std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind,
            std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<ClientHandshake,ClientHandshakeError>;
        [[nodiscard]] static auto create_hybrid(std::span<std::uint8_t const> client_hello, std::span<std::uint8_t const> server_hello,
            HybridClient&& key, std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind,
            std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<ClientHandshake,ClientHandshakeError>;
        [[nodiscard]] static auto create_x25519_retry(std::span<std::uint8_t const> first, std::span<std::uint8_t const> retry,
            std::span<std::uint8_t const> second, std::span<std::uint8_t const> server, crypto::X25519Private&& key,
            std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind,
            std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<ClientHandshake,ClientHandshakeError>;
        [[nodiscard]] static auto create_hybrid_retry(std::span<std::uint8_t const> first, std::span<std::uint8_t const> retry,
            std::span<std::uint8_t const> second, std::span<std::uint8_t const> server, HybridClient&& key,
            std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind,
            std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<ClientHandshake,ClientHandshakeError>;
        [[nodiscard]] auto feed(std::span<std::uint8_t const> bytes) -> std::expected<ClientHandshakeFeed,ClientHandshakeError>;
        [[nodiscard]] auto finish_input() -> std::expected<void,ClientHandshakeError>;
        // Negotiated values are unauthenticated until client_finished_record is returned.
        [[nodiscard]] auto negotiated() const noexcept -> EncryptedExtensions const*;
        [[nodiscard]] auto take_application_records() -> std::expected<ApplicationRecords,ClientHandshakeError>;
    };
}
