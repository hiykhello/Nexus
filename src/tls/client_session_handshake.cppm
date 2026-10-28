export module nexus.tls.client_session_handshake;
export import nexus.tls.client_hello_driver;
import std;
export namespace nexus::tls {
    enum class ClientSessionHandshakeError { invalid_state, invalid_configuration, protocol_error, authentication_failed };
    enum class ClientHelloConfigError { invalid_server_name, invalid_alpn, invalid_group, random_error };
    // SNI is optional and independent of certificate identity; ALPN is a list of opaque protocol IDs.
    // Only X25519 and X25519MLKEM768 groups and implemented TLS 1.3 algorithms are offered.
    [[nodiscard]] auto make_client_hello(std::optional<std::string_view> server_name,
        std::span<std::string_view const> alpn, std::span<std::uint16_t const> groups)
        -> std::expected<ClientHello,ClientHelloConfigError>;
    struct ClientTlsConfig {
        ClientHello hello;
        std::vector<crypto::Bytes> trust_anchors;
        crypto::Bytes peer_name;
        PeerNameKind peer_name_kind=PeerNameKind::dns;
        std::int64_t verification_time=0;
        std::uint16_t initial_group=0;
    };
    struct ClientSessionHandshakeFeed { std::size_t consumed=0; std::optional<crypto::Bytes> outbound; };
    // Socket-free handshake. The caller writes each outbound record in full and acknowledges it.
    class ClientSessionHandshake {
        enum class State { initial, hello, retry_write, encrypted, finished_write, complete, failed } state_=State::initial;
        ClientHelloDriver hello_;
        std::optional<ClientHandshake> handshake_;
        std::vector<crypto::Bytes> anchors_;
        crypto::Bytes name_;
        PeerNameKind kind_;
        std::int64_t time_;
        ClientSessionHandshake(ClientHelloDriver&& hello, std::vector<crypto::Bytes>&& anchors, crypto::Bytes&& name, PeerNameKind kind, std::int64_t time) noexcept;
    public:
        ClientSessionHandshake(ClientSessionHandshake const&)=delete;
        auto operator=(ClientSessionHandshake const&) -> ClientSessionHandshake& = delete;
        ClientSessionHandshake(ClientSessionHandshake&&) noexcept;
        auto operator=(ClientSessionHandshake&&) noexcept -> ClientSessionHandshake&;
        [[nodiscard]] static auto create(ClientHello hello, std::uint16_t initial_group,
            std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind,
            std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<ClientSessionHandshake,ClientSessionHandshakeError>;
        [[nodiscard]] static auto create(ClientTlsConfig config) -> std::expected<ClientSessionHandshake,ClientSessionHandshakeError>;
        [[nodiscard]] auto initial_record() const -> std::expected<crypto::Bytes,ClientSessionHandshakeError>;
        [[nodiscard]] auto sent() -> std::expected<void,ClientSessionHandshakeError>;
        // Returns at one record boundary or epoch transition. Resubmit the unconsumed suffix.
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input) -> std::expected<ClientSessionHandshakeFeed,ClientSessionHandshakeError>;
        [[nodiscard]] auto finish_input() -> std::expected<void,ClientSessionHandshakeError>;
        [[nodiscard]] auto negotiated() const noexcept -> EncryptedExtensions const*;
        [[nodiscard]] auto take_application_records() -> std::expected<ApplicationRecords,ClientSessionHandshakeError>;
    };
}
