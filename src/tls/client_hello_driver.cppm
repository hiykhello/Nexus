export module nexus.tls.client_hello_driver;
export import nexus.tls.client_handshake;
export import nexus.tls.server_hello_stream;
import std;
export namespace nexus::tls {
    enum class ClientHelloDriverError { invalid_state, invalid_hello, invalid_record, invalid_retry, crypto_error };
    struct ClientHelloDriverFeed { std::size_t consumed=0; std::optional<crypto::Bytes> outbound; bool server_hello=false; };
    // Owns ephemeral keys and exact Hello bytes. The template must have a key_share extension.
    class ClientHelloDriver {
        enum class State { initial, first, sending_retry, final, ready, complete, failed } state_=State::initial;
        ClientHello first_, current_;
        crypto::Bytes first_wire_, current_wire_, retry_wire_, server_wire_;
        std::optional<crypto::X25519Private> x_;
        std::optional<HybridClient> hybrid_;
        ServerHelloStream stream_;
        ClientHelloDriver(ClientHello&& hello, crypto::Bytes&& wire, ServerHelloStream&& stream);
        auto make_share(std::uint16_t group) -> std::expected<KeyShareEntry,ClientHelloDriverError>;
    public:
        ClientHelloDriver(ClientHelloDriver const&)=delete;
        auto operator=(ClientHelloDriver const&) -> ClientHelloDriver& = delete;
        ClientHelloDriver(ClientHelloDriver&&) noexcept;
        auto operator=(ClientHelloDriver&&) noexcept -> ClientHelloDriver&;
        // initial_group is 0 for an empty key_share; otherwise 0x001d or 0x11ec.
        [[nodiscard]] static auto create(ClientHello hello, std::uint16_t initial_group) -> std::expected<ClientHelloDriver,ClientHelloDriverError>;
        [[nodiscard]] auto initial_record() const -> std::expected<crypto::Bytes,ClientHelloDriverError>;
        [[nodiscard]] auto initial_sent() -> std::expected<void,ClientHelloDriverError>;
        // Send outbound fully before calling retry_sent; input after consumed remains with caller.
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input) -> std::expected<ClientHelloDriverFeed,ClientHelloDriverError>;
        [[nodiscard]] auto retry_sent() -> std::expected<void,ClientHelloDriverError>;
        [[nodiscard]] auto take_handshake(std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind,
            std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<ClientHandshake,ClientHelloDriverError>;
    };
}
