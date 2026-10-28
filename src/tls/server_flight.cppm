export module nexus.tls.server_flight;
export import nexus.tls.server_keys;
export import nexus.tls.server_credential;
export import nexus.tls.client_flight;
import nexus.tls.handshake;
import std;
export namespace nexus::tls {
    enum class ServerFlightError { invalid_state, invalid_credential, invalid_finished, crypto_error };
    // Leaf and configured chain, no client authentication, ALPN or retry. The caller owns transport framing.
    class ServerFlight {
        enum class State { awaiting_finished, complete, failed } state_=State::awaiting_finished;
        ServerHandshakeKeys keys_;
        std::optional<ApplicationRecords> application_;
        std::vector<crypto::Bytes> records_;
        std::optional<HandshakeDecoder> decoder_;
        ServerFlight(ServerHandshakeKeys&& keys, ApplicationRecords&& application, std::vector<crypto::Bytes>&& records) noexcept;
    public:
        ServerFlight(ServerFlight const&)=delete;
        auto operator=(ServerFlight const&) -> ServerFlight& = delete;
        ServerFlight(ServerFlight&&) noexcept;
        auto operator=(ServerFlight&&) noexcept -> ServerFlight&;
        // Produces encrypted handshake records after ServerHello; transport must send them in order.
        [[nodiscard]] static auto create(ServerHandshakeKeys&& keys, ServerCredential const& credential)
            -> std::expected<ServerFlight,ServerFlightError>;
        [[nodiscard]] auto records() const noexcept -> std::span<crypto::Bytes const> { return records_; }
        // One authenticated handshake record; true only after the complete client Finished.
        [[nodiscard]] auto client_finished(std::span<std::uint8_t const> record) -> std::expected<bool,ServerFlightError>;
        [[nodiscard]] auto take_application_records() -> std::expected<ApplicationRecords,ServerFlightError>;
    };
}
