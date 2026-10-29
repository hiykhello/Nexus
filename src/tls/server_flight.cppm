export module nexus.tls.server_flight;
export import nexus.tls.server_keys;
export import nexus.tls.server_credential;
export import nexus.tls.client_flight;
import nexus.tls.handshake;
import std;
export namespace nexus::tls {
    enum class ServerFlightError { invalid_state, invalid_credential, invalid_finished, crypto_error };
    // Leaf and configured chain, no client authentication or retry. The caller owns transport framing.
    class ServerFlight {
        enum class State { awaiting_finished, complete, failed } state_=State::awaiting_finished;
        std::optional<ServerHandshakeKeys> keys_;
        std::optional<ApplicationRecords> application_;
        std::vector<crypto::Bytes> records_;
        std::optional<HandshakeDecoder> decoder_;
        ServerFlight(ServerHandshakeKeys&& keys, ApplicationRecords&& application, std::vector<crypto::Bytes>&& records) noexcept;
    public:
        // Decryption allocates up to the ciphertext payload length before it
        // knows the plaintext size. Decoder output is limited to one message.
        static constexpr std::size_t finished_temporary_charge=16640+48+52+sizeof(HandshakeMessage);
        static constexpr std::size_t finished_decoder_charge=52;
        ServerFlight(ServerFlight const&)=delete;
        auto operator=(ServerFlight const&) -> ServerFlight& = delete;
        ServerFlight(ServerFlight&&) noexcept;
        auto operator=(ServerFlight&&) noexcept -> ServerFlight&;
        // Produces encrypted handshake records after ServerHello; transport must send them in order.
        // A nonempty ALPN must have been validated against the client offer by the caller.
        [[nodiscard]] static auto create(ServerHandshakeKeys&& keys, ServerCredential const& credential,
                                         std::span<std::uint8_t const> selected_alpn = {})
            -> std::expected<ServerFlight,ServerFlightError>;
        [[nodiscard]] auto records() const noexcept -> std::span<crypto::Bytes const> { return records_; }
        // Release only after the complete record has been sent; indices remain stable.
        auto release_record(std::size_t index) noexcept -> void;
        // After every record has been written, release the index allocation too.
        auto release_records() noexcept -> void;
        // One authenticated handshake record; true only after the complete client Finished.
        // An exception while processing input invalidates the flight.
        [[nodiscard]] auto client_finished(std::span<std::uint8_t const> record) -> std::expected<bool,ServerFlightError>;
        [[nodiscard]] auto take_application_records() -> std::expected<ApplicationRecords,ServerFlightError>;
    };
}
