export module nexus.tls.server_handshake_io;
export import nexus.tls.server_flight;
export import nexus.memory.budget;
import nexus.tls.client_hello_stream;
import nexus.tls.record_stream;
import std;
export namespace nexus::tls {
    enum class ServerHandshakeIoError { invalid_state, invalid_argument, time_reversed, timeout, canceled, protocol_error, certificate_limit, budget_exceeded };
    struct ServerHandshakeIoFeed { std::size_t consumed=0; };
    // Single owner; monotonic milliseconds, absolute deadline. No socket operations.
    class ServerHandshakeIo {
        enum class State { hello, retry_output, retry_hello, output, finished, complete, failed } state_=State::hello;
        std::shared_ptr<memory::Budget> budget_;
        std::optional<memory::Budget::Reservation> hello_reservation_, flight_reservation_, hello_input_reservation_, finished_input_reservation_;
        std::optional<memory::Budget::Reservation> encoded_hello_reservation_, first_hello_reservation_, retry_hello_reservation_;
        std::optional<ServerCredential> credential_;
        std::optional<ClientHelloStream> hello_;
        std::optional<ServerFlight> flight_;
        RecordStream records_;
        crypto::Bytes server_hello_;
        crypto::Bytes first_hello_, retry_hello_, required_alpn_;
        std::size_t record_=0, offset_=0;
        bool ccs_seen_=false, encrypted_seen_=false;
        std::uint64_t now_, deadline_;
        ServerHandshakeIo(ServerCredential&& credential, ClientHelloStream&& hello, std::uint64_t now, std::uint64_t deadline) noexcept;
        auto fail(ServerHandshakeIoError error) -> std::unexpected<ServerHandshakeIoError>;
        auto check_time(std::uint64_t now) -> std::expected<void,ServerHandshakeIoError>;
    public:
        // The record, decoder's pending message and decoded body can coexist.
        static constexpr std::size_t hello_reassembly_charge=16389+65539+65535;
        static constexpr std::size_t hello_encoded_charge=65539;
        static constexpr std::size_t hello_input_charge=hello_reassembly_charge+hello_encoded_charge;
        static constexpr std::size_t generated_hello_charge=16384;
        static constexpr std::size_t finished_input_charge=16645;
        ServerHandshakeIo(ServerHandshakeIo const&)=delete;
        auto operator=(ServerHandshakeIo const&) -> ServerHandshakeIo& = delete;
        ServerHandshakeIo(ServerHandshakeIo&&) noexcept;
        auto operator=(ServerHandshakeIo&&) noexcept -> ServerHandshakeIo&;
        // Empty ALPN disables negotiation; otherwise this single protocol is required.
        // The certificate list limit counts each DER certificate plus its five-byte
        // TLS entry framing; the credential remains caller-owned on rejection.
        [[nodiscard]] static auto create(ServerCredential&& credential, std::uint64_t now, std::uint64_t deadline,
                                         std::string_view required_alpn = {},
                                         std::size_t certificate_list_limit = ServerCredential::max_certificate_list_size,
                                         std::shared_ptr<memory::Budget> budget = {})
            -> std::expected<ServerHandshakeIo,ServerHandshakeIoError>;
        [[nodiscard]] auto pending_output() const noexcept -> std::span<std::uint8_t const>;
        // Exceptions while advancing input or output invalidate the adapter.
        [[nodiscard]] auto written(std::size_t count, std::uint64_t now) -> std::expected<void,ServerHandshakeIoError>;
        // Stops at one record boundary. Returns zero while output is pending or after completion.
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input, std::uint64_t now) -> std::expected<ServerHandshakeIoFeed,ServerHandshakeIoError>;
        [[nodiscard]] auto tick(std::uint64_t now) -> std::expected<void,ServerHandshakeIoError>;
        [[nodiscard]] auto cancel() -> std::expected<void,ServerHandshakeIoError>;
        [[nodiscard]] auto finish_input(std::uint64_t now) -> std::expected<void,ServerHandshakeIoError>;
        [[nodiscard]] auto complete() const noexcept -> bool { return state_==State::complete; }
        // The selected protocol is available only after authenticated handshake completion.
        [[nodiscard]] auto negotiated_alpn() const noexcept -> std::span<std::uint8_t const> {
            return complete() ? std::span<std::uint8_t const>{required_alpn_} : std::span<std::uint8_t const>{};
        }
        [[nodiscard]] auto deadline() const noexcept -> std::uint64_t { return deadline_; }
        [[nodiscard]] auto budget() const noexcept -> std::shared_ptr<memory::Budget> { return budget_; }
        [[nodiscard]] auto take_application_records() -> std::expected<ApplicationRecords,ServerHandshakeIoError>;
    };
}
