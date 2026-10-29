export module nexus.tls.client_flight;
export import nexus.tls.client_auth;
export import nexus.tls.encrypted_extensions;
export import nexus.tls.hybrid_client_keys;
import std;

export namespace nexus::tls {
    enum class ClientFlightError { invalid_state, invalid_hello, invalid_extensions, invalid_certificate, invalid_signature, invalid_finished, crypto_error };
    enum class ApplicationEventKind { data, close_notify, user_canceled, fatal_alert, handshake_fragment, ticket_discarded, key_update, key_update_requested };
    struct ApplicationEvent { ApplicationEventKind kind; crypto::Bytes data; std::uint8_t alert_description=0; };
    enum class ApplicationRole { client, server };
    // Owns one set of application traffic keys. Limits include the TLSInnerPlaintext type and padding.
    class ApplicationRecords {
        RecordLayer write_, read_;
        std::size_t write_limit_, read_limit_;
        ApplicationRole role_;
        bool active_=true, read_closed_=false, write_closed_=false, update_response_=false;
        std::optional<Secret> write_secret_, read_secret_;
        crypto::Hash hash_=crypto::Hash::sha256;
        crypto::Aead algorithm_=crypto::Aead::aes_128_gcm;
        std::size_t key_size_=0;
        crypto::Bytes handshake_pending_;
        std::array<std::uint8_t,5> server_handshake_pending_{};
        std::size_t server_handshake_size_=0;
        [[nodiscard]] auto rotate(bool sending) -> bool;
    public:
        [[nodiscard]] auto role() const noexcept -> ApplicationRole { return role_; }
        // A new transport adapter cannot inherit a pending control message or
        // a closed direction without also inheriting its external I/O state.
        [[nodiscard]] auto ready_for_transport() const noexcept -> bool {
            return active_ && write_.usable(RecordDirection::send) && read_.usable(RecordDirection::receive) &&
                write_.send_limit()>1 && write_.send_remaining()>0 &&
                (write_.send_remaining()>1 || write_secret_.has_value()) &&
                !read_closed_ && !write_closed_ && !update_response_ && handshake_pending_.empty() && !server_handshake_size_ &&
                write_limit_ >= 64 && write_limit_ <= 16385 && read_limit_ >= 64 && read_limit_ <= 16385;
        }
        // Maximum application bytes in one unpadded record, after peer negotiation.
        [[nodiscard]] auto max_write_size() const noexcept -> std::size_t {
            return active_ && !write_closed_ && write_limit_ > 1 ? std::min(write_limit_ - 1, std::size_t{16384}) : 0;
        }
        ApplicationRecords(RecordLayer&& write, RecordLayer&& read, std::size_t write_limit, std::size_t read_limit, ApplicationRole role) noexcept;
        ApplicationRecords(RecordLayer&& write, RecordLayer&& read, std::size_t write_limit, std::size_t read_limit,
            crypto::Hash hash, crypto::Aead algorithm, std::size_t key_size, Secret&& write_secret, Secret&& read_secret, ApplicationRole role) noexcept;
        ApplicationRecords(ApplicationRecords const&)=delete;
        auto operator=(ApplicationRecords const&) -> ApplicationRecords& = delete;
        ApplicationRecords(ApplicationRecords&& other) noexcept;
        auto operator=(ApplicationRecords&& other) noexcept -> ApplicationRecords&;
        [[nodiscard]] auto seal(std::span<std::uint8_t const> data) -> std::expected<crypto::Bytes,RecordError>;
        // Authenticated close_notify closes only the peer's sending direction.
        [[nodiscard]] auto open_event(std::span<std::uint8_t const> record) -> std::expected<ApplicationEvent,RecordError>;
        // Enqueue this returned record before any record generated with the new key.
        [[nodiscard]] auto key_update(bool request_peer_update) -> std::expected<crypto::Bytes,RecordError>;
        [[nodiscard]] auto close_notify() -> std::expected<crypto::Bytes,RecordError>;
        // Signals transport EOF; fails if no authenticated close_notify was received.
        [[nodiscard]] auto finish_input() -> std::expected<void,RecordError>;
        [[nodiscard]] auto open(std::span<std::uint8_t const> record) -> std::expected<crypto::Bytes,RecordError>;
    };
    // Caller must reassemble messages only from open_handshake_record output and pass complete messages.
    // This is not a complete TLS connection.
    class ClientFlight {
        enum class State { extensions, certificate, signature, finished, client_finished, complete, failed } state_=State::extensions;
        ClientHello hello_;
        std::vector<std::uint16_t> offered_;
        ClientHandshakeKeys keys_;
        std::optional<ClientAuth> auth_;
        std::optional<ApplicationRecords> application_;
        crypto::Aead algorithm_;
        std::size_t key_size_, read_limit_=16385, write_limit_=16385;
        ClientFlight(ClientHello&& hello, std::vector<std::uint16_t>&& offered, ClientHandshakeKeys&& keys, crypto::Aead algorithm, std::size_t key_size) noexcept;
        static auto from_keys(std::span<std::uint8_t const> client_hello, std::span<std::uint8_t const> server_hello, ClientHandshakeKeys&& keys) -> std::expected<ClientFlight,ClientFlightError>;
    public:
        ClientFlight(ClientFlight const&)=delete;
        auto operator=(ClientFlight const&) -> ClientFlight& = delete;
        ClientFlight(ClientFlight&& other) noexcept;
        auto operator=(ClientFlight&& other) noexcept -> ClientFlight&;
        [[nodiscard]] static auto create_x25519(std::span<std::uint8_t const> client_hello, std::span<std::uint8_t const> server_hello,
            crypto::X25519Private&& key) -> std::expected<ClientFlight,ClientFlightError>;
        [[nodiscard]] static auto create_hybrid(std::span<std::uint8_t const> client_hello, std::span<std::uint8_t const> server_hello,
            HybridClient&& key) -> std::expected<ClientFlight,ClientFlightError>;
        [[nodiscard]] static auto create_x25519_retry(std::span<std::uint8_t const> first, std::span<std::uint8_t const> retry,
            std::span<std::uint8_t const> second, std::span<std::uint8_t const> server, crypto::X25519Private&& key) -> std::expected<ClientFlight,ClientFlightError>;
        [[nodiscard]] static auto create_hybrid_retry(std::span<std::uint8_t const> first, std::span<std::uint8_t const> retry,
            std::span<std::uint8_t const> second, std::span<std::uint8_t const> server, HybridClient&& key) -> std::expected<ClientFlight,ClientFlightError>;
        [[nodiscard]] auto open_handshake_record(std::span<std::uint8_t const> record) -> std::expected<crypto::Bytes,ClientFlightError>;
        [[nodiscard]] auto encrypted_extensions(std::span<std::uint8_t const> message) -> std::expected<EncryptedExtensions,ClientFlightError>;
        [[nodiscard]] auto certificate(std::span<std::uint8_t const> message, std::span<std::span<std::uint8_t const> const> anchors,
            PeerNameKind kind, std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<void,ClientFlightError>;
        [[nodiscard]] auto certificate_verify(std::span<std::uint8_t const> message) -> std::expected<void,ClientFlightError>;
        [[nodiscard]] auto server_finished(std::span<std::uint8_t const> message) -> std::expected<void,ClientFlightError>;
        // Returns a handshake-epoch TLSCiphertext containing the client Finished.
        [[nodiscard]] auto client_finished() -> std::expected<crypto::Bytes,ClientFlightError>;
        // Take once after producing Finished; send that record before sending application data.
        [[nodiscard]] auto take_application_records() -> std::expected<ApplicationRecords,ClientFlightError>;
    };
}
