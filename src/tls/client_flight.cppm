export module tls.client_flight;
export import tls.client_auth;
export import tls.encrypted_extensions;
export import tls.hybrid_client_keys;
export import tls.raw_client_flight;
export import memory.budget;
import tls.traffic_records;
import tls.post_handshake;
import functional;
import std;

export namespace tls {
    enum class ApplicationEventKind { data, close_notify, user_canceled, fatal_alert, handshake_fragment, ticket_discarded, key_update, key_update_requested, ticket_received };
    struct ApplicationEvent { ApplicationEventKind kind; crypto::Bytes data; std::uint8_t alert_description=0; };
    struct OpenedApplicationData { std::size_t data_size = 0; std::optional<ApplicationEvent> event; };
    enum class ApplicationRole { client, server };
    // Owns one set of application traffic keys. Limits include the TLSInnerPlaintext type and padding.
    class ApplicationRecords {
        // Declared first so it outlives both record keys and traffic secrets.
        std::optional<memory::Budget::Reservation> key_reservation_;
        RecordLayer write_, read_;
        std::size_t write_limit_, read_limit_;
        ApplicationRole role_;
        bool active_=true, read_closed_=false, write_closed_=false, update_response_=false, overflow_alert_pending_=false;
        std::optional<Secret> write_secret_, read_secret_;
        crypto::Hash hash_=crypto::Hash::sha256;
        crypto::Aead algorithm_=crypto::Aead::aes_128_gcm;
        std::size_t key_size_=0;
        crypto::Bytes handshake_pending_;
        using TicketSink=functional::move_only_function<std::expected<void,RecordError>(std::span<std::uint8_t const>)>;
        TicketSink ticket_sink_;

        std::array<std::uint8_t,5> server_handshake_pending_{};
        std::size_t server_handshake_size_=0;
        [[nodiscard]] auto rotate(bool sending) -> bool;
    public:
        auto retain_ticket_sink(TicketSink sink) noexcept -> void {ticket_sink_=std::move(sink);}
        static constexpr std::size_t key_charge=2*(48+32);
        [[nodiscard]] auto retain_key_reservation(memory::Budget::Reservation&& reservation) noexcept -> bool {
            if (key_reservation_ || reservation.size()<key_charge) return false;
            key_reservation_=std::move(reservation); return true;
        }
        [[nodiscard]] auto role() const noexcept -> ApplicationRole { return role_; }
        [[nodiscard]] auto tls12() const noexcept -> bool { return read_.tls12(); }
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
        [[nodiscard]] auto sealed_record_size(std::size_t payload_size) const noexcept -> std::size_t {
            return payload_size + (write_.tls12() ? write_.tls12_overhead() : 22u);
        }
        [[nodiscard]] auto read_overhead() const noexcept -> std::size_t {
            return read_.tls12() ? read_.tls12_overhead() : 21u;
        }
        ApplicationRecords(RecordLayer&& write, RecordLayer&& read, std::size_t write_limit, std::size_t read_limit, ApplicationRole role) noexcept;
        ApplicationRecords(RecordLayer&& write, RecordLayer&& read, std::size_t write_limit, std::size_t read_limit,
            crypto::Hash hash, crypto::Aead algorithm, std::size_t key_size, Secret&& write_secret, Secret&& read_secret, ApplicationRole role) noexcept;
        ApplicationRecords(ApplicationRecords const&)=delete;
        auto operator=(ApplicationRecords const&) -> ApplicationRecords& = delete;
        ApplicationRecords(ApplicationRecords&& other) noexcept;
        auto operator=(ApplicationRecords&& other) noexcept -> ApplicationRecords&;
        ~ApplicationRecords() noexcept;
        [[nodiscard]] auto seal(std::span<std::uint8_t const> data) -> std::expected<crypto::Bytes,RecordError>;
        [[nodiscard]] auto seal_into(std::span<std::uint8_t const> data, std::span<std::uint8_t> out) -> std::expected<std::size_t,RecordError>;
        // Only after a size violation; the caller must first complete any
        // already encoded output on the transport, then write this record.
        [[nodiscard]] auto take_overflow_alert() -> std::expected<crypto::Bytes,RecordError>;
        // A validated oversized ciphertext header can fail before record assembly.
        auto signal_overflow() noexcept -> bool {
            if (!active_ || read_closed_) return false;
            active_=false;overflow_alert_pending_=true;return true;
        }
    private:
        [[nodiscard]] auto check_open_bounds(std::span<std::uint8_t const> record) noexcept -> std::expected<void,RecordError> {
            if (!active_ || read_closed_) return std::unexpected(RecordError::invalid_state);
            auto overhead=read_.tls12() ? read_.tls12_overhead() : 21;
            if (record.size()<overhead+(read_.tls12() ? 0 : 1)) { active_=false; return std::unexpected(RecordError::invalid_record); }
            if (record.size()-overhead>read_limit_) { (void)signal_overflow(); return std::unexpected(RecordError::record_overflow); }
            return {};
        }
        template<class... Recovery>
        inline auto process_non_data_record(ContentType content_type, std::span<std::uint8_t const> content, Recovery&... recovery)
            -> std::expected<ApplicationEvent,RecordError> {
            using Sink=RecoveryPolicy<Recovery...>;
            if (content_type==ContentType::handshake) {
                // A server only accepts a single five-byte KeyUpdate. Keep its
                // fragments inline so they cannot retain an uncharged allocation.
                if (role_==ApplicationRole::server) {
                    if (!read_secret_ || content.empty() || content.size()>server_handshake_pending_.size()-server_handshake_size_) { active_=false; return std::unexpected(RecordError::invalid_record); }
                    std::ranges::copy(content,server_handshake_pending_.begin()+static_cast<std::ptrdiff_t>(server_handshake_size_));
                    server_handshake_size_+=content.size();
                    if (server_handshake_size_>=4 && (server_handshake_pending_[0]!=24 || server_handshake_pending_[1]!=0 || server_handshake_pending_[2]!=0 || server_handshake_pending_[3]!=1)) { active_=false; return std::unexpected(RecordError::invalid_record); }
                    if (server_handshake_size_<5) return ApplicationEvent{ApplicationEventKind::handshake_fragment,{},0};
                    auto request=server_handshake_pending_[4];
                    if (request>1 || !rotate(false)) { active_=false; return std::unexpected(RecordError::invalid_record); }
                    server_handshake_size_=0;
                    if (request==1) update_response_=true;
                    return ApplicationEvent{request ? ApplicationEventKind::key_update_requested : ApplicationEventKind::key_update,{},0};
                }
                constexpr std::size_t max_ticket=max_new_session_ticket;
                constexpr std::size_t max_pending=4+max_ticket+16384-1;
                if (!read_secret_ || content.empty() || content.size()>max_pending-handshake_pending_.size()) { active_=false; return std::unexpected(RecordError::invalid_record); }
                handshake_pending_.insert(handshake_pending_.end(),content.begin(),content.end());
                std::size_t offset=0;
                while (handshake_pending_.size()-offset>=4) {
                    auto type=handshake_pending_[offset];
                    auto size=(std::size_t{handshake_pending_[offset+1]}<<16)|(std::size_t{handshake_pending_[offset+2]}<<8)|handshake_pending_[offset+3];
                    if ((type!=4 && type!=24) || (type==4 && (role_!=ApplicationRole::client || size>max_ticket)) || (type==24 && size!=1)) { active_=false; return std::unexpected(RecordError::invalid_record); }
                    if (size>handshake_pending_.size()-offset-4) break;
                    auto body=std::span{handshake_pending_}.subspan(offset+4,size);
                    offset+=4+size;
                    if (type==4) {
                        if constexpr(Sink::enabled) {
                            auto delivered=recovery_policy(recovery...).ticket(body);if (!delivered) {active_=false;return std::unexpected(delivered.error());}
                        } else if (ticket_sink_) {
                            auto delivered=ticket_sink_(body);
                            if (!delivered) {active_=false;return std::unexpected(delivered.error());}
                        } else if (!valid_new_session_ticket(body)) { active_=false; return std::unexpected(RecordError::invalid_record); }
                        continue;
                    }
                    auto request=body[0];
                    if (offset!=handshake_pending_.size() || request>1 || !rotate(false)) { active_=false; return std::unexpected(RecordError::invalid_record); }
                    crypto::cleanse(handshake_pending_);
                    crypto::Bytes{}.swap(handshake_pending_);
                    if (request==1) update_response_=true;
                    return ApplicationEvent{request ? ApplicationEventKind::key_update_requested : ApplicationEventKind::key_update,{},0};
                }
                handshake_pending_.erase(handshake_pending_.begin(),handshake_pending_.begin()+static_cast<std::ptrdiff_t>(offset));
                if (handshake_pending_.empty()) { crypto::cleanse(handshake_pending_); crypto::Bytes{}.swap(handshake_pending_); }
                return ApplicationEvent{offset ? ((Sink::enabled || ticket_sink_) ? ApplicationEventKind::ticket_received : ApplicationEventKind::ticket_discarded) : ApplicationEventKind::handshake_fragment,{},0};
            }
            if (content_type!=ContentType::alert || content.size()!=2) {
                active_=false; return std::unexpected(RecordError::invalid_record);
            }
            auto description=content[1];
            if (description==0) { read_closed_=true; return ApplicationEvent{ApplicationEventKind::close_notify,{},0}; }
            if (description==90) return ApplicationEvent{ApplicationEventKind::user_canceled,{},description};
            active_=false; return ApplicationEvent{ApplicationEventKind::fatal_alert,{},description};
        }
    public:
        // Authenticated close_notify closes only the peer's sending direction.
        template<class... Recovery>
        inline auto open_event(std::span<std::uint8_t const> record,Recovery&... recovery) -> std::expected<ApplicationEvent,RecordError>{
            if (auto checked=check_open_bounds(record); !checked) return std::unexpected(checked.error());
            try {
                auto plain=read_.open(record); if (!plain) { active_=false; return std::unexpected(plain.error()); }
                if ((!handshake_pending_.empty() || server_handshake_size_) && plain->type!=ContentType::handshake) { active_=false; return std::unexpected(RecordError::invalid_record); }
                if (plain->type==ContentType::application_data) return ApplicationEvent{ApplicationEventKind::data,std::move(plain->content),0};
                return process_non_data_record(plain->type,plain->content,recovery...);
            } catch (...) { active_=false; throw; }
        }
        [[nodiscard]] auto open_data_into(std::span<std::uint8_t const> record, std::span<std::uint8_t> out)
            -> std::expected<OpenedApplicationData,RecordError> {
            if (auto checked=check_open_bounds(record); !checked) return std::unexpected(checked.error());
            try {
                auto opened=read_.open_into(record,out);
                if (!opened) {
                    if (opened.error()!=RecordError::invalid_input) active_=false;
                    return std::unexpected(opened.error());
                }
                if ((!handshake_pending_.empty() || server_handshake_size_) && opened->type!=ContentType::handshake) {
                    crypto::cleanse(out.first(opened->size));
                    active_=false; return std::unexpected(RecordError::invalid_record);
                }
                if (opened->type==ContentType::application_data) return OpenedApplicationData{opened->size,std::nullopt};
                auto ev=process_non_data_record(opened->type,out.first(opened->size));
                crypto::cleanse(out.first(opened->size));
                if (!ev) return std::unexpected(ev.error());
                return OpenedApplicationData{0,std::move(*ev)};
            } catch (...) { crypto::cleanse(out); active_=false; throw; }
        }
        // Enqueue this returned record before any record generated with the new key.
        [[nodiscard]] auto key_update(bool request_peer_update) -> std::expected<crypto::Bytes,RecordError>;
        [[nodiscard]] auto close_notify() -> std::expected<crypto::Bytes,RecordError>;
        // The enabled server's caller publishes its pending cache entry only
        // after this complete authenticated record has been sent.
        [[nodiscard]] auto session_ticket(std::span<std::uint8_t const> body) -> std::expected<crypto::Bytes,RecordError>;
        // Signals transport EOF; fails if no authenticated close_notify was received.
        [[nodiscard]] auto finish_input() -> std::expected<void,RecordError>;
        [[nodiscard]] auto open(std::span<std::uint8_t const> record) -> std::expected<crypto::Bytes,RecordError>;
        struct KtlsDirectionHandoff {
            KtlsKeyMaterial keys;
            Secret secret;
            crypto::Hash hash = crypto::Hash::sha256;
        };
        [[nodiscard]] auto can_handoff_tx() const noexcept -> bool;
        [[nodiscard]] auto can_handoff_rx() const noexcept -> bool;
        [[nodiscard]] auto ktls_algorithm() const noexcept -> std::optional<crypto::Aead> {
            return active_ && !write_.tls12() ? std::optional{write_.algorithm()} : std::nullopt;
        }
        [[nodiscard]] auto take_ktls_tx() -> std::optional<KtlsDirectionHandoff>;
        [[nodiscard]] auto take_ktls_rx() -> std::optional<KtlsDirectionHandoff>;
    };
    // Caller must reassemble messages only from open_handshake_record output and pass complete messages.
    // This is not a complete TLS connection.
    class ClientFlight {
        RawClientFlight raw_;
        RecordLayer write_,read_;
        std::optional<ApplicationRecords> application_;
        std::size_t read_limit_=16385,write_limit_=16385;
        std::uint8_t handshake_terminal_alert_=0;
        ClientFlight(RawClientFlight&& raw,RecordLayer&& write,RecordLayer&& read) noexcept;

    public:
        static auto from_raw(RawClientFlight&& raw) -> std::expected<ClientFlight,ClientFlightError>;
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
        // Recheck the record containing EncryptedExtensions after negotiation.
        [[nodiscard]] auto handshake_record_within_limit(std::size_t ciphertext_size) noexcept -> bool {
            if (ciphertext_size>=22 && ciphertext_size-21<=read_limit_) return true;
            handshake_terminal_alert_=22; return false;
        }
        auto signal_handshake_overflow() noexcept -> void { handshake_terminal_alert_=22; }
        [[nodiscard]] auto take_handshake_overflow_alert() -> std::expected<crypto::Bytes,ClientFlightError>;

        [[nodiscard]] auto certificate(std::span<std::uint8_t const> message, std::span<std::span<std::uint8_t const> const> anchors,
            PeerNameKind kind, std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<void,ClientFlightError>;
        [[nodiscard]] auto certificate(std::span<std::uint8_t const> message, CertificateVerifier const& verifier) -> std::expected<void,ClientFlightError>;
        [[nodiscard]] auto certificate_verify(std::span<std::uint8_t const> message) -> std::expected<void,ClientFlightError>;
        // Returns a handshake-epoch TLSCiphertext containing the client Finished.
        // Take once after producing Finished; send that record before sending application data.
        [[nodiscard]] auto take_application_records() -> std::expected<ApplicationRecords,ClientFlightError>;
        template<class... Recovery>
        inline auto encrypted_extensions(std::span<std::uint8_t const> message,Recovery&... recovery) -> std::expected<EncryptedExtensions,ClientFlightError>{
        using Policy=RecoveryPolicy<Recovery...>;
        auto parsed=raw_.encrypted_extensions(message,recovery...);
        if (!parsed) {
            if (parsed.error().alert==47) {handshake_terminal_alert_=47;return std::unexpected(ClientFlightError::illegal_parameter);}
            return std::unexpected(parsed.error().kind);
        }
        if (parsed->peer_record_size_limit) {
            write_limit_=*parsed->peer_record_size_limit;
            auto* limit=raw_.client_hello().extension(28);
            if (!limit || limit->data.size()!=2) { raw_.cancel();if constexpr(Policy::enabled)recovery_policy(recovery...).cancel(); return std::unexpected(ClientFlightError::invalid_hello); }
            read_limit_=(std::size_t{limit->data[0]}<<8)|limit->data[1];
            if (read_limit_<64 || read_limit_>16385) { raw_.cancel();if constexpr(Policy::enabled)recovery_policy(recovery...).cancel(); return std::unexpected(ClientFlightError::invalid_hello); }
        }
        return std::move(*parsed);
        }
        template<class... Recovery>
        inline auto server_finished(std::span<std::uint8_t const> message,Recovery&... recovery) -> std::expected<void,ClientFlightError>{
        using Policy=RecoveryPolicy<Recovery...>;
        try {
            auto secrets=raw_.server_finished(message,recovery...); if (!secrets) return std::unexpected(secrets.error().kind);
            auto spec=cipher_spec(secrets->cipher_suite);
            auto records=traffic_records(secrets->cipher_suite,secrets->client.view(),secrets->server.view(),false);
            if (!spec || !records) { raw_.cancel();if constexpr(Policy::enabled)recovery_policy(recovery...).cancel(); return std::unexpected(ClientFlightError::crypto_error); }
            application_.emplace(std::move(records->write),std::move(records->read),write_limit_,read_limit_,secrets->hash,spec->algorithm,spec->key_bytes,
                std::move(secrets->client),std::move(secrets->server),ApplicationRole::client);
            return {};
        } catch (...) { raw_.cancel();if constexpr(Policy::enabled)recovery_policy(recovery...).cancel(); application_.reset(); throw; }
        }
        template<class... Recovery>
        inline auto client_finished(Recovery&... recovery) -> std::expected<crypto::Bytes,ClientFlightError>{
        using Policy=RecoveryPolicy<Recovery...>;
        try {
            auto message=raw_.client_finished(recovery...); if (!message) return std::unexpected(message.error().kind);
            auto record=write_.seal(ContentType::handshake,*message);
            if (!record) { raw_.cancel();if constexpr(Policy::enabled)recovery_policy(recovery...).cancel(); return std::unexpected(ClientFlightError::crypto_error); }
            return std::move(*record);
        } catch (...) { raw_.cancel();if constexpr(Policy::enabled)recovery_policy(recovery...).cancel(); application_.reset(); throw; }
        }
    };
}
