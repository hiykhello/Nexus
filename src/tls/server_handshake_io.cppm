export module tls.server_handshake_io;
export import tls.server_flight;
export import memory.budget;
import tls.client_hello_stream;
import tls.record_stream;
import std;
export namespace tls {
    enum class ServerHandshakeIoError { invalid_state, invalid_argument, time_reversed, timeout, canceled, protocol_error, certificate_limit, budget_exceeded, crypto_error };
    struct ServerHandshakeIoFeed { std::size_t consumed=0; };
    // Single owner; monotonic milliseconds, absolute deadline. No socket operations.
    class ServerHandshakeIo {
        enum class State { hello, retry_output, retry_hello, output, finished, complete, failed } state_=State::hello;
        std::shared_ptr<memory::Budget> budget_;
        std::optional<memory::Budget::Reservation> hello_reservation_, flight_reservation_, hello_input_reservation_, finished_input_reservation_;
        std::optional<memory::Budget::Reservation> encoded_hello_reservation_, first_hello_reservation_, retry_hello_reservation_;
        std::optional<memory::Budget::Reservation> finished_decoder_reservation_, finished_keys_reservation_;
        std::optional<memory::Budget::Reservation> credential_reservation_;
        std::optional<ServerCredential> credential_;
        std::optional<ClientHelloStream> hello_;
        std::optional<ServerFlight> flight_;
        RecordStream records_;
        crypto::Bytes server_hello_;
        crypto::Bytes first_hello_, retry_hello_, required_alpn_;
        std::vector<crypto::Bytes> alpn_preferences_;
        bool allow_no_alpn_=false;
        std::size_t record_=0, offset_=0;
        bool ccs_seen_=false, encrypted_seen_=false;
        PeerSignaturePolicy signature_policy_=PeerSignaturePolicy::require_offered;
        std::uint64_t now_, deadline_;
        ServerHandshakeIo(ServerCredential&& credential, ClientHelloStream&& hello, std::uint64_t now, std::uint64_t deadline) noexcept;
        auto fail(ServerHandshakeIoError error) -> std::unexpected<ServerHandshakeIoError>;
        auto check_time(std::uint64_t now) -> std::expected<void,ServerHandshakeIoError>;
    public:
        // Include old header and initial decoder allocations during growth.
        // Vector implementation capacity and allocator overhead remain excluded.
        static constexpr std::size_t hello_reassembly_charge=16389+5+65539+4096+65535;
        static constexpr std::size_t hello_encoded_charge=65539;
        static constexpr std::size_t hello_input_charge=hello_reassembly_charge+hello_encoded_charge;
        static constexpr std::size_t generated_hello_charge=16384;
        // Generated hello fields, body and retry comparison message; logical
        // lengths only, excluding container capacities and other temporaries.
        static constexpr std::size_t generated_hello_scratch_charge=3*16384;
        // Finished verification retains at most a SHA-384 traffic secret and
        // a 256-bit record key. Crypto internals and container capacity are excluded.
        static constexpr std::size_t finished_keys_charge=48+32;
        // Handshake key derivation's digest, early/handshake/traffic secrets,
        // key/IV copies and HKDF temporaries; excludes crypto internals.
        static constexpr std::size_t handshake_key_scratch_charge=512;
        // After derivation, master handshake secret, server traffic secret and
        // write key persist until the encrypted flight has been constructed.
        static constexpr std::size_t handshake_key_retained_charge=48+48+32;
        // Sealing a full fragment holds TLSInnerPlaintext and the encrypted
        // payload simultaneously; the completed record is charged separately.
        static constexpr std::size_t flight_seal_scratch_charge=16385+16401;
        // Conservatively cover hash/verify/master (3*48), four key/IV
        // temporaries (2*(32+12)), and master derivation's zeros, digest,
        // derived secret and largest HKDF label (3*48+64). Logical lengths.
        static constexpr std::size_t flight_key_scratch_charge=512;
        static constexpr std::size_t finished_input_charge=16645+5+ServerFlight::finished_temporary_charge;
        ServerHandshakeIo(ServerHandshakeIo const&)=delete;
        auto operator=(ServerHandshakeIo const&) -> ServerHandshakeIo& = delete;
        ServerHandshakeIo(ServerHandshakeIo&&) noexcept;
        auto operator=(ServerHandshakeIo&&) noexcept -> ServerHandshakeIo&;
        // Empty ALPN disables negotiation; otherwise this single protocol is required.
        // The certificate list limit counts each DER certificate plus its five-byte
        // TLS entry framing; the credential and its optional pre-allocation
        // reservation remain caller-owned on rejection. On success the adapter
        // retains the reservation until after the credential is destroyed.
        [[nodiscard]] static auto create(ServerCredential&& credential, std::uint64_t now, std::uint64_t deadline,
                                         std::string_view required_alpn = {},
                                         std::size_t certificate_list_limit = ServerCredential::max_certificate_list_size,
                                         std::shared_ptr<memory::Budget> budget = {},
                                         std::optional<memory::Budget::Reservation>&& credential_reservation = {})
            -> std::expected<ServerHandshakeIo,ServerHandshakeIoError>;
        [[nodiscard]] static auto create_alpn(ServerCredential&& credential, std::uint64_t now, std::uint64_t deadline,
                                              std::span<std::string_view const> alpn_preferences, bool allow_no_alpn = true,
                                              std::size_t certificate_list_limit = ServerCredential::max_certificate_list_size,
                                              std::shared_ptr<memory::Budget> budget = {},
                                              std::optional<memory::Budget::Reservation>&& credential_reservation = {})
            -> std::expected<ServerHandshakeIo,ServerHandshakeIoError>;
        // Only after the caller authenticates this ClientHello's identity;
        // ordinary TLS requires an advertised signature scheme.
        [[nodiscard]] auto enable_authenticated_ed25519() noexcept -> bool {
            if (state_!=State::hello || !credential_ || credential_->scheme()!=0x0807) return false;
            signature_policy_=PeerSignaturePolicy::authenticated_ed25519; return true;
        }
        [[nodiscard]] auto pending_output() const noexcept -> std::span<std::uint8_t const>;
        // Exceptions while advancing input or output invalidate the adapter.
        [[nodiscard]] auto written(std::size_t count, std::uint64_t now) -> std::expected<void,ServerHandshakeIoError>;
        // Stops at one record boundary. Returns zero while output is pending or after completion.
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
        template<class... Recovery>
        inline auto feed(std::span<std::uint8_t const> input,std::uint64_t now,Recovery&... recovery) -> std::expected<ServerHandshakeIoFeed,ServerHandshakeIoError>{
        using Policy=RecoveryPolicy<Recovery...>;
        auto time=check_time(now); if (!time) return std::unexpected(time.error());
        if (state_==State::output || state_==State::retry_output || state_==State::complete) return ServerHandshakeIoFeed{};
        try {
        if (state_==State::hello || state_==State::retry_hello) {
            // Keep the key-parser reservation alive longer than result and its
            // parsed ClientHello, including error and exception unwinding.
            std::optional<memory::Budget::Reservation> key_parse_reservation;
            std::optional<memory::Budget::Reservation> generated_hello_reservation;
            std::optional<memory::Budget::Reservation> generated_hello_scratch;
            std::optional<memory::Budget::Reservation> encoded_local;
            std::optional<memory::Budget::Reservation> finished_keys_local;
            std::optional<memory::Budget::Reservation> handshake_keys_local;
            auto result=hello_->feed(input,budget_);
            if (!result) return fail(result.error()==ClientHelloStreamError::budget_exceeded ? ServerHandshakeIoError::budget_exceeded : ServerHandshakeIoError::protocol_error);
            if (result->compatibility_ccs) ccs_seen_=true;
            auto consumed=result->consumed; if (!result->hello) return ServerHandshakeIoFeed{consumed};
            encoded_local=std::move(encoded_hello_reservation_);
            if (state_==State::hello && !alpn_preferences_.empty()) {
                required_alpn_.clear();
                if (auto ext=result->hello->extension(16)) {
                    if (ext->data.size()<3 || ((std::size_t{ext->data[0]}<<8)|ext->data[1])!=ext->data.size()-2)
                        return fail(ServerHandshakeIoError::protocol_error);
                    std::array<std::span<std::uint8_t const>,64> offered{};
                    std::size_t offered_count=0;
                    for (std::size_t i=2;i<ext->data.size();) {
                        auto n=ext->data[i++];
                        if (!n || n>ext->data.size()-i || offered_count==offered.size())
                            return fail(ServerHandshakeIoError::protocol_error);
                        offered[offered_count++]=std::span{ext->data}.subspan(i,n);
                        i+=n;
                    }
                    for (auto const& pref : alpn_preferences_) {
                        for (std::size_t k=0;k<offered_count;++k) {
                            if (std::ranges::equal(offered[k],pref)) { required_alpn_=pref; break; }
                        }
                        if (!required_alpn_.empty()) break;
                    }
                }
                if (required_alpn_.empty() && !allow_no_alpn_)
                    return fail(ServerHandshakeIoError::protocol_error);
            } else if (!required_alpn_.empty()) {
                auto ext=result->hello->extension(16);
                if (!ext || ext->data.size()<3 || ((std::size_t{ext->data[0]}<<8)|ext->data[1])!=ext->data.size()-2)
                    return fail(ServerHandshakeIoError::protocol_error);
                bool matched=false;
                for (std::size_t i=2;i<ext->data.size();) {
                    auto n=ext->data[i++];
                    if (!n || n>ext->data.size()-i) return fail(ServerHandshakeIoError::protocol_error);
                    if (std::ranges::equal(std::span{ext->data}.subspan(i,n),required_alpn_)) matched=true;
                    i+=n;
                }
                if (!matched) return fail(ServerHandshakeIoError::protocol_error);
            }
            auto schemes=credential_->signature_schemes();
            if (budget_) {
                auto charge=ClientHelloStream::parsed_charge(result->message.size()-4);
                if (state_==State::retry_hello) charge+=ClientHelloStream::parsed_charge(first_hello_.size()-4);
                key_parse_reservation=memory::Budget::reserve(budget_,charge);
                if (!key_parse_reservation) return fail(ServerHandshakeIoError::budget_exceeded);
                generated_hello_reservation=memory::Budget::reserve(budget_,generated_hello_charge);
                if (!generated_hello_reservation) return fail(ServerHandshakeIoError::budget_exceeded);
                generated_hello_scratch=memory::Budget::reserve(budget_,generated_hello_scratch_charge);
                if (!generated_hello_scratch) return fail(ServerHandshakeIoError::budget_exceeded);
                // Admit the retained Finished keys before key derivation creates
                // them, and keep the reservation through any local unwinding.
                finished_keys_local=memory::Budget::reserve(budget_,finished_keys_charge);
                if (!finished_keys_local) return fail(ServerHandshakeIoError::budget_exceeded);
                handshake_keys_local=memory::Budget::reserve(budget_,handshake_key_scratch_charge);
                if (!handshake_keys_local) return fail(ServerHandshakeIoError::budget_exceeded);
            }
            auto keys=state_==State::hello ? server_handshake_keys(result->message,schemes,signature_policy_,recovery...) :
                server_handshake_keys_retry(first_hello_,retry_hello_,result->message,schemes,recovery...);
            if (!keys && signature_policy_==PeerSignaturePolicy::require_offered && state_==State::hello && keys.error()==ServerKeyError::retry_required) {
                handshake_keys_local.reset();
                finished_keys_local.reset();
                generated_hello_reservation.reset();
                if (budget_) {
                    retry_hello_reservation_=memory::Budget::reserve(budget_,16384);
                    if (!retry_hello_reservation_) return fail(ServerHandshakeIoError::budget_exceeded);
                }
                auto retry=server_retry_hello(result->message,schemes,recovery...);
                if (!retry) return fail(retry.error()==ServerKeyError::crypto_error ? ServerHandshakeIoError::crypto_error : ServerHandshakeIoError::protocol_error);
                generated_hello_scratch.reset();
                if (retry->size()>16384) { crypto::Bytes{}.swap(*retry); return fail(ServerHandshakeIoError::protocol_error); }
                if (retry_hello_reservation_) (void)retry_hello_reservation_->shrink(retry->size());
                if (encoded_local) (void)encoded_local->shrink(result->message.size());
                first_hello_=std::move(result->message); retry_hello_=std::move(*retry);
                first_hello_reservation_=std::move(encoded_local);
                auto size=retry_hello_.size();
                if (budget_) { hello_reservation_=memory::Budget::reserve(budget_,size+5); if (!hello_reservation_) return fail(ServerHandshakeIoError::budget_exceeded); }
                server_hello_.resize(size+5);
                server_hello_[0]=22; server_hello_[1]=3; server_hello_[2]=3;
                server_hello_[3]=static_cast<std::uint8_t>(size>>8); server_hello_[4]=static_cast<std::uint8_t>(size);
                std::ranges::copy(retry_hello_,server_hello_.begin()+5);
                hello_.reset(); hello_input_reservation_.reset(); state_=State::retry_output; return ServerHandshakeIoFeed{consumed};
            }
            if (!keys) return fail(keys.error()==ServerKeyError::crypto_error ? ServerHandshakeIoError::crypto_error : ServerHandshakeIoError::protocol_error);
            if (handshake_keys_local) (void)handshake_keys_local->shrink(handshake_key_retained_charge);
            generated_hello_scratch.reset();
            auto& hello=keys->server_hello; if (hello.size()>16384) return fail(ServerHandshakeIoError::protocol_error);
            std::optional<memory::Budget::Reservation> flight_scratch;
            std::optional<memory::Budget::Reservation> application_keys;
            if (budget_) {
                hello_reservation_=memory::Budget::reserve(budget_,hello.size()+5);
                if (!hello_reservation_) return fail(ServerHandshakeIoError::budget_exceeded);
                auto signature=credential_->max_signature_size(); if (!signature) return fail(ServerHandshakeIoError::protocol_error);
                std::size_t certificate=credential_->certificate().size()+5;
                for (auto const& item:credential_->chain()) certificate+=item.size()+5;
                // Certificate, EncryptedExtensions, CertificateVerify and Finished;
                // each unpadded TLS record adds 22 bytes. Certificate and signature
                // sizes are already limited by the credential implementation.
                auto plaintext=certificate+8+(required_alpn_.empty() ? 6 : 13+required_alpn_.size())+8+*signature+52;
                auto count=(plaintext+16383)/16384;
                flight_reservation_=memory::Budget::reserve(budget_,plaintext+(22+sizeof(crypto::Bytes))*count);
                if (!flight_reservation_) return fail(ServerHandshakeIoError::budget_exceeded);
                // Logical lengths of the simultaneously possible certificate body
                // and encoded message, fragment array, sealing temporaries and
                // small encoded messages. Output records are charged separately.
                // Vector capacities and crypto-library temporaries remain outside it.
                auto scratch=2*(certificate+8)+16384+flight_seal_scratch_charge+flight_key_scratch_charge+(8+*signature)+(required_alpn_.empty() ? 6 : 13+required_alpn_.size())+52;
                flight_scratch=memory::Budget::reserve(budget_,scratch);
                if (!flight_scratch) return fail(ServerHandshakeIoError::budget_exceeded);
                finished_decoder_reservation_=memory::Budget::reserve(budget_,ServerFlight::finished_decoder_charge);
                if (!finished_decoder_reservation_) return fail(ServerHandshakeIoError::budget_exceeded);
                application_keys=memory::Budget::reserve(budget_,ApplicationRecords::key_charge);
                if (!application_keys) return fail(ServerHandshakeIoError::budget_exceeded);
            }
            server_hello_.resize(hello.size()+5);
            server_hello_[0]=22; server_hello_[1]=3; server_hello_[2]=3;
            server_hello_[3]=static_cast<std::uint8_t>(hello.size()>>8); server_hello_[4]=static_cast<std::uint8_t>(hello.size());
            std::ranges::copy(hello,server_hello_.begin()+5);
            auto flight=ServerFlight::create(std::move(*keys),*credential_,required_alpn_,recovery...); if (!flight) return fail(flight.error()==ServerFlightError::crypto_error ? ServerHandshakeIoError::crypto_error : ServerHandshakeIoError::protocol_error);
            handshake_keys_local.reset();
            if (application_keys && !flight->retain_application_key_reservation(std::move(*application_keys))) return fail(ServerHandshakeIoError::protocol_error);
            generated_hello_reservation.reset();
            flight_scratch.reset();
            if (flight_reservation_) {
                std::size_t actual=flight->records().size()*sizeof(crypto::Bytes);
                if (actual>flight_reservation_->size()) {
                    flight=std::unexpected(ServerFlightError::invalid_state);
                    return fail(ServerHandshakeIoError::protocol_error);
                }
                for (auto const& record:flight->records()) {
                    if (record.size()>flight_reservation_->size()-actual) {
                        flight=std::unexpected(ServerFlightError::invalid_state);
                        return fail(ServerHandshakeIoError::protocol_error);
                    }
                    actual+=record.size();
                }
                (void)flight_reservation_->shrink(actual);
            }
            flight_.emplace(std::move(*flight)); finished_keys_reservation_=std::move(finished_keys_local); credential_.reset(); credential_reservation_.reset(); hello_.reset(); hello_input_reservation_.reset(); crypto::Bytes{}.swap(first_hello_); crypto::Bytes{}.swap(retry_hello_); first_hello_reservation_.reset(); retry_hello_reservation_.reset(); state_=State::output; return ServerHandshakeIoFeed{consumed};
        }
        if (budget_ && !input.empty() && !finished_input_reservation_) {
            finished_input_reservation_=memory::Budget::reserve(budget_,finished_input_charge);
            if (!finished_input_reservation_) return fail(ServerHandshakeIoError::budget_exceeded);
        }
        auto record=records_.feed(input,RecordFraming::handshake_ciphertext); if (!record) return fail(ServerHandshakeIoError::protocol_error);
        auto consumed=record->consumed; if (!record->record) return ServerHandshakeIoFeed{consumed};
        auto const& bytes=record->record->bytes;
        if (bytes[0]==20) {
            if (ccs_seen_ || encrypted_seen_ || bytes.size()!=6 || bytes[5]!=1) { record->record.reset(); return fail(ServerHandshakeIoError::protocol_error); }
            ccs_seen_=true; record->record.reset(); finished_input_reservation_.reset(); return ServerHandshakeIoFeed{consumed};
        }
        encrypted_seen_=true; auto result=flight_->client_finished(bytes,recovery...);
        record->record.reset(); finished_input_reservation_.reset();
        if (!result) return fail(result.error()==ServerFlightError::crypto_error ? ServerHandshakeIoError::crypto_error : ServerHandshakeIoError::protocol_error);
        if (*result) { finished_decoder_reservation_.reset(); finished_keys_reservation_.reset(); state_=State::complete; }
        return ServerHandshakeIoFeed{consumed};
        } catch (...) { (void)fail(ServerHandshakeIoError::protocol_error); throw; }
        }
        auto abort() -> void {(void)fail(ServerHandshakeIoError::canceled);}
    };
}
