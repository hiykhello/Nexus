export module tls.server_flight;
export import tls.server_keys;
export import tls.server_credential;
export import tls.client_flight;
export import tls.raw_server_flight;
import tls.handshake;
import tls.server_hello;
import tls.traffic_records;
import std;
export namespace tls {
    // Leaf and configured chain, no client authentication or retry. The caller owns transport framing.
    class ServerFlight {
        RawServerFlight raw_;
        std::optional<RecordLayer> read_;
        std::optional<ApplicationRecords> application_;
        std::vector<crypto::Bytes> records_;
        std::optional<HandshakeDecoder> decoder_;
        ServerFlight(RawServerFlight&& raw,RecordLayer&& read,ApplicationRecords&& application,std::vector<crypto::Bytes>&& records) noexcept;
    public:
        [[nodiscard]] auto retain_application_key_reservation(memory::Budget::Reservation&& reservation) noexcept -> bool {
            return application_ && application_->retain_key_reservation(std::move(reservation));
        }
        // Decryption output, one decoded body and message, plus SHA-384
        // transcript snapshot, Finished key, HMAC and the 18-byte HKDF label.
        // Container capacity and crypto-library internals are excluded.
        static constexpr std::size_t finished_temporary_charge=16640+48+sizeof(HandshakeMessage)+3*48+18;
        static constexpr std::size_t finished_decoder_charge=52;
        ServerFlight(ServerFlight const&)=delete;
        auto operator=(ServerFlight const&) -> ServerFlight& = delete;
        ServerFlight(ServerFlight&&) noexcept;
        auto operator=(ServerFlight&&) noexcept -> ServerFlight&;
        // Produces encrypted handshake records after ServerHello; transport must send them in order.
        // A nonempty ALPN must have been validated against the client offer by the caller.
        [[nodiscard]] auto records() const noexcept -> std::span<crypto::Bytes const> { return records_; }
        // Release only after the complete record has been sent; indices remain stable.
        auto release_record(std::size_t index) noexcept -> void;
        // After every record has been written, release the index allocation too.
        auto release_records() noexcept -> void;
        // One authenticated handshake record; true only after the complete client Finished.
        // An exception while processing input invalidates the flight.
        [[nodiscard]] auto take_application_records() -> std::expected<ApplicationRecords,ServerFlightError>;
        template<class... Recovery>
        static inline auto create(ServerHandshakeKeys&& input,ServerCredential const& credential,std::span<std::uint8_t const> selected_alpn={},Recovery&... recovery) -> std::expected<ServerFlight,ServerFlightError>{
            return create_with_ech_retry(std::move(input),credential,selected_alpn,{},recovery...);
        }
        template<class... Recovery>
        static inline auto create_with_ech_retry(ServerHandshakeKeys&& input,ServerCredential const& credential,std::span<std::uint8_t const> selected_alpn,std::span<std::uint8_t const> ech_retry_configs,Recovery&... recovery) -> std::expected<ServerFlight,ServerFlightError>{
        using Policy=RecoveryPolicy<Recovery...>;
        auto keys=std::move(input);
        if (keys.server_hello.size()<4) return std::unexpected(ServerFlightError::crypto_error);
        std::uint16_t suite=0;
        {
            auto hello=ServerHello::parse(std::span(keys.server_hello).subspan(4));
            if (!hello) return std::unexpected(ServerFlightError::crypto_error);
            suite=hello->cipher_suite;
        }
        std::array<crypto::Bytes,4> messages;
        std::optional<TrafficSecrets> secrets;
        auto raw=RawServerFlight::create_with_ech_retry(ServerHandshakeSecrets{std::move(keys.server_hello),keys.signature_scheme,
            HandshakeSecrets{suite,keys.hash,std::move(keys.transcript),std::move(keys.handshake_secret),std::move(keys.client_traffic),std::move(keys.server_traffic)}},credential,messages,secrets,selected_alpn,{},ech_retry_configs,recovery...);
        if (!raw) return std::unexpected(raw.error().kind);
        auto spec=cipher_spec(secrets->cipher_suite);
        auto layers=traffic_records(secrets->cipher_suite,secrets->client.view(),secrets->server.view(),true);
        if (!spec || !layers) return std::unexpected(ServerFlightError::crypto_error);
        ApplicationRecords application(std::move(layers->write),std::move(layers->read),16385,16385,secrets->hash,spec->algorithm,spec->key_bytes,
            std::move(secrets->server),std::move(secrets->client),ApplicationRole::server);
        std::size_t total=0;
        for (auto const& message:messages) total+=message.size();
        std::vector<crypto::Bytes> records; records.reserve((total+16383)/16384);
        std::array<std::uint8_t,16384> fragment{}; std::size_t used=0;
        for (std::size_t index=0;index<messages.size();++index) {
            auto bytes=std::span<std::uint8_t const>(messages[index]);
            while (!bytes.empty()) {
                auto count=std::min(fragment.size()-used,bytes.size());
                std::copy_n(bytes.begin(),count,fragment.begin()+used); used+=count; bytes=bytes.subspan(count);
                if (used==fragment.size()) {
                    auto record=keys.write.seal(ContentType::handshake,fragment);
                    if (!record) return std::unexpected(ServerFlightError::crypto_error);
                    records.push_back(std::move(*record)); used=0;
                }
            }
            crypto::Bytes{}.swap(messages[index]);
        }
        if (used) {
            auto record=keys.write.seal(ContentType::handshake,std::span(fragment).first(used));
            if (!record) return std::unexpected(ServerFlightError::crypto_error);
            records.push_back(std::move(*record));
        }
        auto decoder=HandshakeDecoder::create(48); if (!decoder) return std::unexpected(ServerFlightError::crypto_error);
        ServerFlight flight(std::move(*raw),std::move(keys.read),std::move(application),std::move(records));
        flight.decoder_.emplace(std::move(*decoder)); return flight;
        }
        template<class... Recovery>
        inline auto client_finished(std::span<std::uint8_t const> record,Recovery&... recovery) -> std::expected<bool,ServerFlightError>{
        using Policy=RecoveryPolicy<Recovery...>;
        if (!raw_.awaiting_finished()) return std::unexpected(ServerFlightError::invalid_state);
        auto fail=[this](ServerFlightError error) -> std::unexpected<ServerFlightError> {
            raw_.cancel(); read_.reset(); decoder_.reset(); application_.reset(); return std::unexpected(error);
        };
        try {
            auto plain=read_->open(record);
            if (!plain) return fail(plain.error()==RecordError::crypto_error ? ServerFlightError::crypto_error : ServerFlightError::invalid_finished);
            if (plain->type!=ContentType::handshake || plain->content.empty()) return fail(ServerFlightError::invalid_finished);
            auto messages=decoder_->feed(plain->content,1);
            if (!messages || messages->size()>1 || (!messages->empty() && decoder_->pending_bytes())) return fail(ServerFlightError::invalid_finished);
            if (messages->empty()) return false;
            auto const& message=messages->front();
            auto result=raw_.client_finished(message.type,message.body,recovery...);
            if (!result) return fail(result.error().kind);
            read_.reset(); decoder_.reset(); return true;
        } catch (...) { (void)fail(ServerFlightError::crypto_error); throw; }
        }
    };
}
