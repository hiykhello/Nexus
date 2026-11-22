export module tls.client_handshake;
export import tls.client_flight;
import tls.handshake;
import tls.certificate_compression;
import tls.record_stream;
import std;

export namespace tls {
    enum class ClientHandshakeError { invalid_state, invalid_configuration, invalid_hello, invalid_record, invalid_message, authentication_failed, crypto_error, record_overflow, illegal_parameter, bad_certificate };
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
        std::size_t pre_extensions_record_max_=0;
        std::vector<crypto::Bytes> anchors_;
        crypto::Bytes name_;
        PeerNameKind kind_;
        std::int64_t time_;
        std::vector<std::array<std::uint8_t,32>> pins_;
        std::optional<EncryptedExtensions> negotiated_;
        CertificateVerifier verifier_;
        ClientHandshake(ClientFlight&& flight, HandshakeDecoder&& decoder, std::vector<crypto::Bytes>&& anchors,
            crypto::Bytes&& name, PeerNameKind kind, std::int64_t time) noexcept;
        static auto setup(ClientFlight&& flight, std::span<std::span<std::uint8_t const> const> anchors,
            PeerNameKind kind, std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<ClientHandshake,ClientHandshakeError>;
        static auto setup_verifier(ClientFlight&& flight, CertificateVerifier verifier) -> std::expected<ClientHandshake,ClientHandshakeError>;
    public:
        auto set_certificate_pins(std::span<std::array<std::uint8_t,32> const> pins) -> void { pins_.assign(pins.begin(),pins.end()); }
        ClientHandshake(ClientHandshake const&)=delete;
        auto operator=(ClientHandshake const&) -> ClientHandshake& = delete;
        ClientHandshake(ClientHandshake&& other) noexcept;
        auto operator=(ClientHandshake&& other) noexcept -> ClientHandshake&;
        [[nodiscard]] static auto create_x25519(std::span<std::uint8_t const> client_hello, std::span<std::uint8_t const> server_hello,
            crypto::X25519Private&& key, std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind,
            std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<ClientHandshake,ClientHandshakeError>;
        [[nodiscard]] static auto create_x25519_with_verifier(std::span<std::uint8_t const> client_hello,
            std::span<std::uint8_t const> server_hello, crypto::X25519Private&& key, CertificateVerifier verifier)
            -> std::expected<ClientHandshake,ClientHandshakeError>;
        [[nodiscard]] static auto create_hybrid_with_verifier(std::span<std::uint8_t const> client_hello,
            std::span<std::uint8_t const> server_hello, HybridClient&& key, CertificateVerifier verifier)
            -> std::expected<ClientHandshake,ClientHandshakeError>;
        [[nodiscard]] static auto create_x25519_retry_with_verifier(std::span<std::uint8_t const> first,
            std::span<std::uint8_t const> retry, std::span<std::uint8_t const> second,
            std::span<std::uint8_t const> server, crypto::X25519Private&& key, CertificateVerifier verifier)
            -> std::expected<ClientHandshake,ClientHandshakeError>;
        [[nodiscard]] static auto create_hybrid_retry_with_verifier(std::span<std::uint8_t const> first,
            std::span<std::uint8_t const> retry, std::span<std::uint8_t const> second,
            std::span<std::uint8_t const> server, HybridClient&& key, CertificateVerifier verifier)
            -> std::expected<ClientHandshake,ClientHandshakeError>;
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
        [[nodiscard]] static auto create_from_flight(ClientFlight&& flight,std::span<std::span<std::uint8_t const> const> anchors,
            PeerNameKind kind,std::span<std::uint8_t const> name,std::int64_t time) -> std::expected<ClientHandshake,ClientHandshakeError>;
        [[nodiscard]] static auto create_from_flight_with_verifier(ClientFlight&& flight,CertificateVerifier verifier)
            -> std::expected<ClientHandshake,ClientHandshakeError>;
        [[nodiscard]] auto finish_input() -> std::expected<void,ClientHandshakeError>;
        // Negotiated values are unauthenticated until client_finished_record is returned.
        [[nodiscard]] auto negotiated() const noexcept -> EncryptedExtensions const*;
        [[nodiscard]] auto take_overflow_alert() -> std::expected<crypto::Bytes,ClientHandshakeError> {
            if (state_!=State::failed) return std::unexpected(ClientHandshakeError::invalid_state);
            auto record=flight_.take_handshake_overflow_alert();
            if (!record) return std::unexpected(ClientHandshakeError::crypto_error);
            return std::move(*record);
        }
        [[nodiscard]] auto take_application_records() -> std::expected<ApplicationRecords,ClientHandshakeError>;
        template<class... Recovery>
        inline auto feed(std::span<std::uint8_t const> bytes,Recovery&... recovery) -> std::expected<ClientHandshakeFeed,ClientHandshakeError>{
        using Policy=RecoveryPolicy<Recovery...>;
        if (state_==State::failed || state_==State::complete) return std::unexpected(ClientHandshakeError::invalid_state);
        try {
        auto framed=records_.feed(bytes,RecordFraming::handshake_ciphertext);
        if (!framed) {
            state_=State::failed;
            if (framed.error()==RecordStreamError::record_too_large) {
                flight_.signal_handshake_overflow();return std::unexpected(ClientHandshakeError::record_overflow);
            }
            return std::unexpected(ClientHandshakeError::invalid_record);
        }
        ClientHandshakeFeed result{framed->consumed,{}}; if (!framed->record) return result;
        if (framed->record->bytes[0]==20) {
            if (framed->record->bytes[5]!=1 || decoder_.pending_bytes()!=0) { state_=State::failed; return std::unexpected(ClientHandshakeError::invalid_record); }
            return result;
        }
        auto plain=flight_.open_handshake_record(framed->record->bytes);
        if (!plain) { state_=State::failed; return std::unexpected(plain.error()==ClientFlightError::crypto_error ? ClientHandshakeError::crypto_error : plain.error()==ClientFlightError::record_overflow ? ClientHandshakeError::record_overflow : ClientHandshakeError::invalid_record); }
        if (state_==State::extensions) pre_extensions_record_max_=std::max(pre_extensions_record_max_,framed->record->bytes.size());
        auto messages=decoder_.feed(*plain);
        if (!messages) { state_=State::failed; return std::unexpected(ClientHandshakeError::invalid_message); }
        for (std::size_t i=0;i<messages->size();++i) {
            auto& msg=(*messages)[i]; auto wire=HandshakeDecoder::encode(msg.type,msg.body,4194300);
            if (!wire) { state_=State::failed; return std::unexpected(ClientHandshakeError::invalid_message); }
            if (state_==State::extensions && msg.type==8) {
                auto ext=flight_.encrypted_extensions(*wire,recovery...); if (!ext) { state_=State::failed; return std::unexpected(ext.error()==ClientFlightError::crypto_error ? ClientHandshakeError::crypto_error : ext.error()==ClientFlightError::illegal_parameter ? ClientHandshakeError::illegal_parameter : ClientHandshakeError::invalid_message); }
                if (!flight_.handshake_record_within_limit(pre_extensions_record_max_)) {
                    state_=State::failed; return std::unexpected(ClientHandshakeError::record_overflow);
                }
                pre_extensions_record_max_=0;
                negotiated_=std::move(*ext);
                if constexpr(Policy::enabled)state_=recovery_policy(recovery...).selected() ? State::finished : State::certificate;
                else state_=State::certificate;
            } else if (state_==State::certificate && (msg.type==11 || msg.type==compressed_certificate_message)) {
                std::vector<std::span<std::uint8_t const>> anchors; for (auto const& a:anchors_) anchors.emplace_back(a);
                if (!pins_.empty()) verifier_=[&](std::span<std::span<std::uint8_t const> const> chain) {
                    return bool(verify_server_certificate_chain(chain,anchors,kind_,name_,time_,pins_));
                };
                auto accepted=verifier_ ? flight_.certificate(*wire,verifier_) : flight_.certificate(*wire,anchors,kind_,name_,time_);
                verifier_=nullptr;
                if (!accepted) {
                    state_=State::failed;
                    switch (accepted.error()) {
                    case ClientFlightError::crypto_error: return std::unexpected(ClientHandshakeError::crypto_error);
                    case ClientFlightError::illegal_parameter: return std::unexpected(ClientHandshakeError::illegal_parameter);
                    case ClientFlightError::bad_certificate: return std::unexpected(ClientHandshakeError::bad_certificate);
                    default: return std::unexpected(ClientHandshakeError::authentication_failed);
                    }
                }
                state_=State::signature;
            } else if (state_==State::signature && msg.type==15) {
                auto verified=flight_.certificate_verify(*wire);
                if (!verified) { state_=State::failed; return std::unexpected(verified.error()==ClientFlightError::crypto_error ? ClientHandshakeError::crypto_error : ClientHandshakeError::authentication_failed); }
                state_=State::finished;
            } else if (state_==State::finished && msg.type==20) {
                if (i+1!=messages->size() || decoder_.pending_bytes()!=0) { state_=State::failed; return std::unexpected(ClientHandshakeError::invalid_message); }
                auto verified=flight_.server_finished(*wire,recovery...);
                if (!verified) { state_=State::failed; return std::unexpected(verified.error()==ClientFlightError::crypto_error ? ClientHandshakeError::crypto_error : ClientHandshakeError::authentication_failed); }
                auto finished=flight_.client_finished(recovery...); if (!finished) { state_=State::failed; return std::unexpected(finished.error()==ClientFlightError::crypto_error ? ClientHandshakeError::crypto_error : ClientHandshakeError::authentication_failed); }
                result.client_finished_record=std::move(*finished); state_=State::complete;
            } else { state_=State::failed; return std::unexpected(ClientHandshakeError::invalid_message); }
        }
        return result;
        } catch (...) { state_=State::failed; throw; }
        }
    };
}
