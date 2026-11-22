module tls.raw_client_flight;
import tls.certificate_compression;
import std;

namespace tls {
    RawClientFlight::RawClientFlight(ClientHello&& hello,std::vector<std::uint16_t>&& offered,HandshakeSecrets&& keys) noexcept
        : hello_(std::move(hello)),offered_(std::move(offered)),keys_(std::move(keys)) {}
    RawClientFlight::RawClientFlight(RawClientFlight&& other) noexcept
        : state_(other.state_),hello_(std::move(other.hello_)),offered_(std::move(other.offered_)),keys_(std::move(other.keys_)),auth_(std::move(other.auth_)),alps_(other.alps_) { other.state_=State::failed; }
    auto RawClientFlight::operator=(RawClientFlight&& other) noexcept -> RawClientFlight& {
        if (this!=&other) { state_=other.state_; hello_=std::move(other.hello_); offered_=std::move(other.offered_); keys_=std::move(other.keys_); auth_=std::move(other.auth_); alps_=other.alps_; other.state_=State::failed; }
        return *this;
    }
    auto RawClientFlight::cancel() noexcept -> void { state_=State::failed; keys_.reset(); auth_.reset(); }
    auto RawClientFlight::fail(RawClientError error) noexcept -> std::unexpected<RawClientError> { cancel(); return std::unexpected(error); }
    auto RawClientFlight::client_hello() const noexcept -> ClientHello const& { return hello_; }
    auto RawClientFlight::can_read_handshake() const noexcept -> bool { return state_==State::extensions || state_==State::certificate || state_==State::signature || state_==State::finished; }
    auto RawClientFlight::complete() const noexcept -> bool { return state_==State::complete; }
    auto RawClientFlight::handshake_secrets() const noexcept -> std::expected<TrafficSecretView,RawClientError> {
        if (state_!=State::extensions || !keys_) return std::unexpected(RawClientError{ClientFlightError::invalid_state});
        return TrafficSecretView{keys_->cipher_suite,keys_->hash,keys_->client_traffic.view(),keys_->server_traffic.view()};
    }
    auto RawClientFlight::from_keys(std::span<std::uint8_t const> wire,HandshakeSecrets&& keys) -> std::expected<RawClientFlight,RawClientError> {
        if (wire.size()<4 || wire[0]!=1 || ((std::size_t{wire[1]}<<16)|(std::size_t{wire[2]}<<8)|wire[3])!=wire.size()-4)
            return std::unexpected(RawClientError{ClientFlightError::invalid_hello,50});
        auto hello=ClientHello::parse(wire.subspan(4));
        if (!hello || !hello->validate_tls13()) return std::unexpected(RawClientError{ClientFlightError::invalid_hello,47});
        auto signatures=hello->extension(13);
        if (!signatures || signatures->data.size()<4 || ((std::size_t{signatures->data[0]}<<8)|signatures->data[1])!=signatures->data.size()-2 || (signatures->data.size()-2)%2)
            return std::unexpected(RawClientError{ClientFlightError::invalid_hello,50});
        std::vector<std::uint16_t> offered;
        for (std::size_t i=2;i<signatures->data.size();i+=2) offered.push_back(static_cast<std::uint16_t>((std::uint16_t{signatures->data[i]}<<8)|signatures->data[i+1]));
        return RawClientFlight(std::move(*hello),std::move(offered),std::move(keys));
    }
    auto RawClientFlight::create_x25519(std::span<std::uint8_t const> client,std::span<std::uint8_t const> server,crypto::X25519Private&& key,HandshakeTransport transport) -> std::expected<RawClientFlight,RawClientError> {
        auto keys=client_handshake_secrets(client,server,std::move(key),transport);
        if (!keys) return std::unexpected(keys.error()==ClientKeyError::crypto_error ? RawClientError{ClientFlightError::crypto_error,80} : RawClientError{ClientFlightError::invalid_hello,47});
        return from_keys(client,std::move(*keys));
    }
    auto RawClientFlight::create_hybrid(std::span<std::uint8_t const> client,std::span<std::uint8_t const> server,HybridClient&& key,HandshakeTransport transport) -> std::expected<RawClientFlight,RawClientError> {
        auto keys=client_hybrid_handshake_secrets(client,server,std::move(key),transport);
        if (!keys) return std::unexpected(keys.error()==ClientKeyError::crypto_error ? RawClientError{ClientFlightError::crypto_error,80} : RawClientError{ClientFlightError::invalid_hello,47});
        return from_keys(client,std::move(*keys));
    }
    auto RawClientFlight::create_x25519_retry(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,std::span<std::uint8_t const> second,std::span<std::uint8_t const> server,crypto::X25519Private&& key,HandshakeTransport transport) -> std::expected<RawClientFlight,RawClientError> {
        auto keys=client_handshake_secrets_retry(first,retry,second,server,std::move(key),transport);
        if (!keys) return std::unexpected(keys.error()==ClientKeyError::crypto_error ? RawClientError{ClientFlightError::crypto_error,80} : RawClientError{ClientFlightError::invalid_hello,47});
        return from_keys(second,std::move(*keys));
    }
    auto RawClientFlight::create_hybrid_retry(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,std::span<std::uint8_t const> second,std::span<std::uint8_t const> server,HybridClient&& key,HandshakeTransport transport) -> std::expected<RawClientFlight,RawClientError> {
        auto keys=client_hybrid_handshake_secrets_retry(first,retry,second,server,std::move(key),transport);
        if (!keys) return std::unexpected(keys.error()==ClientKeyError::crypto_error ? RawClientError{ClientFlightError::crypto_error,80} : RawClientError{ClientFlightError::invalid_hello,47});
        return from_keys(second,std::move(*keys));
    }
    auto RawClientFlight::create_ecdh(std::span<std::uint8_t const> client,std::span<std::uint8_t const> server,crypto::EcPrivate&& key,HandshakeTransport transport) -> std::expected<RawClientFlight,RawClientError> {
        auto keys=client_handshake_secrets(client,server,std::move(key),transport);
        if (!keys) return std::unexpected(keys.error()==ClientKeyError::crypto_error ? RawClientError{ClientFlightError::crypto_error,80} : RawClientError{ClientFlightError::invalid_hello,47});
        return from_keys(client,std::move(*keys));
    }
    auto RawClientFlight::create_ecdh_retry(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,std::span<std::uint8_t const> second,std::span<std::uint8_t const> server,crypto::EcPrivate&& key,HandshakeTransport transport) -> std::expected<RawClientFlight,RawClientError> {
        auto keys=client_handshake_secrets_retry(first,retry,second,server,std::move(key),transport);
        if (!keys) return std::unexpected(keys.error()==ClientKeyError::crypto_error ? RawClientError{ClientFlightError::crypto_error,80} : RawClientError{ClientFlightError::invalid_hello,47});
        return from_keys(second,std::move(*keys));
    }
    auto RawClientFlight::extension_error(EncryptedExtensionsError error) noexcept -> RawClientError {
        auto alert=error==EncryptedExtensionsError::missing_required ? 109 : error==EncryptedExtensionsError::invalid_selection ? 120 : error==EncryptedExtensionsError::invalid_record_limit ? 47 :
            (error==EncryptedExtensionsError::unoffered || error==EncryptedExtensionsError::unsupported) ? 110 : error==EncryptedExtensionsError::malformed ? 50 : 47;
        return {ClientFlightError::invalid_extensions,static_cast<std::uint8_t>(alert)};
    }
    auto RawClientFlight::certificate_error(ClientAuthError error) noexcept -> RawClientError {
        return {error==ClientAuthError::crypto_error ? ClientFlightError::crypto_error : ClientFlightError::invalid_certificate,static_cast<std::uint8_t>(error==ClientAuthError::malformed_certificate ? 50 : error==ClientAuthError::untrusted_certificate ? 42 : 80)};
    }



    auto RawClientFlight::certificate_for_parsing(std::span<std::uint8_t const> message,std::size_t maximum_body) const
        -> std::expected<crypto::Bytes,RawClientError> {
        if (message.empty() || message.front()!=compressed_certificate_message) return crypto::Bytes{};
        auto offer=hello_.extension(certificate_compression_extension);
        if (!offer) return std::unexpected(RawClientError{ClientFlightError::illegal_parameter,47});
        auto decoded=expand_certificate(message,offer->data,maximum_body);
        if (!decoded) {
            if (decoded.error()==CertificateCompressionError::unoffered)
                return std::unexpected(RawClientError{ClientFlightError::illegal_parameter,47});
            if (decoded.error()==CertificateCompressionError::malformed)
                return std::unexpected(RawClientError{ClientFlightError::invalid_certificate,50});
            return std::unexpected(RawClientError{ClientFlightError::bad_certificate,42});
        }
        return std::move(*decoded);
    }

    auto RawClientFlight::certificate(std::span<std::uint8_t const> message,std::span<std::span<std::uint8_t const> const> anchors,PeerNameKind kind,std::span<std::uint8_t const> name,std::int64_t time) -> std::expected<void,RawClientError> {
        return certificate_with(message,[&](std::span<std::span<std::uint8_t const> const> chain) { return verify_server_certificate_chain(chain,anchors,kind,name,time); });
    }
    auto RawClientFlight::certificate(std::span<std::uint8_t const> message,CertificateVerifier const& verifier) -> std::expected<void,RawClientError> {
        if (state_!=State::certificate) return std::unexpected(RawClientError{ClientFlightError::invalid_state});
        state_=State::failed;
        try {
            auto decompressed=certificate_for_parsing(message,4194300);
            if (!decompressed) return fail(decompressed.error());
            auto decoded=decompressed->empty() ? message : std::span<std::uint8_t const>(*decompressed);
            auto result=auth_->certificate(decoded,verifier,message);
            if (!result) return fail(certificate_error(result.error()));
            state_=State::signature;
            return {};
        } catch (...) { cancel(); throw; }
    }
    auto RawClientFlight::certificate_verify(std::span<std::uint8_t const> message) -> std::expected<void,RawClientError> {
        if (state_!=State::signature) return std::unexpected(RawClientError{ClientFlightError::invalid_state});
        state_=State::failed;
        try {
            auto result=auth_->certificate_verify(message,offered_);
            if (!result) return fail(result.error()==ClientAuthError::crypto_error ? RawClientError{ClientFlightError::crypto_error,80} : RawClientError{ClientFlightError::invalid_signature,51});
            state_=State::finished; return {};
        } catch (...) { cancel(); throw; }
    }


}
