module tls.client_handshake;
import std;
namespace tls {
    ClientHandshake::ClientHandshake(ClientFlight&& f, HandshakeDecoder&& d, std::vector<crypto::Bytes>&& a,
        crypto::Bytes&& n, PeerNameKind k, std::int64_t time) noexcept
        : flight_(std::move(f)), decoder_(std::move(d)), anchors_(std::move(a)), name_(std::move(n)), kind_(k), time_(time) {}
    ClientHandshake::ClientHandshake(ClientHandshake&& o) noexcept
        : state_(o.state_), flight_(std::move(o.flight_)), records_(std::move(o.records_)), decoder_(std::move(o.decoder_)), pre_extensions_record_max_(std::exchange(o.pre_extensions_record_max_,0)),
          anchors_(std::move(o.anchors_)), name_(std::move(o.name_)), kind_(o.kind_), time_(o.time_), pins_(std::move(o.pins_)), negotiated_(std::move(o.negotiated_)), verifier_(std::move(o.verifier_)) { o.state_=State::failed; }
    auto ClientHandshake::operator=(ClientHandshake&& o) noexcept -> ClientHandshake& {
        if (this!=&o) { state_=o.state_; flight_=std::move(o.flight_); records_=std::move(o.records_); decoder_=std::move(o.decoder_); pre_extensions_record_max_=std::exchange(o.pre_extensions_record_max_,0);
            anchors_=std::move(o.anchors_); name_=std::move(o.name_); kind_=o.kind_; time_=o.time_;pins_=std::move(o.pins_); negotiated_=std::move(o.negotiated_); verifier_=std::move(o.verifier_); o.state_=State::failed; }
        return *this;
    }
    auto ClientHandshake::setup(ClientFlight&& flight, std::span<std::span<std::uint8_t const> const> anchors,
        PeerNameKind kind, std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<ClientHandshake,ClientHandshakeError> {
        if (anchors.empty() || anchors.size()>1024 || name.empty() || name.size()>253 ||
            (kind!=PeerNameKind::dns && kind!=PeerNameKind::ip) || (kind==PeerNameKind::ip && name.size()!=4 && name.size()!=16))
            return std::unexpected(ClientHandshakeError::invalid_configuration);
        std::size_t total=0; std::vector<crypto::Bytes> copies;
        for (auto cert:anchors) {
            if (cert.empty() || cert.size()>1048576 || cert.size()>4194304-total) return std::unexpected(ClientHandshakeError::invalid_configuration);
            total+=cert.size(); copies.emplace_back(cert.begin(),cert.end());
        }
        auto decoder=HandshakeDecoder::create(4194300); if (!decoder) return std::unexpected(ClientHandshakeError::invalid_configuration);
        return ClientHandshake(std::move(flight),std::move(*decoder),std::move(copies),crypto::Bytes(name.begin(),name.end()),kind,time);
    }
    auto ClientHandshake::create_x25519(std::span<std::uint8_t const> c, std::span<std::uint8_t const> s, crypto::X25519Private&& key,
        std::span<std::span<std::uint8_t const> const> a, PeerNameKind kind, std::span<std::uint8_t const> name, std::int64_t time)
        -> std::expected<ClientHandshake,ClientHandshakeError> {
        auto flight=ClientFlight::create_x25519(c,s,std::move(key)); if (!flight) return std::unexpected(ClientHandshakeError::invalid_hello);
        return setup(std::move(*flight),a,kind,name,time);
    }
    auto ClientHandshake::create_hybrid(std::span<std::uint8_t const> c, std::span<std::uint8_t const> s, HybridClient&& key,
        std::span<std::span<std::uint8_t const> const> a, PeerNameKind kind, std::span<std::uint8_t const> name, std::int64_t time)
        -> std::expected<ClientHandshake,ClientHandshakeError> {
        auto flight=ClientFlight::create_hybrid(c,s,std::move(key)); if (!flight) return std::unexpected(ClientHandshakeError::invalid_hello);
        return setup(std::move(*flight),a,kind,name,time);
    }
    auto ClientHandshake::setup_verifier(ClientFlight&& flight, CertificateVerifier verifier) -> std::expected<ClientHandshake,ClientHandshakeError> {
        if (!verifier) return std::unexpected(ClientHandshakeError::invalid_configuration);
        auto decoder=HandshakeDecoder::create(4194300); if (!decoder) return std::unexpected(ClientHandshakeError::invalid_configuration);
        ClientHandshake result(std::move(flight),std::move(*decoder),{}, {},PeerNameKind::dns,0);
        result.verifier_=std::move(verifier); return result;
    }
    auto ClientHandshake::create_x25519_with_verifier(std::span<std::uint8_t const> c, std::span<std::uint8_t const> s,
        crypto::X25519Private&& key, CertificateVerifier verifier) -> std::expected<ClientHandshake,ClientHandshakeError> {
        if (!verifier) return std::unexpected(ClientHandshakeError::invalid_configuration);
        auto flight=ClientFlight::create_x25519(c,s,std::move(key)); if (!flight) return std::unexpected(ClientHandshakeError::invalid_hello);
        return setup_verifier(std::move(*flight),std::move(verifier));
    }
    auto ClientHandshake::create_hybrid_with_verifier(std::span<std::uint8_t const> c, std::span<std::uint8_t const> s,
        HybridClient&& key, CertificateVerifier verifier) -> std::expected<ClientHandshake,ClientHandshakeError> {
        if (!verifier) return std::unexpected(ClientHandshakeError::invalid_configuration);
        auto flight=ClientFlight::create_hybrid(c,s,std::move(key)); if (!flight) return std::unexpected(ClientHandshakeError::invalid_hello);
        return setup_verifier(std::move(*flight),std::move(verifier));
    }
    auto ClientHandshake::create_x25519_retry_with_verifier(std::span<std::uint8_t const> first, std::span<std::uint8_t const> retry,
        std::span<std::uint8_t const> second, std::span<std::uint8_t const> server, crypto::X25519Private&& key,
        CertificateVerifier verifier) -> std::expected<ClientHandshake,ClientHandshakeError> {
        if (!verifier) return std::unexpected(ClientHandshakeError::invalid_configuration);
        auto flight=ClientFlight::create_x25519_retry(first,retry,second,server,std::move(key)); if (!flight) return std::unexpected(ClientHandshakeError::invalid_hello);
        return setup_verifier(std::move(*flight),std::move(verifier));
    }
    auto ClientHandshake::create_hybrid_retry_with_verifier(std::span<std::uint8_t const> first, std::span<std::uint8_t const> retry,
        std::span<std::uint8_t const> second, std::span<std::uint8_t const> server, HybridClient&& key,
        CertificateVerifier verifier) -> std::expected<ClientHandshake,ClientHandshakeError> {
        if (!verifier) return std::unexpected(ClientHandshakeError::invalid_configuration);
        auto flight=ClientFlight::create_hybrid_retry(first,retry,second,server,std::move(key)); if (!flight) return std::unexpected(ClientHandshakeError::invalid_hello);
        return setup_verifier(std::move(*flight),std::move(verifier));
    }
    auto ClientHandshake::create_x25519_retry(std::span<std::uint8_t const> first, std::span<std::uint8_t const> retry, std::span<std::uint8_t const> second, std::span<std::uint8_t const> server, crypto::X25519Private&& key,
        std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind, std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<ClientHandshake,ClientHandshakeError> {
        auto flight=ClientFlight::create_x25519_retry(first,retry,second,server,std::move(key)); if (!flight) return std::unexpected(ClientHandshakeError::invalid_hello);
        return setup(std::move(*flight),anchors,kind,name,time);
    }
    auto ClientHandshake::create_hybrid_retry(std::span<std::uint8_t const> first, std::span<std::uint8_t const> retry, std::span<std::uint8_t const> second, std::span<std::uint8_t const> server, HybridClient&& key,
        std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind, std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<ClientHandshake,ClientHandshakeError> {
        auto flight=ClientFlight::create_hybrid_retry(first,retry,second,server,std::move(key)); if (!flight) return std::unexpected(ClientHandshakeError::invalid_hello);
        return setup(std::move(*flight),anchors,kind,name,time);
    }

    auto ClientHandshake::finish_input() -> std::expected<void,ClientHandshakeError> {
        if (state_==State::failed || state_==State::complete) return std::unexpected(ClientHandshakeError::invalid_state);
        state_=State::failed; return std::unexpected(ClientHandshakeError::invalid_record);
    }
    auto ClientHandshake::negotiated() const noexcept -> EncryptedExtensions const* { return negotiated_ ? &*negotiated_ : nullptr; }
    auto ClientHandshake::take_application_records() -> std::expected<ApplicationRecords,ClientHandshakeError> {
        if (state_!=State::complete) return std::unexpected(ClientHandshakeError::invalid_state);
        auto records=flight_.take_application_records(); if (!records) return std::unexpected(ClientHandshakeError::invalid_state);
        return std::move(*records);
    }
    auto ClientHandshake::create_from_flight(ClientFlight&& flight,std::span<std::span<std::uint8_t const> const> anchors,PeerNameKind kind,
        std::span<std::uint8_t const> name,std::int64_t time) -> std::expected<ClientHandshake,ClientHandshakeError> {
        return setup(std::move(flight),anchors,kind,name,time);
    }
    auto ClientHandshake::create_from_flight_with_verifier(ClientFlight&& flight,CertificateVerifier verifier) -> std::expected<ClientHandshake,ClientHandshakeError> {
        return setup_verifier(std::move(flight),std::move(verifier));
    }

}
