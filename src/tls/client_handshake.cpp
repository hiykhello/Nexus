module nexus.tls.client_handshake;
import std;
namespace nexus::tls {
    ClientHandshake::ClientHandshake(ClientFlight&& f, HandshakeDecoder&& d, std::vector<crypto::Bytes>&& a,
        crypto::Bytes&& n, PeerNameKind k, std::int64_t time) noexcept
        : flight_(std::move(f)), decoder_(std::move(d)), anchors_(std::move(a)), name_(std::move(n)), kind_(k), time_(time) {}
    ClientHandshake::ClientHandshake(ClientHandshake&& o) noexcept
        : state_(o.state_), flight_(std::move(o.flight_)), records_(std::move(o.records_)), decoder_(std::move(o.decoder_)),
          anchors_(std::move(o.anchors_)), name_(std::move(o.name_)), kind_(o.kind_), time_(o.time_), negotiated_(std::move(o.negotiated_)) { o.state_=State::failed; }
    auto ClientHandshake::operator=(ClientHandshake&& o) noexcept -> ClientHandshake& {
        if (this!=&o) { state_=o.state_; flight_=std::move(o.flight_); records_=std::move(o.records_); decoder_=std::move(o.decoder_);
            anchors_=std::move(o.anchors_); name_=std::move(o.name_); kind_=o.kind_; time_=o.time_; negotiated_=std::move(o.negotiated_); o.state_=State::failed; }
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
    auto ClientHandshake::feed(std::span<std::uint8_t const> bytes) -> std::expected<ClientHandshakeFeed,ClientHandshakeError> {
        if (state_==State::failed || state_==State::complete) return std::unexpected(ClientHandshakeError::invalid_state);
        auto framed=records_.feed(bytes,RecordFraming::handshake_ciphertext);
        if (!framed) { state_=State::failed; return std::unexpected(ClientHandshakeError::invalid_record); }
        ClientHandshakeFeed result{framed->consumed,{}}; if (!framed->record) return result;
        if (framed->record->bytes[0]==20) {
            if (framed->record->bytes[5]!=1 || decoder_.pending_bytes()!=0) { state_=State::failed; return std::unexpected(ClientHandshakeError::invalid_record); }
            return result;
        }
        auto plain=flight_.open_handshake_record(framed->record->bytes);
        if (!plain) { state_=State::failed; return std::unexpected(ClientHandshakeError::invalid_record); }
        auto messages=decoder_.feed(*plain);
        if (!messages) { state_=State::failed; return std::unexpected(ClientHandshakeError::invalid_message); }
        for (std::size_t i=0;i<messages->size();++i) {
            auto& msg=(*messages)[i]; auto wire=HandshakeDecoder::encode(msg.type,msg.body,4194300);
            if (!wire) { state_=State::failed; return std::unexpected(ClientHandshakeError::invalid_message); }
            if (state_==State::extensions && msg.type==8) {
                auto ext=flight_.encrypted_extensions(*wire); if (!ext) { state_=State::failed; return std::unexpected(ClientHandshakeError::invalid_message); }
                negotiated_=std::move(*ext); state_=State::certificate;
            } else if (state_==State::certificate && msg.type==11) {
                std::vector<std::span<std::uint8_t const>> anchors; for (auto const& a:anchors_) anchors.emplace_back(a);
                if (!flight_.certificate(*wire,anchors,kind_,name_,time_)) { state_=State::failed; return std::unexpected(ClientHandshakeError::authentication_failed); }
                state_=State::signature;
            } else if (state_==State::signature && msg.type==15) {
                if (!flight_.certificate_verify(*wire)) { state_=State::failed; return std::unexpected(ClientHandshakeError::authentication_failed); }
                state_=State::finished;
            } else if (state_==State::finished && msg.type==20) {
                if (i+1!=messages->size() || decoder_.pending_bytes()!=0) { state_=State::failed; return std::unexpected(ClientHandshakeError::invalid_message); }
                if (!flight_.server_finished(*wire)) { state_=State::failed; return std::unexpected(ClientHandshakeError::authentication_failed); }
                auto finished=flight_.client_finished(); if (!finished) { state_=State::failed; return std::unexpected(ClientHandshakeError::authentication_failed); }
                result.client_finished_record=std::move(*finished); state_=State::complete;
            } else { state_=State::failed; return std::unexpected(ClientHandshakeError::invalid_message); }
        }
        return result;
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
}
