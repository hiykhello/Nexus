module nexus.tls.client_hello_driver;
import nexus.tls.handshake;
import std;
namespace nexus::tls {
    namespace {
        auto frame(ClientHello const& hello) -> std::expected<crypto::Bytes,ClientHelloDriverError> {
            auto body=hello.encode(); if (!body) return std::unexpected(ClientHelloDriverError::invalid_hello);
            auto wire=HandshakeDecoder::encode(1,*body,65531); if (!wire) return std::unexpected(ClientHelloDriverError::invalid_hello); return std::move(*wire);
        }
        auto record(std::span<std::uint8_t const> wire, std::uint8_t version) -> std::expected<crypto::Bytes,ClientHelloDriverError> {
            if (wire.size()>16384) return std::unexpected(ClientHelloDriverError::invalid_hello);
            crypto::Bytes out{22,3,version,static_cast<std::uint8_t>(wire.size()>>8),static_cast<std::uint8_t>(wire.size())}; out.insert(out.end(),wire.begin(),wire.end()); return out;
        }
    }
    ClientHelloDriver::ClientHelloDriver(ClientHello&& h, crypto::Bytes&& wire, ServerHelloStream&& stream)
        : first_(std::move(h)), current_(first_), first_wire_(std::move(wire)), current_wire_(first_wire_), stream_(std::move(stream)) {}
    ClientHelloDriver::ClientHelloDriver(ClientHelloDriver&& o) noexcept : state_(o.state_), first_(std::move(o.first_)), current_(std::move(o.current_)), first_wire_(std::move(o.first_wire_)), current_wire_(std::move(o.current_wire_)), retry_wire_(std::move(o.retry_wire_)), server_wire_(std::move(o.server_wire_)), x_(std::move(o.x_)), hybrid_(std::move(o.hybrid_)), stream_(std::move(o.stream_)) { o.state_=State::failed; }
    auto ClientHelloDriver::operator=(ClientHelloDriver&& o) noexcept -> ClientHelloDriver& {
        if (this!=&o) { state_=o.state_; first_=std::move(o.first_); current_=std::move(o.current_); first_wire_=std::move(o.first_wire_); current_wire_=std::move(o.current_wire_); retry_wire_=std::move(o.retry_wire_); server_wire_=std::move(o.server_wire_); x_=std::move(o.x_); hybrid_=std::move(o.hybrid_); stream_=std::move(o.stream_); o.state_=State::failed; } return *this;
    }
    auto ClientHelloDriver::make_share(std::uint16_t group) -> std::expected<KeyShareEntry,ClientHelloDriverError> {
        x_.reset(); hybrid_.reset();
        if (group==0x001d) { auto key=crypto::X25519Private::generate(); if (!key) return std::unexpected(ClientHelloDriverError::crypto_error); auto share=key->public_key(); if (!share) return std::unexpected(ClientHelloDriverError::crypto_error); x_=std::move(*key); return KeyShareEntry{group,{share->begin(),share->end()}}; }
        if (group==x25519_mlkem768_group) { auto key=HybridClient::generate(); if (!key) return std::unexpected(ClientHelloDriverError::crypto_error); auto share=key->share(); if (!share) return std::unexpected(ClientHelloDriverError::crypto_error); hybrid_=std::move(*key); return KeyShareEntry{group,{share->begin(),share->end()}}; }
        return std::unexpected(ClientHelloDriverError::invalid_hello);
    }
    auto ClientHelloDriver::create(ClientHello hello, std::uint16_t group) -> std::expected<ClientHelloDriver,ClientHelloDriverError> {
        if (!hello.validate_tls13() || hello.extension(41) || hello.extension(42) || hello.extension(44) || !hello.extension(51)) return std::unexpected(ClientHelloDriverError::invalid_hello);
        auto groups=hello.extension(10); if (!groups || groups->data.size()<4 || ((std::size_t{groups->data[0]}<<8)|groups->data[1])!=groups->data.size()-2 || (groups->data.size()-2)%2) return std::unexpected(ClientHelloDriverError::invalid_hello);
        bool offered=group==0; std::bitset<65536> seen;
        for (std::size_t i=2;i<groups->data.size();i+=2) {
            auto value=static_cast<std::uint16_t>((std::uint16_t{groups->data[i]}<<8)|groups->data[i+1]);
            if ((value!=0x001d && value!=x25519_mlkem768_group) || seen.test(value)) return std::unexpected(ClientHelloDriverError::invalid_hello);
            seen.set(value); if (value==group) offered=true;
        }
        if (!offered) return std::unexpected(ClientHelloDriverError::invalid_hello);
        auto stream=ServerHelloStream::create(); if (!stream) return std::unexpected(ClientHelloDriverError::crypto_error);
        auto wire=frame(hello); if (!wire) return std::unexpected(wire.error());
        ClientHelloDriver out(std::move(hello),std::move(*wire),std::move(*stream));
        std::vector<KeyShareEntry> entries;
        if (group) { auto share=out.make_share(group); if (!share) return std::unexpected(share.error()); entries.push_back(std::move(*share)); }
        auto encoded=KeyShare::encode_client(entries); if (!encoded) return std::unexpected(ClientHelloDriverError::invalid_hello);
        for (auto& e:out.first_.extensions) if (e.type==51) e.data=*encoded;
        auto actual=frame(out.first_); if (!actual || !record(*actual,1)) return std::unexpected(ClientHelloDriverError::invalid_hello);
        out.current_=out.first_; out.first_wire_=std::move(*actual); out.current_wire_=out.first_wire_;
        return out;
    }
    auto ClientHelloDriver::initial_record() const -> std::expected<crypto::Bytes,ClientHelloDriverError> {
        if (state_!=State::initial) return std::unexpected(ClientHelloDriverError::invalid_state); return record(first_wire_,1);
    }
    auto ClientHelloDriver::initial_sent() -> std::expected<void,ClientHelloDriverError> {
        if (state_!=State::initial) return std::unexpected(ClientHelloDriverError::invalid_state); state_=State::first; return {};
    }
    auto ClientHelloDriver::feed(std::span<std::uint8_t const> input) -> std::expected<ClientHelloDriverFeed,ClientHelloDriverError> {
        if (state_!=State::first && state_!=State::final) return std::unexpected(ClientHelloDriverError::invalid_state);
        auto parsed=stream_.feed(input); if (!parsed) { state_=State::failed; return std::unexpected(ClientHelloDriverError::invalid_record); }
        ClientHelloDriverFeed out{parsed->consumed,{},false}; if (!parsed->message) return out;
        if (!parsed->retry) { server_wire_=std::move(*parsed->message); state_=State::ready; out.server_hello=true; return out; }
        auto hello=ServerHello::parse(std::span{*parsed->message}.subspan(4)); if (!hello) { state_=State::failed; return std::unexpected(ClientHelloDriverError::invalid_retry); }
        auto selected=hello->validate_retry_request(first_); if (!selected) { state_=State::failed; return std::unexpected(ClientHelloDriverError::invalid_retry); }
        std::optional<KeyShareEntry> share;
        if (*selected) { auto fresh=make_share(**selected); if (!fresh) { state_=State::failed; return std::unexpected(fresh.error()); } share=std::move(*fresh); }
        auto second=hello->retry_client_hello(first_,std::move(share)); if (!second) { state_=State::failed; return std::unexpected(ClientHelloDriverError::invalid_retry); }
        auto wire=frame(*second); if (!wire) { state_=State::failed; return std::unexpected(wire.error()); }
        auto outbound=record(*wire,3); if (!outbound) { state_=State::failed; return std::unexpected(outbound.error()); }
        retry_wire_=std::move(*parsed->message); current_=std::move(*second); current_wire_=std::move(*wire); state_=State::sending_retry; out.outbound=std::move(*outbound); return out;
    }
    auto ClientHelloDriver::retry_sent() -> std::expected<void,ClientHelloDriverError> {
        if (state_!=State::sending_retry) return std::unexpected(ClientHelloDriverError::invalid_state);
        if (!stream_.resume_retry()) { state_=State::failed; return std::unexpected(ClientHelloDriverError::invalid_state); } state_=State::final; return {};
    }
    auto ClientHelloDriver::take_handshake(std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind, std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<ClientHandshake,ClientHelloDriverError> {
        if (state_!=State::ready) return std::unexpected(ClientHelloDriverError::invalid_state);
        state_=State::failed;
        auto server=ServerHello::parse(std::span{server_wire_}.subspan(4)); if (!server) return std::unexpected(ClientHelloDriverError::invalid_hello);
        auto share=std::ranges::find(server->extensions,std::uint16_t{51},&Extension::type); if (share==server->extensions.end()) return std::unexpected(ClientHelloDriverError::invalid_hello);
        auto peer=KeyShare::parse_server(share->data); if (!peer) return std::unexpected(ClientHelloDriverError::invalid_hello);
        std::optional<ClientHandshake> result;
        if (peer->group==0x001d && x_) {
            auto h=retry_wire_.empty() ? ClientHandshake::create_x25519(first_wire_,server_wire_,std::move(*x_),anchors,kind,name,time) : ClientHandshake::create_x25519_retry(first_wire_,retry_wire_,current_wire_,server_wire_,std::move(*x_),anchors,kind,name,time);
            if (h) result=std::move(*h);
        } else if (peer->group==x25519_mlkem768_group && hybrid_) {
            auto h=retry_wire_.empty() ? ClientHandshake::create_hybrid(first_wire_,server_wire_,std::move(*hybrid_),anchors,kind,name,time) : ClientHandshake::create_hybrid_retry(first_wire_,retry_wire_,current_wire_,server_wire_,std::move(*hybrid_),anchors,kind,name,time);
            if (h) result=std::move(*h);
        }
        x_.reset(); hybrid_.reset(); if (!result) return std::unexpected(ClientHelloDriverError::invalid_hello); state_=State::complete; return std::move(*result);
    }
}
