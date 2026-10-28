module nexus.tls.client_flight;
import nexus.tls.server_hello;
import std;
namespace nexus::tls {
    namespace {
        auto valid_ticket(std::span<std::uint8_t const> body) -> bool {
            if (body.size()<13) return false;
            std::size_t p=8, nonce=body[p++]; if (nonce>body.size()-p) return false; p+=nonce;
            if (body.size()-p<2) return false;
            auto ticket=(std::size_t{body[p]}<<8)|body[p+1]; p+=2;
            if (!ticket || ticket>body.size()-p) return false; p+=ticket;
            if (body.size()-p<2) return false;
            auto extensions=(std::size_t{body[p]}<<8)|body[p+1]; p+=2;
            if (extensions>65534 || extensions!=body.size()-p) return false;
            std::bitset<65536> seen;
            while (p<body.size()) {
                if (body.size()-p<4) return false;
                auto type=(std::size_t{body[p]}<<8)|body[p+1]; auto len=(std::size_t{body[p+2]}<<8)|body[p+3]; p+=4;
                if (len>body.size()-p || seen.test(type) || (type==42 && len!=4)) return false;
                seen.set(type); p+=len;
            }
            return true;
        }
    }
    ApplicationRecords::ApplicationRecords(RecordLayer&& write, RecordLayer&& read, std::size_t wl, std::size_t rl, ApplicationRole role) noexcept
        : write_(std::move(write)), read_(std::move(read)), write_limit_(wl), read_limit_(rl), role_(role) {}
    ApplicationRecords::ApplicationRecords(RecordLayer&& write, RecordLayer&& read, std::size_t wl, std::size_t rl,
        crypto::Hash hash, crypto::Aead algorithm, std::size_t size, Secret&& ws, Secret&& rs, ApplicationRole role) noexcept
        : write_(std::move(write)), read_(std::move(read)), write_limit_(wl), read_limit_(rl), role_(role),
          write_secret_(std::move(ws)), read_secret_(std::move(rs)), hash_(hash), algorithm_(algorithm), key_size_(size) {}
    auto ApplicationRecords::rotate(bool sending) -> bool {
        auto& secret=sending ? write_secret_ : read_secret_; if (!secret) return false;
        auto n=hash_==crypto::Hash::sha256 ? 32u : hash_==crypto::Hash::sha384 ? 48u : 0u;
        if (!n) return false;
        auto next=expand_label(hash_,secret->view(),"traffic upd",{},n); if (!next) return false;
        auto key=expand_label(hash_,next->view(),"key",{},key_size_), iv=expand_label(hash_,next->view(),"iv",{},12);
        if (!key || !iv) return false;
        auto layer=RecordLayer::create(sending ? RecordDirection::send : RecordDirection::receive,algorithm_,key->view(),iv->view(),sending ? write_.send_limit() : (1u << 24));
        if (!layer) return false;
        (sending ? write_ : read_)=std::move(*layer); secret=std::move(*next); return true;
    }
    ApplicationRecords::ApplicationRecords(ApplicationRecords&& o) noexcept
        : write_(std::move(o.write_)), read_(std::move(o.read_)), write_limit_(o.write_limit_), read_limit_(o.read_limit_), role_(o.role_), active_(o.active_), read_closed_(o.read_closed_), write_closed_(o.write_closed_), update_response_(o.update_response_), write_secret_(std::move(o.write_secret_)), read_secret_(std::move(o.read_secret_)), hash_(o.hash_), algorithm_(o.algorithm_), key_size_(o.key_size_), handshake_pending_(std::move(o.handshake_pending_)) { o.active_=false; }
    auto ApplicationRecords::operator=(ApplicationRecords&& o) noexcept -> ApplicationRecords& {
        if (this!=&o) { write_=std::move(o.write_); read_=std::move(o.read_); write_limit_=o.write_limit_; read_limit_=o.read_limit_; role_=o.role_; active_=o.active_; read_closed_=o.read_closed_; write_closed_=o.write_closed_; update_response_=o.update_response_; write_secret_=std::move(o.write_secret_); read_secret_=std::move(o.read_secret_); hash_=o.hash_; algorithm_=o.algorithm_; key_size_=o.key_size_; handshake_pending_=std::move(o.handshake_pending_); o.active_=false; } return *this;
    }
    auto ApplicationRecords::seal(std::span<std::uint8_t const> data) -> std::expected<crypto::Bytes,RecordError> {
        if (!active_ || write_closed_ || update_response_) return std::unexpected(RecordError::invalid_state);
        if (data.size()>=write_limit_) return std::unexpected(RecordError::invalid_input);
        // Keep one record available for KeyUpdate or close_notify.
        if (write_.send_remaining()<=1) return std::unexpected(RecordError::key_usage_limit);
        auto out=write_.seal(ContentType::application_data,data); if (!out) { active_=false; return std::unexpected(out.error()); }
        return std::move(*out);
    }
    auto ApplicationRecords::open_event(std::span<std::uint8_t const> record) -> std::expected<ApplicationEvent,RecordError> {
        if (!active_ || read_closed_) return std::unexpected(RecordError::invalid_state);
        if (record.size()<22 || record.size()-21>read_limit_) { active_=false; return std::unexpected(RecordError::invalid_record); }
        auto plain=read_.open(record); if (!plain) { active_=false; return std::unexpected(plain.error()); }
        if (!handshake_pending_.empty() && plain->type!=ContentType::handshake) { active_=false; return std::unexpected(RecordError::invalid_record); }
        if (plain->type==ContentType::handshake) {
            // NewSessionTicket: two uint32s, uint8 nonce length and nonce,
            // uint16 ticket and extensions lengths and their contents. Allow
            // one extra record for bytes following a nearly complete message.
            constexpr std::size_t max_ticket=8+1+255+2+65535+2+65534;
            constexpr std::size_t max_pending=4+max_ticket+16384-1;
            if (!read_secret_ || plain->content.empty() || plain->content.size()>max_pending-handshake_pending_.size()) { active_=false; return std::unexpected(RecordError::invalid_record); }
            // A server accepts only KeyUpdate, which must end its record. No
            // valid server-side post-handshake message exceeds its five bytes.
            if (role_==ApplicationRole::server && plain->content.size()>5-handshake_pending_.size()) {
                active_=false; return std::unexpected(RecordError::invalid_record);
            }
            handshake_pending_.insert(handshake_pending_.end(),plain->content.begin(),plain->content.end());
            std::size_t offset=0;
            while (handshake_pending_.size()-offset>=4) {
                auto type=handshake_pending_[offset];
                auto size=(std::size_t{handshake_pending_[offset+1]}<<16)|(std::size_t{handshake_pending_[offset+2]}<<8)|handshake_pending_[offset+3];
                if ((type!=4 && type!=24) || (type==4 && (role_!=ApplicationRole::client || size>max_ticket)) || (type==24 && size!=1)) { active_=false; return std::unexpected(RecordError::invalid_record); }
                if (size>handshake_pending_.size()-offset-4) break;
                auto body=std::span{handshake_pending_}.subspan(offset+4,size);
                offset+=4+size;
                if (type==4) {
                    if (!valid_ticket(body)) { active_=false; return std::unexpected(RecordError::invalid_record); }
                    continue;
                }
                auto request=body[0];
                if (offset!=handshake_pending_.size() || request>1 || !rotate(false)) { active_=false; return std::unexpected(RecordError::invalid_record); }
                crypto::Bytes{}.swap(handshake_pending_);
                if (request==1) update_response_=true;
                return ApplicationEvent{request ? ApplicationEventKind::key_update_requested : ApplicationEventKind::key_update,{},0};
            }
            handshake_pending_.erase(handshake_pending_.begin(),handshake_pending_.begin()+static_cast<std::ptrdiff_t>(offset));
            if (handshake_pending_.empty()) crypto::Bytes{}.swap(handshake_pending_);
            return ApplicationEvent{offset ? ApplicationEventKind::ticket_discarded : ApplicationEventKind::handshake_fragment,{},0};
        }
        if (plain->type==ContentType::application_data) return ApplicationEvent{ApplicationEventKind::data,std::move(plain->content),0};
        if (plain->type!=ContentType::alert || plain->content.size()!=2) {
            active_=false; return std::unexpected(RecordError::invalid_record);
        }
        auto description=plain->content[1];
        if (description==0) { read_closed_=true; return ApplicationEvent{ApplicationEventKind::close_notify,{},0}; }
        if (description==90) return ApplicationEvent{ApplicationEventKind::user_canceled,{},description};
        // TLS 1.3 error alerts are fatal regardless of the legacy level.
        active_=false; return ApplicationEvent{ApplicationEventKind::fatal_alert,{},description};
    }
    auto ApplicationRecords::open(std::span<std::uint8_t const> record) -> std::expected<crypto::Bytes,RecordError> {
        auto event=open_event(record); if (!event) return std::unexpected(event.error());
        if (event->kind!=ApplicationEventKind::data) return std::unexpected(RecordError::invalid_state);
        return std::move(event->data);
    }
    auto ApplicationRecords::key_update(bool request) -> std::expected<crypto::Bytes,RecordError> {
        if (!active_ || write_closed_ || !write_secret_ || (update_response_ && request)) return std::unexpected(RecordError::invalid_state);
        std::array<std::uint8_t,5> message{24,0,0,1,static_cast<std::uint8_t>(request)};
        auto record=write_.seal(ContentType::handshake,message);
        if (!record || !rotate(true)) { active_=false; return std::unexpected(RecordError::crypto_error); }
        update_response_=false; return std::move(*record);
    }
    auto ApplicationRecords::close_notify() -> std::expected<crypto::Bytes,RecordError> {
        if (!active_ || write_closed_) return std::unexpected(RecordError::invalid_state);
        constexpr std::array<std::uint8_t,2> alert{1,0};
        auto record=write_.seal(ContentType::alert,alert);
        if (!record) { active_=false; return std::unexpected(record.error()); }
        write_closed_=true; return std::move(*record);
    }
    auto ApplicationRecords::finish_input() -> std::expected<void,RecordError> {
        if (!active_) return std::unexpected(RecordError::invalid_state);
        if (!read_closed_) { active_=false; return std::unexpected(RecordError::invalid_record); }
        return {};
    }
    ClientFlight::ClientFlight(ClientHello&& hello, std::vector<std::uint16_t>&& offered, ClientHandshakeKeys&& keys, crypto::Aead algorithm, std::size_t key_size) noexcept
        : hello_(std::move(hello)), offered_(std::move(offered)), keys_(std::move(keys)), algorithm_(algorithm), key_size_(key_size) {}
    ClientFlight::ClientFlight(ClientFlight&& o) noexcept
        : state_(o.state_), hello_(std::move(o.hello_)), offered_(std::move(o.offered_)), keys_(std::move(o.keys_)), auth_(std::move(o.auth_)), application_(std::move(o.application_)), algorithm_(o.algorithm_), key_size_(o.key_size_), read_limit_(o.read_limit_), write_limit_(o.write_limit_) { o.state_=State::failed; }
    auto ClientFlight::operator=(ClientFlight&& o) noexcept -> ClientFlight& {
        if (this!=&o) { state_=o.state_; hello_=std::move(o.hello_); offered_=std::move(o.offered_); keys_=std::move(o.keys_); auth_=std::move(o.auth_); application_=std::move(o.application_); algorithm_=o.algorithm_; key_size_=o.key_size_; read_limit_=o.read_limit_; write_limit_=o.write_limit_; o.state_=State::failed; }
        return *this;
    }
    auto ClientFlight::from_keys(std::span<std::uint8_t const> wire, std::span<std::uint8_t const> server_wire, ClientHandshakeKeys&& keys) -> std::expected<ClientFlight,ClientFlightError> {
        if (wire.size()<4 || wire[0]!=1 || ((std::size_t{wire[1]}<<16)|(std::size_t{wire[2]}<<8)|wire[3])!=wire.size()-4)
            return std::unexpected(ClientFlightError::invalid_hello);
        auto hello=ClientHello::parse(wire.subspan(4)); if (!hello) return std::unexpected(ClientFlightError::invalid_hello);
        if (auto limit=hello->extension(28)) {
            if (limit->data.size()!=2) return std::unexpected(ClientFlightError::invalid_hello);
            auto n=(std::size_t{limit->data[0]}<<8)|limit->data[1];
            if (n<64 || n>16385) return std::unexpected(ClientFlightError::invalid_hello);
        }
        auto ext=hello->extension(13);
        if (!ext || ext->data.size()<4 || ((std::size_t{ext->data[0]}<<8)|ext->data[1])!=ext->data.size()-2 || (ext->data.size()-2)%2)
            return std::unexpected(ClientFlightError::invalid_hello);
        std::vector<std::uint16_t> offered;
        for (std::size_t i=2;i<ext->data.size();i+=2) offered.push_back(static_cast<std::uint16_t>((std::uint16_t{ext->data[i]}<<8)|ext->data[i+1]));
        if (server_wire.size()<4) return std::unexpected(ClientFlightError::invalid_hello);
        auto server=ServerHello::parse(server_wire.subspan(4)); if (!server) return std::unexpected(ClientFlightError::invalid_hello);
        auto algorithm=server->cipher_suite==0x1301 ? crypto::Aead::aes_128_gcm : server->cipher_suite==0x1302 ? crypto::Aead::aes_256_gcm : crypto::Aead::chacha20_poly1305;
        auto size=server->cipher_suite==0x1301 ? 16u : 32u;
        return ClientFlight(std::move(*hello),std::move(offered),std::move(keys),algorithm,size);
    }
    auto ClientFlight::create_x25519(std::span<std::uint8_t const> c, std::span<std::uint8_t const> s, crypto::X25519Private&& key) -> std::expected<ClientFlight,ClientFlightError> {
        auto keys=client_handshake_keys(c,s,std::move(key)); if (!keys) return std::unexpected(ClientFlightError::invalid_hello);
        return from_keys(c,s,std::move(*keys));
    }
    auto ClientFlight::create_hybrid(std::span<std::uint8_t const> c, std::span<std::uint8_t const> s, HybridClient&& key) -> std::expected<ClientFlight,ClientFlightError> {
        auto keys=client_hybrid_handshake_keys(c,s,std::move(key)); if (!keys) return std::unexpected(ClientFlightError::invalid_hello);
        return from_keys(c,s,std::move(*keys));
    }
    auto ClientFlight::create_x25519_retry(std::span<std::uint8_t const> first, std::span<std::uint8_t const> retry, std::span<std::uint8_t const> second, std::span<std::uint8_t const> server, crypto::X25519Private&& key) -> std::expected<ClientFlight,ClientFlightError> {
        auto keys=client_handshake_keys_retry(first,retry,second,server,std::move(key)); if (!keys) return std::unexpected(ClientFlightError::invalid_hello);
        return from_keys(second,server,std::move(*keys));
    }
    auto ClientFlight::create_hybrid_retry(std::span<std::uint8_t const> first, std::span<std::uint8_t const> retry, std::span<std::uint8_t const> second, std::span<std::uint8_t const> server, HybridClient&& key) -> std::expected<ClientFlight,ClientFlightError> {
        auto keys=client_hybrid_handshake_keys_retry(first,retry,second,server,std::move(key)); if (!keys) return std::unexpected(ClientFlightError::invalid_hello);
        return from_keys(second,server,std::move(*keys));
    }
    auto ClientFlight::open_handshake_record(std::span<std::uint8_t const> record) -> std::expected<crypto::Bytes,ClientFlightError> {
        if (state_==State::complete || state_==State::failed || state_==State::client_finished) return std::unexpected(ClientFlightError::invalid_state);
        if (record.size()<22 || record.size()-5-16>read_limit_) { state_=State::failed; return std::unexpected(ClientFlightError::crypto_error); }
        auto plain=keys_.read.open(record);
        if (!plain || plain->type!=ContentType::handshake) { state_=State::failed; return std::unexpected(ClientFlightError::crypto_error); }
        return std::move(plain->content);
    }
    auto ClientFlight::encrypted_extensions(std::span<std::uint8_t const> m) -> std::expected<EncryptedExtensions,ClientFlightError> {
        if (state_!=State::extensions) return std::unexpected(ClientFlightError::invalid_state); state_=State::failed;
        auto ext=validate_encrypted_extensions(hello_,m); if (!ext) return std::unexpected(ClientFlightError::invalid_extensions);
        if (!keys_.transcript.append(m)) return std::unexpected(ClientFlightError::crypto_error);
        if (ext->peer_record_size_limit) {
            write_limit_=*ext->peer_record_size_limit;
            auto offered_limit=hello_.extension(28);
            if (offered_limit->data.size()!=2) return std::unexpected(ClientFlightError::invalid_hello);
            read_limit_=(std::size_t{offered_limit->data[0]}<<8)|offered_limit->data[1];
            if (read_limit_<64 || read_limit_>16385) return std::unexpected(ClientFlightError::invalid_hello);
        }
        auth_.emplace(keys_.hash,std::move(keys_.transcript),std::move(keys_.client_traffic),std::move(keys_.server_traffic));
        state_=State::certificate; return std::move(*ext);
    }
    auto ClientFlight::certificate(std::span<std::uint8_t const> m, std::span<std::span<std::uint8_t const> const> anchors,
        PeerNameKind kind, std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<void,ClientFlightError> {
        if (state_!=State::certificate) return std::unexpected(ClientFlightError::invalid_state); state_=State::failed;
        if (!auth_->certificate(m,anchors,kind,name,time)) return std::unexpected(ClientFlightError::invalid_certificate);
        state_=State::signature; return {};
    }
    auto ClientFlight::certificate_verify(std::span<std::uint8_t const> m) -> std::expected<void,ClientFlightError> {
        if (state_!=State::signature) return std::unexpected(ClientFlightError::invalid_state); state_=State::failed;
        if (!auth_->certificate_verify(m,offered_)) return std::unexpected(ClientFlightError::invalid_signature);
        state_=State::finished; return {};
    }
    auto ClientFlight::server_finished(std::span<std::uint8_t const> m) -> std::expected<void,ClientFlightError> {
        if (state_!=State::finished) return std::unexpected(ClientFlightError::invalid_state); state_=State::failed;
        if (!auth_->server_finished(m)) return std::unexpected(ClientFlightError::invalid_finished);
        auto hash=auth_->server_finished_hash(); auto master=master_secret(keys_.hash,keys_.handshake_secret.view());
        if (!hash || !master) return std::unexpected(ClientFlightError::crypto_error);
        auto client=derive_secret(keys_.hash,master->view(),"c ap traffic",*hash), server=derive_secret(keys_.hash,master->view(),"s ap traffic",*hash);
        if (!client || !server) return std::unexpected(ClientFlightError::crypto_error);
        auto ck=expand_label(keys_.hash,client->view(),"key",{},key_size_), ci=expand_label(keys_.hash,client->view(),"iv",{},12);
        auto sk=expand_label(keys_.hash,server->view(),"key",{},key_size_), si=expand_label(keys_.hash,server->view(),"iv",{},12);
        if (!ck || !ci || !sk || !si) return std::unexpected(ClientFlightError::crypto_error);
        auto write=RecordLayer::create(RecordDirection::send,algorithm_,ck->view(),ci->view());
        auto read=RecordLayer::create(RecordDirection::receive,algorithm_,sk->view(),si->view());
        if (!write || !read) return std::unexpected(ClientFlightError::crypto_error);
        application_.emplace(std::move(*write),std::move(*read),write_limit_,read_limit_,keys_.hash,algorithm_,key_size_,std::move(*client),std::move(*server),ApplicationRole::client);
        state_=State::client_finished; return {};
    }
    auto ClientFlight::client_finished() -> std::expected<crypto::Bytes,ClientFlightError> {
        if (state_!=State::client_finished) return std::unexpected(ClientFlightError::invalid_state); state_=State::failed;
        auto result=auth_->client_finished(); if (!result) return std::unexpected(ClientFlightError::crypto_error);
        auto record=keys_.write.seal(ContentType::handshake,*result);
        if (!record) return std::unexpected(ClientFlightError::crypto_error);
        state_=State::complete; return std::move(*record);
    }
    auto ClientFlight::take_application_records() -> std::expected<ApplicationRecords,ClientFlightError> {
        if (state_!=State::complete || !application_) return std::unexpected(ClientFlightError::invalid_state);
        auto result=std::move(*application_); application_.reset(); return result;
    }
}
