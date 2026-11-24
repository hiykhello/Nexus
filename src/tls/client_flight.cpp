module tls.client_flight;
import tls.server_hello;
import tls.traffic_records;
import tls.post_handshake;
import tls.handshake;
import std;
namespace tls {
    ApplicationRecords::ApplicationRecords(RecordLayer&& write, RecordLayer&& read, std::size_t wl, std::size_t rl, ApplicationRole role) noexcept
        : write_(std::move(write)), read_(std::move(read)), write_limit_(wl), read_limit_(rl), role_(role) {}
    ApplicationRecords::ApplicationRecords(RecordLayer&& write, RecordLayer&& read, std::size_t wl, std::size_t rl,
        crypto::Hash hash, crypto::Aead algorithm, std::size_t size, Secret&& ws, Secret&& rs, ApplicationRole role) noexcept
        : write_(std::move(write)), read_(std::move(read)), write_limit_(wl), read_limit_(rl), role_(role),
          write_secret_(std::move(ws)), read_secret_(std::move(rs)), hash_(hash), algorithm_(algorithm), key_size_(size) {}
    auto ApplicationRecords::rotate(bool sending) -> bool {
        auto& secret=sending ? write_secret_ : read_secret_; if (!secret) return false;
        auto n=hash_==crypto::Hash::sha256 ? 32u : hash_==crypto::Hash::sha384 ? 48u : 0u;
        auto expected_key=algorithm_==crypto::Aead::aes_128_gcm ? 16u :
            (algorithm_==crypto::Aead::aes_256_gcm || algorithm_==crypto::Aead::chacha20_poly1305) ? 32u : 0u;
        if (!n || !expected_key || key_size_!=expected_key) return false;
        auto next=expand_label(hash_,secret->view(),"traffic upd",{},n); if (!next) return false;
        auto key=expand_label(hash_,next->view(),"key",{},key_size_), iv=expand_label(hash_,next->view(),"iv",{},12);
        if (!key || !iv) return false;
        auto layer=RecordLayer::create(sending ? RecordDirection::send : RecordDirection::receive,algorithm_,key->view(),iv->view(),sending ? write_.send_limit() : (1u << 24));
        if (!layer) return false;
        (sending ? write_ : read_)=std::move(*layer); secret=std::move(*next); return true;
    }
    ApplicationRecords::ApplicationRecords(ApplicationRecords&& o) noexcept
        : key_reservation_(std::move(o.key_reservation_)), write_(std::move(o.write_)), read_(std::move(o.read_)), write_limit_(o.write_limit_), read_limit_(o.read_limit_), role_(o.role_), active_(o.active_), read_closed_(o.read_closed_), write_closed_(o.write_closed_), update_response_(o.update_response_), overflow_alert_pending_(std::exchange(o.overflow_alert_pending_,false)), write_secret_(std::move(o.write_secret_)), read_secret_(std::move(o.read_secret_)), hash_(o.hash_), algorithm_(o.algorithm_), key_size_(o.key_size_), handshake_pending_(std::move(o.handshake_pending_)), ticket_sink_(std::move(o.ticket_sink_)), server_handshake_pending_(o.server_handshake_pending_), server_handshake_size_(std::exchange(o.server_handshake_size_,0)) { crypto::cleanse(o.server_handshake_pending_); o.active_=false; }
    ApplicationRecords::~ApplicationRecords() noexcept {
        crypto::cleanse(handshake_pending_);
        crypto::cleanse(server_handshake_pending_);
    }
    auto ApplicationRecords::operator=(ApplicationRecords&& o) noexcept -> ApplicationRecords& {
        if (this!=&o) {
            crypto::cleanse(handshake_pending_); crypto::cleanse(server_handshake_pending_);
            write_=std::move(o.write_); read_=std::move(o.read_); write_limit_=o.write_limit_; read_limit_=o.read_limit_; role_=o.role_; active_=o.active_; read_closed_=o.read_closed_; write_closed_=o.write_closed_; update_response_=o.update_response_; overflow_alert_pending_=std::exchange(o.overflow_alert_pending_,false); write_secret_=std::move(o.write_secret_); read_secret_=std::move(o.read_secret_); key_reservation_=std::move(o.key_reservation_); hash_=o.hash_; algorithm_=o.algorithm_; key_size_=o.key_size_; handshake_pending_=std::move(o.handshake_pending_); ticket_sink_=std::move(o.ticket_sink_); server_handshake_pending_=o.server_handshake_pending_; server_handshake_size_=std::exchange(o.server_handshake_size_,0); crypto::cleanse(o.server_handshake_pending_); o.active_=false;
        }
        return *this;
    }
    auto ApplicationRecords::take_overflow_alert() -> std::expected<crypto::Bytes,RecordError> {
        if (!std::exchange(overflow_alert_pending_,false) || write_closed_) return std::unexpected(RecordError::invalid_state);
        constexpr std::array<std::uint8_t,2> alert{2,22};
        return write_.seal(ContentType::alert,alert);
    }
    auto ApplicationRecords::seal(std::span<std::uint8_t const> data) -> std::expected<crypto::Bytes,RecordError> {
        if (!active_ || write_closed_ || update_response_) return std::unexpected(RecordError::invalid_state);
        if (data.size()>=write_limit_) return std::unexpected(RecordError::invalid_input);
        // Keep one record available for KeyUpdate or close_notify.
        if (write_.send_remaining()<=1) return std::unexpected(RecordError::key_usage_limit);
        try {
            auto out=write_.seal(ContentType::application_data,data); if (!out) { active_=false; return std::unexpected(out.error()); }
            return std::move(*out);
        } catch (...) { active_=false; throw; }
    }
    auto ApplicationRecords::seal_into(std::span<std::uint8_t const> data, std::span<std::uint8_t> dest)
        -> std::expected<std::size_t,RecordError> {
        if (!active_ || write_closed_ || update_response_) return std::unexpected(RecordError::invalid_state);
        if (data.size()>=write_limit_) return std::unexpected(RecordError::invalid_input);
        if (write_.send_remaining()<=1) return std::unexpected(RecordError::key_usage_limit);
        try {
            auto out=write_.seal_into(ContentType::application_data,data,dest);
            if (!out) { if (out.error()!=RecordError::invalid_input) active_=false; return std::unexpected(out.error()); }
            return *out;
        } catch (...) { active_=false; throw; }
    }

    auto ApplicationRecords::open(std::span<std::uint8_t const> record) -> std::expected<crypto::Bytes,RecordError> {
        auto event=open_event(record); if (!event) return std::unexpected(event.error());
        if (event->kind!=ApplicationEventKind::data) return std::unexpected(RecordError::invalid_state);
        return std::move(event->data);
    }
    auto ApplicationRecords::key_update(bool request) -> std::expected<crypto::Bytes,RecordError> {
        if (!active_ || write_closed_ || !write_secret_ || (update_response_ && request)) return std::unexpected(RecordError::invalid_state);
        try {
        std::array<std::uint8_t,5> message{24,0,0,1,static_cast<std::uint8_t>(request)};
        auto record=write_.seal(ContentType::handshake,message);
        if (!record || !rotate(true)) { active_=false; return std::unexpected(RecordError::crypto_error); }
        update_response_=false; return std::move(*record);
        } catch (...) { active_=false; throw; }
    }
    auto ApplicationRecords::close_notify() -> std::expected<crypto::Bytes,RecordError> {
        if (!active_ || write_closed_) return std::unexpected(RecordError::invalid_state);
        try {
            constexpr std::array<std::uint8_t,2> alert{1,0};
            auto record=write_.seal(ContentType::alert,alert);
            if (!record) { active_=false; return std::unexpected(record.error()); }
            write_closed_=true; return std::move(*record);
        } catch (...) { active_=false; throw; }
    }
    auto ApplicationRecords::finish_input() -> std::expected<void,RecordError> {
        if (!active_) return std::unexpected(RecordError::invalid_state);
        if (!read_closed_) { active_=false; return std::unexpected(RecordError::invalid_record); }
        return {};
    }
    auto ApplicationRecords::can_handoff_tx() const noexcept -> bool {
        return active_ && !write_closed_ && !update_response_ && !overflow_alert_pending_ &&
            !write_.tls12() && write_.usable(RecordDirection::send) && write_secret_.has_value();
    }
    auto ApplicationRecords::can_handoff_rx() const noexcept -> bool {
        return active_ && !read_closed_ && handshake_pending_.empty() && !server_handshake_size_ &&
            !read_.tls12() && read_.usable(RecordDirection::receive) && read_secret_.has_value();
    }
    auto ApplicationRecords::take_ktls_tx() -> std::optional<KtlsDirectionHandoff> {
        if (!can_handoff_tx()) return {};
        auto mat = write_.export_ktls_material();
        if (!mat) return {};
        auto sec = std::move(*write_secret_);
        write_secret_.reset();
        return KtlsDirectionHandoff{std::move(*mat), std::move(sec), hash_};
    }
    auto ApplicationRecords::take_ktls_rx() -> std::optional<KtlsDirectionHandoff> {
        if (!can_handoff_rx()) return {};
        auto mat = read_.export_ktls_material();
        if (!mat) return {};
        auto sec = std::move(*read_secret_);
        read_secret_.reset();
        return KtlsDirectionHandoff{std::move(*mat), std::move(sec), hash_};
    }
    auto ApplicationRecords::session_ticket(std::span<std::uint8_t const> body) -> std::expected<crypto::Bytes,RecordError> {
        if (!active_ || write_closed_ || update_response_ || role_!=ApplicationRole::server || !valid_new_session_ticket(body)) return std::unexpected(RecordError::invalid_state);
        if (body.size()>write_limit_-std::min(write_limit_,std::size_t{5})) return std::unexpected(RecordError::invalid_input);
        if (write_.send_remaining()<=1)return std::unexpected(RecordError::key_usage_limit);
        try {
            auto message=HandshakeDecoder::encode(4,body,max_new_session_ticket);if (!message)return std::unexpected(RecordError::invalid_input);
            auto record=write_.seal(ContentType::handshake,*message);if (!record){active_=false;return std::unexpected(record.error());}return std::move(*record);
        } catch (...) {active_=false;throw;}
    }
    ClientFlight::ClientFlight(RawClientFlight&& raw,RecordLayer&& write,RecordLayer&& read) noexcept
        : raw_(std::move(raw)),write_(std::move(write)),read_(std::move(read)) {}
    ClientFlight::ClientFlight(ClientFlight&& other) noexcept
        : raw_(std::move(other.raw_)),write_(std::move(other.write_)),read_(std::move(other.read_)),application_(std::move(other.application_)),read_limit_(other.read_limit_),write_limit_(other.write_limit_),handshake_terminal_alert_(std::exchange(other.handshake_terminal_alert_,0)) {}
    auto ClientFlight::operator=(ClientFlight&& other) noexcept -> ClientFlight& {
        if (this!=&other) { raw_=std::move(other.raw_); write_=std::move(other.write_); read_=std::move(other.read_); application_=std::move(other.application_); read_limit_=other.read_limit_; write_limit_=other.write_limit_; handshake_terminal_alert_=std::exchange(other.handshake_terminal_alert_,0); }
        return *this;
    }
    auto ClientFlight::from_raw(RawClientFlight&& raw) -> std::expected<ClientFlight,ClientFlightError> {
        auto const& hello=raw.client_hello();
        if (!validate_handshake_transport(hello,HandshakeTransport::tcp)) return std::unexpected(ClientFlightError::invalid_hello);
        if (auto limit=hello.extension(28)) {
            if (limit->data.size()!=2) return std::unexpected(ClientFlightError::invalid_hello);
            auto n=(std::size_t{limit->data[0]}<<8)|limit->data[1];
            if (n<64 || n>16385) return std::unexpected(ClientFlightError::invalid_hello);
        }
        auto secrets=raw.handshake_secrets(); if (!secrets) return std::unexpected(secrets.error().kind);
        auto records=traffic_records(secrets->cipher_suite,secrets->client,secrets->server,false);
        if (!records) return std::unexpected(ClientFlightError::crypto_error);
        return ClientFlight(std::move(raw),std::move(records->write),std::move(records->read));
    }
    auto ClientFlight::create_x25519(std::span<std::uint8_t const> client,std::span<std::uint8_t const> server,crypto::X25519Private&& key) -> std::expected<ClientFlight,ClientFlightError> {
        auto raw=RawClientFlight::create_x25519(client,server,std::move(key));
        if (!raw) return std::unexpected(raw.error().kind);
        return from_raw(std::move(*raw));
    }
    auto ClientFlight::create_hybrid(std::span<std::uint8_t const> client,std::span<std::uint8_t const> server,HybridClient&& key) -> std::expected<ClientFlight,ClientFlightError> {
        auto raw=RawClientFlight::create_hybrid(client,server,std::move(key));
        if (!raw) return std::unexpected(raw.error().kind);
        return from_raw(std::move(*raw));
    }
    auto ClientFlight::create_x25519_retry(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,std::span<std::uint8_t const> second,std::span<std::uint8_t const> server,crypto::X25519Private&& key) -> std::expected<ClientFlight,ClientFlightError> {
        auto raw=RawClientFlight::create_x25519_retry(first,retry,second,server,std::move(key));
        if (!raw) return std::unexpected(raw.error().kind);
        return from_raw(std::move(*raw));
    }
    auto ClientFlight::create_hybrid_retry(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,std::span<std::uint8_t const> second,std::span<std::uint8_t const> server,HybridClient&& key) -> std::expected<ClientFlight,ClientFlightError> {
        auto raw=RawClientFlight::create_hybrid_retry(first,retry,second,server,std::move(key));
        if (!raw) return std::unexpected(raw.error().kind);
        return from_raw(std::move(*raw));
    }
    auto ClientFlight::open_handshake_record(std::span<std::uint8_t const> record) -> std::expected<crypto::Bytes,ClientFlightError> {
        if (!raw_.can_read_handshake()) return std::unexpected(ClientFlightError::invalid_state);
        if (record.size()<22) { raw_.cancel(); return std::unexpected(ClientFlightError::invalid_record); }
        if (!handshake_record_within_limit(record.size())) return std::unexpected(ClientFlightError::record_overflow);
        auto plain=read_.open(record);
        if (!plain) { raw_.cancel(); return std::unexpected(plain.error()==RecordError::crypto_error ? ClientFlightError::crypto_error : ClientFlightError::invalid_record); }
        if (plain->type!=ContentType::handshake) { raw_.cancel(); return std::unexpected(ClientFlightError::invalid_record); }
        return std::move(plain->content);
    }

    auto ClientFlight::take_handshake_overflow_alert() -> std::expected<crypto::Bytes,ClientFlightError> {
        auto description=std::exchange(handshake_terminal_alert_,0);
        if (!description) return std::unexpected(ClientFlightError::invalid_state);
        std::array<std::uint8_t,2> alert{2,description};
        auto result=write_.seal(ContentType::alert,alert);raw_.cancel();
        if (!result) return std::unexpected(ClientFlightError::crypto_error);
        return std::move(*result);
    }

    auto ClientFlight::certificate(std::span<std::uint8_t const> message,std::span<std::span<std::uint8_t const> const> anchors,PeerNameKind kind,std::span<std::uint8_t const> name,std::int64_t time) -> std::expected<void,ClientFlightError> {
        auto result=raw_.certificate(message,anchors,kind,name,time);
        if (!result) {
            if (result.error().kind==ClientFlightError::illegal_parameter || result.error().kind==ClientFlightError::bad_certificate)
                handshake_terminal_alert_=result.error().alert;
            return std::unexpected(result.error().kind);
        }
        return {};
    }
    auto ClientFlight::certificate(std::span<std::uint8_t const> message,CertificateVerifier const& verifier) -> std::expected<void,ClientFlightError> {
        auto result=raw_.certificate(message,verifier);
        if (!result) {
            if (result.error().kind==ClientFlightError::illegal_parameter || result.error().kind==ClientFlightError::bad_certificate)
                handshake_terminal_alert_=result.error().alert;
            return std::unexpected(result.error().kind);
        }
        return {};
    }
    auto ClientFlight::certificate_verify(std::span<std::uint8_t const> message) -> std::expected<void,ClientFlightError> {
        auto result=raw_.certificate_verify(message);
        if (!result) return std::unexpected(result.error().kind);
        return {};
    }


    auto ClientFlight::take_application_records() -> std::expected<ApplicationRecords,ClientFlightError> {
        if (!raw_.complete() || !application_) return std::unexpected(ClientFlightError::invalid_state);
        auto result=std::move(*application_); application_.reset(); return result;
    }
}
