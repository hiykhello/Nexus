module nexus.tls.server_handshake_io;
import std;
namespace nexus::tls {
    ServerHandshakeIo::ServerHandshakeIo(ServerCredential&& c, ClientHelloStream&& h, std::uint64_t now, std::uint64_t deadline) noexcept
        : credential_(std::move(c)), hello_(std::move(h)), now_(now), deadline_(deadline) {}
    ServerHandshakeIo::ServerHandshakeIo(ServerHandshakeIo&& o) noexcept
        : state_(o.state_),credential_(std::move(o.credential_)),hello_(std::move(o.hello_)),flight_(std::move(o.flight_)),records_(std::move(o.records_)),
          server_hello_(std::move(o.server_hello_)),first_hello_(std::move(o.first_hello_)),retry_hello_(std::move(o.retry_hello_)),required_alpn_(std::move(o.required_alpn_)),record_(o.record_),offset_(o.offset_),ccs_seen_(o.ccs_seen_),encrypted_seen_(o.encrypted_seen_),now_(o.now_),deadline_(o.deadline_) { o.state_=State::failed; }
    auto ServerHandshakeIo::operator=(ServerHandshakeIo&& o) noexcept -> ServerHandshakeIo& {
        if (this!=&o) { state_=o.state_; credential_=std::move(o.credential_); hello_=std::move(o.hello_); flight_=std::move(o.flight_); records_=std::move(o.records_);
            server_hello_=std::move(o.server_hello_); first_hello_=std::move(o.first_hello_); retry_hello_=std::move(o.retry_hello_); required_alpn_=std::move(o.required_alpn_); record_=o.record_; offset_=o.offset_; ccs_seen_=o.ccs_seen_; encrypted_seen_=o.encrypted_seen_; now_=o.now_; deadline_=o.deadline_; o.state_=State::failed; } return *this;
    }
    auto ServerHandshakeIo::fail(ServerHandshakeIoError error) -> std::unexpected<ServerHandshakeIoError> {
        state_=State::failed; credential_.reset(); hello_.reset(); flight_.reset(); records_=RecordStream{};
        crypto::Bytes{}.swap(server_hello_); crypto::Bytes{}.swap(first_hello_); crypto::Bytes{}.swap(retry_hello_);
        crypto::Bytes{}.swap(required_alpn_); return std::unexpected(error);
    }
    auto ServerHandshakeIo::check_time(std::uint64_t now) -> std::expected<void,ServerHandshakeIoError> {
        if (state_==State::failed) return std::unexpected(ServerHandshakeIoError::invalid_state);
        if (now<now_) return std::unexpected(ServerHandshakeIoError::time_reversed);
        now_=now; if (state_!=State::complete && now>=deadline_) return fail(ServerHandshakeIoError::timeout); return {};
    }
    auto ServerHandshakeIo::create(ServerCredential&& credential,std::uint64_t now,std::uint64_t deadline,std::string_view required_alpn,std::size_t certificate_list_limit) -> std::expected<ServerHandshakeIo,ServerHandshakeIoError> {
        if (deadline<=now || !credential.scheme() || required_alpn.size()>255) return std::unexpected(ServerHandshakeIoError::invalid_argument);
        auto remaining=certificate_list_limit;
        auto fits=[&](std::span<std::uint8_t const> cert) {
            if (remaining<5 || cert.size()>remaining-5) return false;
            remaining-=cert.size()+5; return true;
        };
        if (!fits(credential.certificate())) return std::unexpected(ServerHandshakeIoError::certificate_limit);
        for (auto const& cert:credential.chain()) if (!fits(cert)) return std::unexpected(ServerHandshakeIoError::certificate_limit);
        auto hello=ClientHelloStream::create(); if (!hello) return std::unexpected(ServerHandshakeIoError::invalid_state);
        ServerHandshakeIo result(std::move(credential),std::move(*hello),now,deadline);
        result.required_alpn_.assign(required_alpn.begin(),required_alpn.end()); return result;
    }
    auto ServerHandshakeIo::pending_output() const noexcept -> std::span<std::uint8_t const> {
        if (state_==State::retry_output) return std::span{server_hello_}.subspan(offset_);
        if (state_!=State::output) return {};
        if (record_==0) return std::span{server_hello_}.subspan(offset_);
        return std::span{flight_->records()[record_-1]}.subspan(offset_);
    }
    auto ServerHandshakeIo::written(std::size_t count,std::uint64_t now) -> std::expected<void,ServerHandshakeIoError> {
        auto time=check_time(now); if (!time) return std::unexpected(time.error());
        if (state_!=State::output && state_!=State::retry_output) return std::unexpected(ServerHandshakeIoError::invalid_state);
        auto remaining=pending_output().size(); if (count>remaining) return std::unexpected(ServerHandshakeIoError::invalid_argument);
        try {
        offset_+=count; if (count!=remaining) return {};
        offset_=0;
        if (state_==State::retry_output) {
            auto next=ClientHelloStream::create(65535,true); if (!next) return fail(ServerHandshakeIoError::protocol_error);
            hello_.emplace(std::move(*next)); crypto::Bytes{}.swap(server_hello_); state_=State::retry_hello; return {};
        }
        if (record_==0) crypto::Bytes{}.swap(server_hello_);
        else flight_->release_record(record_-1);
        ++record_; if (record_>flight_->records().size()) state_=State::finished; return {};
        } catch (...) { (void)fail(ServerHandshakeIoError::protocol_error); throw; }
    }
    auto ServerHandshakeIo::feed(std::span<std::uint8_t const> input,std::uint64_t now) -> std::expected<ServerHandshakeIoFeed,ServerHandshakeIoError> {
        auto time=check_time(now); if (!time) return std::unexpected(time.error());
        if (state_==State::output || state_==State::retry_output || state_==State::complete) return ServerHandshakeIoFeed{};
        try {
        if (state_==State::hello || state_==State::retry_hello) {
            auto result=hello_->feed(input); if (!result) return fail(ServerHandshakeIoError::protocol_error);
            if (result->compatibility_ccs) ccs_seen_=true;
            auto consumed=result->consumed; if (!result->hello) return ServerHandshakeIoFeed{consumed};
            if (!required_alpn_.empty()) {
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
            auto scheme=*credential_->scheme();
            auto keys=state_==State::hello ? server_handshake_keys(result->message,std::span{&scheme,1}) :
                server_handshake_keys_retry(first_hello_,retry_hello_,result->message,std::span{&scheme,1});
            if (!keys && state_==State::hello && keys.error()==ServerKeyError::retry_required) {
                auto retry=server_retry_hello(result->message,std::span{&scheme,1});
                if (!retry || retry->size()>16384) return fail(ServerHandshakeIoError::protocol_error);
                first_hello_=std::move(result->message); retry_hello_=std::move(*retry);
                auto size=retry_hello_.size(); server_hello_={22,3,3,static_cast<std::uint8_t>(size>>8),static_cast<std::uint8_t>(size)};
                server_hello_.insert(server_hello_.end(),retry_hello_.begin(),retry_hello_.end());
                hello_.reset(); state_=State::retry_output; return ServerHandshakeIoFeed{consumed};
            }
            if (!keys) return fail(ServerHandshakeIoError::protocol_error);
            auto& hello=keys->server_hello; if (hello.size()>16384) return fail(ServerHandshakeIoError::protocol_error);
            server_hello_={22,3,3,static_cast<std::uint8_t>(hello.size()>>8),static_cast<std::uint8_t>(hello.size())};
            server_hello_.insert(server_hello_.end(),hello.begin(),hello.end());
            auto flight=ServerFlight::create(std::move(*keys),*credential_,required_alpn_); if (!flight) return fail(ServerHandshakeIoError::protocol_error);
            flight_.emplace(std::move(*flight)); credential_.reset(); hello_.reset(); crypto::Bytes{}.swap(first_hello_); crypto::Bytes{}.swap(retry_hello_); state_=State::output; return ServerHandshakeIoFeed{consumed};
        }
        auto record=records_.feed(input,RecordFraming::handshake_ciphertext); if (!record) return fail(ServerHandshakeIoError::protocol_error);
        auto consumed=record->consumed; if (!record->record) return ServerHandshakeIoFeed{consumed};
        auto const& bytes=record->record->bytes;
        if (bytes[0]==20) {
            if (ccs_seen_ || encrypted_seen_ || bytes.size()!=6 || bytes[5]!=1) return fail(ServerHandshakeIoError::protocol_error);
            ccs_seen_=true; return ServerHandshakeIoFeed{consumed};
        }
        encrypted_seen_=true; auto result=flight_->client_finished(bytes);
        if (!result) return fail(ServerHandshakeIoError::protocol_error);
        if (*result) state_=State::complete;
        return ServerHandshakeIoFeed{consumed};
        } catch (...) { (void)fail(ServerHandshakeIoError::protocol_error); throw; }
    }
    auto ServerHandshakeIo::tick(std::uint64_t now) -> std::expected<void,ServerHandshakeIoError> { return check_time(now); }
    auto ServerHandshakeIo::cancel() -> std::expected<void,ServerHandshakeIoError> {
        if (state_==State::complete || state_==State::failed) return std::unexpected(ServerHandshakeIoError::invalid_state);
        (void)fail(ServerHandshakeIoError::canceled); return {};
    }
    auto ServerHandshakeIo::finish_input(std::uint64_t now) -> std::expected<void,ServerHandshakeIoError> {
        auto time=check_time(now); if (!time) return std::unexpected(time.error());
        if (state_==State::complete) return std::unexpected(ServerHandshakeIoError::invalid_state); return fail(ServerHandshakeIoError::protocol_error);
    }
    auto ServerHandshakeIo::take_application_records() -> std::expected<ApplicationRecords,ServerHandshakeIoError> {
        if (state_!=State::complete || !flight_) return std::unexpected(ServerHandshakeIoError::invalid_state);
        auto app=flight_->take_application_records(); if (!app) return std::unexpected(ServerHandshakeIoError::invalid_state);
        flight_.reset(); return std::move(*app);
    }
}
