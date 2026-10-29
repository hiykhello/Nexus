module nexus.tls.server_handshake_io;
import std;
namespace nexus::tls {
    ServerHandshakeIo::ServerHandshakeIo(ServerCredential&& c, ClientHelloStream&& h, std::uint64_t now, std::uint64_t deadline) noexcept
        : credential_(std::move(c)), hello_(std::move(h)), now_(now), deadline_(deadline) {}
    ServerHandshakeIo::ServerHandshakeIo(ServerHandshakeIo&& o) noexcept
        : state_(o.state_),budget_(std::move(o.budget_)),hello_reservation_(std::move(o.hello_reservation_)),flight_reservation_(std::move(o.flight_reservation_)),hello_input_reservation_(std::move(o.hello_input_reservation_)),finished_input_reservation_(std::move(o.finished_input_reservation_)),encoded_hello_reservation_(std::move(o.encoded_hello_reservation_)),first_hello_reservation_(std::move(o.first_hello_reservation_)),retry_hello_reservation_(std::move(o.retry_hello_reservation_)),finished_decoder_reservation_(std::move(o.finished_decoder_reservation_)),finished_keys_reservation_(std::move(o.finished_keys_reservation_)),credential_(std::move(o.credential_)),hello_(std::move(o.hello_)),flight_(std::move(o.flight_)),records_(std::move(o.records_)),
          server_hello_(std::move(o.server_hello_)),first_hello_(std::move(o.first_hello_)),retry_hello_(std::move(o.retry_hello_)),required_alpn_(std::move(o.required_alpn_)),record_(o.record_),offset_(o.offset_),ccs_seen_(o.ccs_seen_),encrypted_seen_(o.encrypted_seen_),now_(o.now_),deadline_(o.deadline_) { o.state_=State::failed; }
    auto ServerHandshakeIo::operator=(ServerHandshakeIo&& o) noexcept -> ServerHandshakeIo& {
        if (this!=&o) { state_=o.state_; credential_=std::move(o.credential_); hello_=std::move(o.hello_); flight_=std::move(o.flight_); records_=std::move(o.records_);
            server_hello_=std::move(o.server_hello_); first_hello_=std::move(o.first_hello_); retry_hello_=std::move(o.retry_hello_); required_alpn_=std::move(o.required_alpn_); hello_reservation_=std::move(o.hello_reservation_); flight_reservation_=std::move(o.flight_reservation_); hello_input_reservation_=std::move(o.hello_input_reservation_); finished_input_reservation_=std::move(o.finished_input_reservation_); encoded_hello_reservation_=std::move(o.encoded_hello_reservation_); first_hello_reservation_=std::move(o.first_hello_reservation_); retry_hello_reservation_=std::move(o.retry_hello_reservation_); finished_decoder_reservation_=std::move(o.finished_decoder_reservation_); finished_keys_reservation_=std::move(o.finished_keys_reservation_); budget_=std::move(o.budget_); record_=o.record_; offset_=o.offset_; ccs_seen_=o.ccs_seen_; encrypted_seen_=o.encrypted_seen_; now_=o.now_; deadline_=o.deadline_; o.state_=State::failed; } return *this;
    }
    auto ServerHandshakeIo::fail(ServerHandshakeIoError error) -> std::unexpected<ServerHandshakeIoError> {
        state_=State::failed; credential_.reset(); hello_.reset(); flight_.reset(); records_=RecordStream{};
        crypto::Bytes{}.swap(server_hello_); crypto::Bytes{}.swap(first_hello_); crypto::Bytes{}.swap(retry_hello_);
        crypto::Bytes{}.swap(required_alpn_); hello_reservation_.reset(); flight_reservation_.reset(); hello_input_reservation_.reset(); finished_input_reservation_.reset(); encoded_hello_reservation_.reset(); first_hello_reservation_.reset(); retry_hello_reservation_.reset(); finished_decoder_reservation_.reset(); finished_keys_reservation_.reset(); return std::unexpected(error);
    }
    auto ServerHandshakeIo::check_time(std::uint64_t now) -> std::expected<void,ServerHandshakeIoError> {
        if (state_==State::failed) return std::unexpected(ServerHandshakeIoError::invalid_state);
        if (now<now_) return std::unexpected(ServerHandshakeIoError::time_reversed);
        now_=now; if (state_!=State::complete && now>=deadline_) return fail(ServerHandshakeIoError::timeout); return {};
    }
    auto ServerHandshakeIo::create(ServerCredential&& credential,std::uint64_t now,std::uint64_t deadline,std::string_view required_alpn,std::size_t certificate_list_limit,std::shared_ptr<memory::Budget> budget) -> std::expected<ServerHandshakeIo,ServerHandshakeIoError> {
        if (deadline<=now || !credential.scheme() || required_alpn.size()>255) return std::unexpected(ServerHandshakeIoError::invalid_argument);
        auto remaining=certificate_list_limit;
        auto fits=[&](std::span<std::uint8_t const> cert) {
            if (remaining<5 || cert.size()>remaining-5) return false;
            remaining-=cert.size()+5; return true;
        };
        if (!fits(credential.certificate())) return std::unexpected(ServerHandshakeIoError::certificate_limit);
        for (auto const& cert:credential.chain()) if (!fits(cert)) return std::unexpected(ServerHandshakeIoError::certificate_limit);
        std::optional<memory::Budget::Reservation> input_reservation,encoded_reservation;
        if (budget) {
            input_reservation=memory::Budget::reserve(budget,hello_reassembly_charge);
            if (!input_reservation) return std::unexpected(ServerHandshakeIoError::budget_exceeded);
            encoded_reservation=memory::Budget::reserve(budget,hello_encoded_charge);
            if (!encoded_reservation) return std::unexpected(ServerHandshakeIoError::budget_exceeded);
        }
        auto hello=ClientHelloStream::create(); if (!hello) return std::unexpected(ServerHandshakeIoError::invalid_state);
        ServerHandshakeIo result(std::move(credential),std::move(*hello),now,deadline);
        result.budget_=std::move(budget); result.hello_input_reservation_=std::move(input_reservation); result.encoded_hello_reservation_=std::move(encoded_reservation); result.required_alpn_.assign(required_alpn.begin(),required_alpn.end()); return result;
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
            crypto::Bytes{}.swap(server_hello_); hello_reservation_.reset();
            if (budget_) {
                hello_input_reservation_=memory::Budget::reserve(budget_,hello_reassembly_charge);
                if (!hello_input_reservation_) return fail(ServerHandshakeIoError::budget_exceeded);
                encoded_hello_reservation_=memory::Budget::reserve(budget_,hello_encoded_charge);
                if (!encoded_hello_reservation_) return fail(ServerHandshakeIoError::budget_exceeded);
            }
            auto next=ClientHelloStream::create(65535,true); if (!next) return fail(ServerHandshakeIoError::protocol_error);
            hello_.emplace(std::move(*next)); state_=State::retry_hello; return {};
        }
        if (record_==0) { crypto::Bytes{}.swap(server_hello_); hello_reservation_.reset(); }
        else {
            auto count=flight_->records()[record_-1].size(); flight_->release_record(record_-1);
            if (flight_reservation_) (void)flight_reservation_->shrink(flight_reservation_->size()-count);
        }
        ++record_;
        if (record_>flight_->records().size()) {
            flight_->release_records(); flight_reservation_.reset(); state_=State::finished;
        }
        return {};
        } catch (...) { (void)fail(ServerHandshakeIoError::protocol_error); throw; }
    }
    auto ServerHandshakeIo::feed(std::span<std::uint8_t const> input,std::uint64_t now) -> std::expected<ServerHandshakeIoFeed,ServerHandshakeIoError> {
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
            auto result=hello_->feed(input,budget_);
            if (!result) return fail(result.error()==ClientHelloStreamError::budget_exceeded ? ServerHandshakeIoError::budget_exceeded : ServerHandshakeIoError::protocol_error);
            if (result->compatibility_ccs) ccs_seen_=true;
            auto consumed=result->consumed; if (!result->hello) return ServerHandshakeIoFeed{consumed};
            encoded_local=std::move(encoded_hello_reservation_);
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
            if (budget_) {
                auto charge=ClientHelloStream::parsed_charge(result->message.size()-4);
                if (state_==State::retry_hello) charge+=ClientHelloStream::parsed_charge(first_hello_.size()-4);
                key_parse_reservation=memory::Budget::reserve(budget_,charge);
                if (!key_parse_reservation) return fail(ServerHandshakeIoError::budget_exceeded);
                generated_hello_reservation=memory::Budget::reserve(budget_,generated_hello_charge);
                if (!generated_hello_reservation) return fail(ServerHandshakeIoError::budget_exceeded);
                generated_hello_scratch=memory::Budget::reserve(budget_,generated_hello_scratch_charge);
                if (!generated_hello_scratch) return fail(ServerHandshakeIoError::budget_exceeded);
            }
            auto keys=state_==State::hello ? server_handshake_keys(result->message,std::span{&scheme,1}) :
                server_handshake_keys_retry(first_hello_,retry_hello_,result->message,std::span{&scheme,1});
            if (!keys && state_==State::hello && keys.error()==ServerKeyError::retry_required) {
                generated_hello_reservation.reset();
                if (budget_) {
                    retry_hello_reservation_=memory::Budget::reserve(budget_,16384);
                    if (!retry_hello_reservation_) return fail(ServerHandshakeIoError::budget_exceeded);
                }
                auto retry=server_retry_hello(result->message,std::span{&scheme,1});
                if (!retry) return fail(ServerHandshakeIoError::protocol_error);
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
            if (!keys) return fail(ServerHandshakeIoError::protocol_error);
            if (budget_) {
                finished_keys_local=memory::Budget::reserve(budget_,finished_keys_charge);
                if (!finished_keys_local) return fail(ServerHandshakeIoError::budget_exceeded);
            }
            generated_hello_scratch.reset();
            auto& hello=keys->server_hello; if (hello.size()>16384) return fail(ServerHandshakeIoError::protocol_error);
            std::optional<memory::Budget::Reservation> flight_scratch;
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
                auto scratch=2*(certificate+8)+16384+flight_seal_scratch_charge+(8+*signature)+(required_alpn_.empty() ? 6 : 13+required_alpn_.size())+52;
                flight_scratch=memory::Budget::reserve(budget_,scratch);
                if (!flight_scratch) return fail(ServerHandshakeIoError::budget_exceeded);
                finished_decoder_reservation_=memory::Budget::reserve(budget_,ServerFlight::finished_decoder_charge);
                if (!finished_decoder_reservation_) return fail(ServerHandshakeIoError::budget_exceeded);
            }
            server_hello_.resize(hello.size()+5);
            server_hello_[0]=22; server_hello_[1]=3; server_hello_[2]=3;
            server_hello_[3]=static_cast<std::uint8_t>(hello.size()>>8); server_hello_[4]=static_cast<std::uint8_t>(hello.size());
            std::ranges::copy(hello,server_hello_.begin()+5);
            auto flight=ServerFlight::create(std::move(*keys),*credential_,required_alpn_); if (!flight) return fail(ServerHandshakeIoError::protocol_error);
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
            flight_.emplace(std::move(*flight)); finished_keys_reservation_=std::move(finished_keys_local); credential_.reset(); hello_.reset(); hello_input_reservation_.reset(); crypto::Bytes{}.swap(first_hello_); crypto::Bytes{}.swap(retry_hello_); first_hello_reservation_.reset(); retry_hello_reservation_.reset(); state_=State::output; return ServerHandshakeIoFeed{consumed};
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
        encrypted_seen_=true; auto result=flight_->client_finished(bytes);
        record->record.reset(); finished_input_reservation_.reset();
        if (!result) return fail(ServerHandshakeIoError::protocol_error);
        if (*result) { finished_decoder_reservation_.reset(); finished_keys_reservation_.reset(); state_=State::complete; }
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
