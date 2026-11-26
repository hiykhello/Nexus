module tls.server_handshake_io;
import std;
namespace tls {
    ServerHandshakeIo::ServerHandshakeIo(ServerCredential&& c, ClientHelloStream&& h, std::uint64_t now, std::uint64_t deadline) noexcept
        : credential_(std::move(c)), hello_(std::move(h)), now_(now), deadline_(deadline) {}
    ServerHandshakeIo::ServerHandshakeIo(ServerHandshakeIo&& o) noexcept
        : state_(o.state_),budget_(std::move(o.budget_)),hello_reservation_(std::move(o.hello_reservation_)),flight_reservation_(std::move(o.flight_reservation_)),hello_input_reservation_(std::move(o.hello_input_reservation_)),finished_input_reservation_(std::move(o.finished_input_reservation_)),encoded_hello_reservation_(std::move(o.encoded_hello_reservation_)),first_hello_reservation_(std::move(o.first_hello_reservation_)),retry_hello_reservation_(std::move(o.retry_hello_reservation_)),finished_decoder_reservation_(std::move(o.finished_decoder_reservation_)),finished_keys_reservation_(std::move(o.finished_keys_reservation_)),credential_reservation_(std::move(o.credential_reservation_)),credential_(std::move(o.credential_)),hello_(std::move(o.hello_)),flight_(std::move(o.flight_)),records_(std::move(o.records_)),
          server_hello_(std::move(o.server_hello_)),first_hello_(std::move(o.first_hello_)),retry_hello_(std::move(o.retry_hello_)),required_alpn_(std::move(o.required_alpn_)),alpn_preferences_(std::move(o.alpn_preferences_)),allow_no_alpn_(o.allow_no_alpn_),record_(o.record_),offset_(o.offset_),ccs_seen_(o.ccs_seen_),encrypted_seen_(o.encrypted_seen_),signature_policy_(o.signature_policy_),now_(o.now_),deadline_(o.deadline_),ech_(std::move(o.ech_)),negotiated_sni_buf_(o.negotiated_sni_buf_),negotiated_sni_len_(o.negotiated_sni_len_) { o.state_=State::failed; o.negotiated_sni_len_=0; }
    auto ServerHandshakeIo::operator=(ServerHandshakeIo&& o) noexcept -> ServerHandshakeIo& {
        if (this!=&o) { state_=o.state_; credential_.reset(); credential_reservation_=std::move(o.credential_reservation_); credential_=std::move(o.credential_); hello_=std::move(o.hello_); flight_=std::move(o.flight_); records_=std::move(o.records_);
            server_hello_=std::move(o.server_hello_); first_hello_=std::move(o.first_hello_); retry_hello_=std::move(o.retry_hello_); required_alpn_=std::move(o.required_alpn_); alpn_preferences_=std::move(o.alpn_preferences_); allow_no_alpn_=o.allow_no_alpn_; hello_reservation_=std::move(o.hello_reservation_); flight_reservation_=std::move(o.flight_reservation_); hello_input_reservation_=std::move(o.hello_input_reservation_); finished_input_reservation_=std::move(o.finished_input_reservation_); encoded_hello_reservation_=std::move(o.encoded_hello_reservation_); first_hello_reservation_=std::move(o.first_hello_reservation_); retry_hello_reservation_=std::move(o.retry_hello_reservation_); finished_decoder_reservation_=std::move(o.finished_decoder_reservation_); finished_keys_reservation_=std::move(o.finished_keys_reservation_); budget_=std::move(o.budget_); record_=o.record_; offset_=o.offset_; ccs_seen_=o.ccs_seen_; encrypted_seen_=o.encrypted_seen_; signature_policy_=o.signature_policy_; now_=o.now_; deadline_=o.deadline_; ech_=std::move(o.ech_); negotiated_sni_buf_=o.negotiated_sni_buf_; negotiated_sni_len_=o.negotiated_sni_len_; o.negotiated_sni_len_=0; o.state_=State::failed; } return *this;
    }
    auto ServerHandshakeIo::fail(ServerHandshakeIoError error) -> std::unexpected<ServerHandshakeIoError> {
        state_=State::failed; credential_.reset(); credential_reservation_.reset(); hello_.reset(); flight_.reset(); records_=RecordStream{}; ech_.reset(); negotiated_sni_len_=0;
        crypto::Bytes{}.swap(server_hello_); crypto::Bytes{}.swap(first_hello_); crypto::Bytes{}.swap(retry_hello_);
        crypto::Bytes{}.swap(required_alpn_); alpn_preferences_.clear(); allow_no_alpn_=false; hello_reservation_.reset(); flight_reservation_.reset(); hello_input_reservation_.reset(); finished_input_reservation_.reset(); encoded_hello_reservation_.reset(); first_hello_reservation_.reset(); retry_hello_reservation_.reset(); finished_decoder_reservation_.reset(); finished_keys_reservation_.reset(); return std::unexpected(error);
    }
    auto ServerHandshakeIo::check_time(std::uint64_t now) -> std::expected<void,ServerHandshakeIoError> {
        if (state_==State::failed) return std::unexpected(ServerHandshakeIoError::invalid_state);
        if (now<now_) return std::unexpected(ServerHandshakeIoError::time_reversed);
        now_=now; if (state_!=State::complete && now>=deadline_) return fail(ServerHandshakeIoError::timeout); return {};
    }
    auto ServerHandshakeIo::create(ServerCredential&& credential,std::uint64_t now,std::uint64_t deadline,std::string_view required_alpn,std::size_t certificate_list_limit,std::shared_ptr<memory::Budget> budget,std::optional<memory::Budget::Reservation>&& credential_reservation) -> std::expected<ServerHandshakeIo,ServerHandshakeIoError> {
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
        result.budget_=std::move(budget); result.credential_reservation_=std::move(credential_reservation); result.hello_input_reservation_=std::move(input_reservation); result.encoded_hello_reservation_=std::move(encoded_reservation); result.required_alpn_.assign(required_alpn.begin(),required_alpn.end()); return result;
    }
    auto ServerHandshakeIo::create_alpn(ServerCredential&& credential,std::uint64_t now,std::uint64_t deadline,std::span<std::string_view const> alpn_preferences,bool allow_no_alpn,std::size_t certificate_list_limit,std::shared_ptr<memory::Budget> budget,std::optional<memory::Budget::Reservation>&& credential_reservation) -> std::expected<ServerHandshakeIo,ServerHandshakeIoError> {
        if (alpn_preferences.size()>16) return std::unexpected(ServerHandshakeIoError::invalid_argument);
        for (auto p : alpn_preferences) if (p.empty() || p.size()>255) return std::unexpected(ServerHandshakeIoError::invalid_argument);
        auto base=create(std::move(credential),now,deadline,{},certificate_list_limit,std::move(budget),std::move(credential_reservation));
        if (!base) return std::unexpected(base.error());
        base->alpn_preferences_.reserve(alpn_preferences.size());
        for (auto p : alpn_preferences) base->alpn_preferences_.emplace_back(p.begin(),p.end());
        base->allow_no_alpn_=allow_no_alpn;
        return base;
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
