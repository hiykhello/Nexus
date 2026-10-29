module nexus.tls.server_flight;
import nexus.tls.handshake;
import nexus.tls.server_hello;
import std;
namespace nexus::tls {
    ServerFlight::ServerFlight(ServerHandshakeKeys&& keys, ApplicationRecords&& application, std::vector<crypto::Bytes>&& records) noexcept
        : keys_(FinishedKeys{keys.hash,std::move(keys.transcript),std::move(keys.client_traffic),std::move(keys.read)}),
          application_(std::move(application)), records_(std::move(records)) {}
    ServerFlight::ServerFlight(ServerFlight&& o) noexcept
        : state_(o.state_), keys_(std::move(o.keys_)), application_(std::move(o.application_)), records_(std::move(o.records_)), decoder_(std::move(o.decoder_)) { o.state_=State::failed; }
    auto ServerFlight::operator=(ServerFlight&& o) noexcept -> ServerFlight& {
        if (this!=&o) { state_=o.state_; keys_=std::move(o.keys_); application_=std::move(o.application_); records_=std::move(o.records_); decoder_=std::move(o.decoder_); o.state_=State::failed; } return *this;
    }
    auto ServerFlight::release_record(std::size_t index) noexcept -> void {
        if (index<records_.size()) crypto::Bytes{}.swap(records_[index]);
    }
    auto ServerFlight::release_records() noexcept -> void { std::vector<crypto::Bytes>{}.swap(records_); }
    auto ServerFlight::create(ServerHandshakeKeys&& input, ServerCredential const& credential, std::span<std::uint8_t const> selected_alpn) -> std::expected<ServerFlight,ServerFlightError> {
        auto keys=std::move(input); auto cert=credential.certificate();
        constexpr auto list_limit=ServerCredential::max_certificate_list_size;
        if (!credential.scheme() || *credential.scheme()!=keys.signature_scheme || cert.empty() || cert.size()>list_limit-5)
            return std::unexpected(ServerFlightError::invalid_credential);
        if (keys.server_hello.size()<4 || keys.server_hello[0]!=2 ||
            ((std::size_t{keys.server_hello[1]}<<16)|(std::size_t{keys.server_hello[2]}<<8)|keys.server_hello[3])!=keys.server_hello.size()-4)
            return std::unexpected(ServerFlightError::crypto_error);
        crypto::Aead algorithm; std::size_t key_size;
        {
            auto server=ServerHello::parse(std::span{keys.server_hello}.subspan(4));
            if (!server || (server->cipher_suite!=0x1301 && server->cipher_suite!=0x1302 && server->cipher_suite!=0x1303))
                return std::unexpected(ServerFlightError::crypto_error);
            algorithm=server->cipher_suite==0x1301 ? crypto::Aead::aes_128_gcm : server->cipher_suite==0x1302 ? crypto::Aead::aes_256_gcm : crypto::Aead::chacha20_poly1305;
            key_size=server->cipher_suite==0x1301 ? 16u : 32u;
        }
        // The transcript already owns the hash state; neither encoded nor
        // parsed ServerHello is needed while retaining the handshake keys.
        crypto::Bytes{}.swap(keys.server_hello);
        auto put24=[](crypto::Bytes& out,std::size_t n) { out.push_back(static_cast<std::uint8_t>(n>>16)); out.push_back(static_cast<std::uint8_t>(n>>8)); out.push_back(static_cast<std::uint8_t>(n)); };
        if (selected_alpn.size()>255) return std::unexpected(ServerFlightError::invalid_state);
        // Encode directly into the final message: the flight scratch budget
        // accounts for this message, not separate extension-vector copies.
        auto n=selected_alpn.size();
        auto extension_size=n ? n+7 : 0;
        crypto::Bytes extensions(6+extension_size);
        extensions[0]=8; extensions[2]=static_cast<std::uint8_t>((extension_size+2)>>8);
        extensions[3]=static_cast<std::uint8_t>(extension_size+2);
        extensions[4]=static_cast<std::uint8_t>(extension_size>>8); extensions[5]=static_cast<std::uint8_t>(extension_size);
        if (n) {
            extensions[6]=0; extensions[7]=16;
            extensions[8]=static_cast<std::uint8_t>((n+3)>>8); extensions[9]=static_cast<std::uint8_t>(n+3);
            extensions[10]=static_cast<std::uint8_t>((n+1)>>8); extensions[11]=static_cast<std::uint8_t>(n+1);
            extensions[12]=static_cast<std::uint8_t>(n);
            std::ranges::copy(selected_alpn,extensions.begin()+13);
        }
        std::size_t list_size=cert.size()+5;
        for (auto const& intermediate:credential.chain()) {
            if (intermediate.empty() || intermediate.size()>list_limit-5 || list_size>list_limit-intermediate.size()-5)
                return std::unexpected(ServerFlightError::invalid_credential);
            list_size+=intermediate.size()+5;
        }
        // Allocate the complete certificate body once, so growing the large
        // chain cannot temporarily retain an old body alongside a new one.
        crypto::Bytes body; body.reserve(list_size+4); body.push_back(0); put24(body,list_size);
        auto append_cert=[&](std::span<std::uint8_t const> value) { put24(body,value.size()); body.insert(body.end(),value.begin(),value.end()); body.insert(body.end(),{0,0}); };
        append_cert(cert); for (auto const& intermediate:credential.chain()) append_cert(intermediate);
        auto certificate=HandshakeDecoder::encode(11,body,1048580); if (!certificate) return std::unexpected(ServerFlightError::crypto_error);
        crypto::Bytes{}.swap(body);
        if (!keys.transcript.append(extensions) || !keys.transcript.append(*certificate)) return std::unexpected(ServerFlightError::crypto_error);
        auto hash=keys.transcript.snapshot(); if (!hash) return std::unexpected(ServerFlightError::crypto_error);
        auto signature=credential.sign(keys.hash,*hash); if (!signature || !keys.transcript.append(*signature)) return std::unexpected(ServerFlightError::crypto_error);
        hash=keys.transcript.snapshot(); if (!hash) return std::unexpected(ServerFlightError::crypto_error);
        auto verify=finished_verify_data(keys.hash,keys.server_traffic.view(),*hash); if (!verify) return std::unexpected(ServerFlightError::crypto_error);
        auto finished=HandshakeDecoder::encode(20,verify->view()); if (!finished || !keys.transcript.append(*finished)) return std::unexpected(ServerFlightError::crypto_error);
        auto application=[&]() -> std::expected<ApplicationRecords,ServerFlightError> {
            auto transcript_hash=keys.transcript.snapshot(); auto master=master_secret(keys.hash,keys.handshake_secret.view());
            if (!transcript_hash || !master) return std::unexpected(ServerFlightError::crypto_error);
            auto ct=derive_secret(keys.hash,master->view(),"c ap traffic",*transcript_hash), st=derive_secret(keys.hash,master->view(),"s ap traffic",*transcript_hash);
            if (!ct || !st) return std::unexpected(ServerFlightError::crypto_error);
            auto ck=expand_label(keys.hash,ct->view(),"key",{},key_size), ci=expand_label(keys.hash,ct->view(),"iv",{},12);
            auto sk=expand_label(keys.hash,st->view(),"key",{},key_size), si=expand_label(keys.hash,st->view(),"iv",{},12);
            if (!ck || !ci || !sk || !si) return std::unexpected(ServerFlightError::crypto_error);
            auto read=RecordLayer::create(RecordDirection::receive,algorithm,ck->view(),ci->view());
            auto write=RecordLayer::create(RecordDirection::send,algorithm,sk->view(),si->view());
            if (!read || !write) return std::unexpected(ServerFlightError::crypto_error);
            return ApplicationRecords(std::move(*write),std::move(*read),16385,16385,keys.hash,algorithm,key_size,std::move(*st),std::move(*ct),ApplicationRole::server);
        }();
        if (!application) return std::unexpected(application.error());
        std::vector<crypto::Bytes> records;
        auto total=extensions.size()+certificate->size()+signature->size()+finished->size();
        records.reserve((total+16383)/16384);
        std::array<std::uint8_t,16384> fragment{}; std::size_t used=0;
        for (auto const* message:{&extensions,&*certificate,&*signature,&*finished}) {
            auto bytes=std::span<std::uint8_t const>{*message};
            while (!bytes.empty()) {
                auto count=std::min(fragment.size()-used,bytes.size());
                std::copy_n(bytes.begin(),count,fragment.begin()+static_cast<std::ptrdiff_t>(used));
                used+=count; bytes=bytes.subspan(count);
                if (used==fragment.size()) {
                    auto record=keys.write.seal(ContentType::handshake,fragment);
                    if (!record) return std::unexpected(ServerFlightError::crypto_error);
                    records.push_back(std::move(*record)); used=0;
                }
            }
        }
        if (used) {
            auto record=keys.write.seal(ContentType::handshake,std::span{fragment}.first(used));
            if (!record) return std::unexpected(ServerFlightError::crypto_error);
            records.push_back(std::move(*record));
        }
        auto decoder=HandshakeDecoder::create(48); if (!decoder) return std::unexpected(ServerFlightError::crypto_error);
        ServerFlight flight(std::move(keys),std::move(*application),std::move(records));
        flight.decoder_.emplace(std::move(*decoder)); return flight;
    }
    auto ServerFlight::client_finished(std::span<std::uint8_t const> record) -> std::expected<bool,ServerFlightError> {
        if (state_!=State::awaiting_finished) return std::unexpected(ServerFlightError::invalid_state);
        auto fail=[this](ServerFlightError error) -> std::unexpected<ServerFlightError> {
            state_=State::failed; keys_.reset(); decoder_.reset(); application_.reset(); return std::unexpected(error);
        };
        try {
        auto plain=keys_->read.open(record);
        if (!plain || plain->type!=ContentType::handshake || plain->content.empty()) return fail(ServerFlightError::invalid_finished);
        auto messages=decoder_->feed(plain->content,1);
        if (!messages || messages->size()>1 || (!messages->empty() && decoder_->pending_bytes())) return fail(ServerFlightError::invalid_finished);
        if (messages->empty()) return false;
        auto const& message=messages->front();
        auto size=keys_->hash==crypto::Hash::sha256 ? 32u : 48u;
        if (message.type!=20 || message.body.size()!=size) return fail(ServerFlightError::invalid_finished);
        auto hash=keys_->transcript.snapshot(); if (!hash) return fail(ServerFlightError::crypto_error);
        auto verify=finished_verify_data(keys_->hash,keys_->client_traffic.view(),*hash);
        if (!verify) return fail(ServerFlightError::crypto_error);
        if (!crypto::constant_time_equal(verify->view(),message.body)) return fail(ServerFlightError::invalid_finished);
        // No later operation consumes the handshake transcript or keys.
        keys_.reset(); decoder_.reset(); state_=State::complete; return true;
        } catch (...) { (void)fail(ServerFlightError::crypto_error); throw; }
    }
    auto ServerFlight::take_application_records() -> std::expected<ApplicationRecords,ServerFlightError> {
        if (state_!=State::complete || !application_) return std::unexpected(ServerFlightError::invalid_state);
        auto app=std::move(*application_); application_.reset(); return app;
    }
}
