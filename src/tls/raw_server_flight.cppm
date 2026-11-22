export module tls.raw_server_flight;
export import tls.server_keys;
export import tls.server_credential;
export import tls.flight_types;
export import tls.handshake_policy;
import tls.server_hello;
import tls.handshake;
import std;

export namespace tls {
    class RawServerFlight {
        enum class State { awaiting_finished,complete,failed } state_=State::awaiting_finished;
        struct FinishedSecrets { crypto::Hash hash; Transcript transcript; Secret client; };
        std::optional<FinishedSecrets> keys_;
        explicit RawServerFlight(HandshakeSecrets&& keys) noexcept;
        auto fail(RawServerError error) noexcept -> std::unexpected<RawServerError>;
    public:
        RawServerFlight(RawServerFlight const&)=delete;
        auto operator=(RawServerFlight const&) -> RawServerFlight& = delete;
        RawServerFlight(RawServerFlight&&) noexcept;
        auto operator=(RawServerFlight&&) noexcept -> RawServerFlight&;
        // Caller must send raw ServerHello at Initial level before consuming
        // these keys; this builder drops that no-longer-needed byte storage.
        template<class... Recovery>
        [[nodiscard]] auto client_finished(std::span<std::uint8_t const> message,Recovery&... recovery) -> std::expected<void,RawServerError> {
            if (!awaiting_finished()) return std::unexpected(RawServerError{ServerFlightError::invalid_state});
            if (message.size()<4 || ((std::size_t{message[1]}<<16)|(std::size_t{message[2]}<<8)|message[3])!=message.size()-4)
                return fail({ServerFlightError::invalid_finished,50});
            return client_finished(message[0],message.subspan(4),recovery...);
        }
        auto cancel() noexcept -> void;
        [[nodiscard]] auto complete() const noexcept -> bool;
        [[nodiscard]] auto awaiting_finished() const noexcept -> bool;

        template<class... Recovery>
        static inline auto create(ServerHandshakeSecrets&& input,ServerCredential const& credential,std::array<crypto::Bytes,4>& messages,std::optional<TrafficSecrets>& output_secrets,std::span<std::uint8_t const> selected_alpn={},
        std::optional<std::span<std::uint8_t const>> quic_parameters={},Recovery&... recovery) -> std::expected<RawServerFlight,RawServerError>{
        using Policy=RecoveryPolicy<Recovery...>;
        auto raw=std::move(input); auto& keys=raw.secrets; auto cert=credential.certificate();
        constexpr auto list_limit=ServerCredential::max_certificate_list_size;
        if constexpr(Policy::enabled) {
            if (!recovery_policy(recovery...).selected() && (!std::ranges::contains(credential.signature_schemes(),raw.signature_scheme) || cert.empty() || cert.size()>list_limit-5)) return std::unexpected(RawServerError{ServerFlightError::invalid_credential});
        } else if (!std::ranges::contains(credential.signature_schemes(),raw.signature_scheme) || cert.empty() || cert.size()>list_limit-5)
            return std::unexpected(RawServerError{ServerFlightError::invalid_credential});
        if (raw.server_hello.size()<4 || raw.server_hello[0]!=2 ||
            ((std::size_t{raw.server_hello[1]}<<16)|(std::size_t{raw.server_hello[2]}<<8)|raw.server_hello[3])!=raw.server_hello.size()-4)
            return std::unexpected(RawServerError{ServerFlightError::crypto_error});
        {
            auto hello=ServerHello::parse(std::span(raw.server_hello).subspan(4));
            if (!hello || hello->cipher_suite!=keys.cipher_suite || !cipher_spec(keys.cipher_suite)) return std::unexpected(RawServerError{ServerFlightError::crypto_error});
        }
        crypto::Bytes{}.swap(raw.server_hello);
        auto extensions=encode_encrypted_extensions(selected_alpn,quic_parameters);
        if (!extensions) return std::unexpected(RawServerError{ServerFlightError::invalid_state,static_cast<std::uint8_t>(extensions.error()==HandshakePolicyError::invalid_alpn ? 120 : 80)});
        if (!keys.transcript.append(*extensions)) return std::unexpected(RawServerError{ServerFlightError::crypto_error});
        if ([&]() __attribute__((always_inline)) {if constexpr(Policy::enabled)return !recovery_policy(recovery...).selected();else return true;}()) {
        std::size_t list_size=cert.size()+5;
        for (auto const& intermediate:credential.chain()) {
            if (intermediate.empty() || intermediate.size()>list_limit-5 || list_size>list_limit-intermediate.size()-5)
                return std::unexpected(RawServerError{ServerFlightError::invalid_credential});
            list_size+=intermediate.size()+5;
        }
        auto put24=[](crypto::Bytes& out,std::size_t n) { out.push_back(static_cast<std::uint8_t>(n>>16)); out.push_back(static_cast<std::uint8_t>(n>>8)); out.push_back(static_cast<std::uint8_t>(n)); };
        crypto::Bytes body; body.reserve(list_size+4); body.push_back(0); put24(body,list_size);
        auto append_cert=[&](std::span<std::uint8_t const> value) { put24(body,value.size()); body.insert(body.end(),value.begin(),value.end()); body.insert(body.end(),{0,0}); };
        append_cert(cert); for (auto const& intermediate:credential.chain()) append_cert(intermediate);
        auto certificate=HandshakeDecoder::encode(11,body,1048580); if (!certificate) return std::unexpected(RawServerError{ServerFlightError::crypto_error});
        crypto::Bytes{}.swap(body);
        if (!keys.transcript.append(*certificate)) return std::unexpected(RawServerError{ServerFlightError::crypto_error});
        auto hash=keys.transcript.snapshot(); if (!hash) return std::unexpected(RawServerError{ServerFlightError::crypto_error});
        auto signature=credential.sign(raw.signature_scheme,keys.hash,*hash); if (!signature || !keys.transcript.append(*signature)) return std::unexpected(RawServerError{ServerFlightError::crypto_error});
            messages[1]=std::move(*certificate);messages[2]=std::move(*signature);
        } else {
            crypto::Bytes{}.swap(messages[1]);crypto::Bytes{}.swap(messages[2]);
        }
        auto hash=keys.transcript.snapshot(); if (!hash) return std::unexpected(RawServerError{ServerFlightError::crypto_error});
        auto verify=finished_verify_data(keys.hash,keys.server_traffic.view(),*hash); if (!verify) return std::unexpected(RawServerError{ServerFlightError::crypto_error});
        auto finished=HandshakeDecoder::encode(20,verify->view()); if (!finished || !keys.transcript.append(*finished)) return std::unexpected(RawServerError{ServerFlightError::crypto_error});
        auto transcript_hash=keys.transcript.snapshot(); if (!transcript_hash) return std::unexpected(RawServerError{ServerFlightError::crypto_error});
        auto application=application_traffic_secrets(keys.cipher_suite,keys.hash,keys.handshake_secret.view(),*transcript_hash,recovery...);
        if (!application) return std::unexpected(RawServerError{ServerFlightError::crypto_error});
        messages[0]=std::move(*extensions);messages[3]=std::move(*finished);
        output_secrets.emplace(std::move(*application));
        return RawServerFlight(std::move(keys));
        }
        template<class... Recovery>
        inline auto client_finished(std::uint8_t type,std::span<std::uint8_t const> body,Recovery&... recovery) -> std::expected<void,RawServerError>{
        using Policy=RecoveryPolicy<Recovery...>;
        if (state_!=State::awaiting_finished) return std::unexpected(RawServerError{ServerFlightError::invalid_state});
        state_=State::failed;
        try {
            auto size=keys_->hash==crypto::Hash::sha256 ? 32u : 48u;
            if (type!=20 || body.size()!=size) return fail({ServerFlightError::invalid_finished,50});
            auto hash=keys_->transcript.snapshot(); if (!hash) return fail({ServerFlightError::crypto_error});
            auto verify=finished_verify_data(keys_->hash,keys_->client.view(),*hash);
            if (!verify) return fail({ServerFlightError::crypto_error});
            if (!crypto::constant_time_equal(verify->view(),body)) return fail({ServerFlightError::invalid_finished,51});
            if constexpr(Policy::enabled) {
                auto message=HandshakeDecoder::encode(type,body);if (!message || !keys_->transcript.append(*message)) return fail({ServerFlightError::crypto_error});
                auto complete=keys_->transcript.snapshot();if (!complete)return fail({ServerFlightError::crypto_error});
                auto retained=recovery_policy(recovery...).client_finished(*complete);if (!retained)return fail({ServerFlightError::crypto_error});
            }
            keys_.reset(); state_=State::complete; return {};
        } catch (...) { cancel(); throw; }
        }
    };
}
