export module quic.tls_server;
import std;
import crypto;
import quic.packet_keys;
import quic.tls_common;
import tls.raw_server_flight;
import tls.handshake_policy;
import tls.handshake;
import ngtcp2;

export namespace quic {
    class TlsServer {
        enum class State { hello,retry_hello,finished,completing,complete,failed } state_=State::hello;
        struct ApplicationReadKey { PacketSuite suite; tls::Secret secret; };
        tls::ServerCredential const& credential_;
        std::string_view alpn_;
        std::optional<tls::HandshakeDecoder> decoder_;
        std::optional<tls::RawServerFlight> flight_;
        std::optional<ApplicationReadKey> application_;
        std::optional<tls::Secret> exporter_;
        crypto::Hash cipher_hash_=crypto::Hash::sha256;
        crypto::Bytes first_,retry_;
        std::uint8_t last_alert_=0;
        auto alpn() const noexcept -> std::span<std::uint8_t const> { return {reinterpret_cast<std::uint8_t const*>(alpn_.data()),alpn_.size()}; }
        template<class Connection,class... Recovery> auto fail(Connection& connection,std::uint8_t alert,int code=ngtcp2::err_crypto,Recovery&... recovery) noexcept -> int {
            last_alert_=alert; connection.tls_alert(alert); cancel(recovery...); return code;
        }
        template<class Connection,class... Recovery> auto initial_message(Connection& connection,std::uint8_t type,std::span<std::uint8_t const> wire,Recovery&... recovery) -> int {
            using Resumption=tls::RecoveryPolicy<Recovery...>;
            using namespace ngtcp2;
            if ((state_!=State::hello && state_!=State::retry_hello) || type!=1) return fail(connection,10,ngtcp2::err_crypto,recovery...);
            auto client=tls::ClientHello::parse(wire.subspan(4),65535); if (!client) return fail(connection,50,ngtcp2::err_crypto,recovery...);
            auto parameters=tls::quic_client_parameters<Resumption::enabled>(*client,alpn());
            if (!parameters) return fail(connection,parameters.error()==tls::HandshakePolicyError::missing_transport_parameters ? 109 : parameters.error()==tls::HandshakePolicyError::invalid_alpn ? 120 : 47,ngtcp2::err_crypto,recovery...);
            auto framing=parameter_block_status(*parameters); if (framing) return fail(connection,47,framing,recovery...);
            auto schemes=credential_.signature_schemes(); if (schemes.empty()) return fail(connection,80,ngtcp2::err_crypto,recovery...);
            auto raw=state_==State::hello ? tls::server_handshake_secrets(wire,schemes,tls::PeerSignaturePolicy::require_offered,tls_packet_ciphers,tls::HandshakeTransport::quic,recovery...) :
                tls::server_handshake_secrets_retry(first_,retry_,wire,schemes,tls_packet_ciphers,tls::HandshakeTransport::quic,recovery...);
            if (!raw) {
                if (state_!=State::hello || raw.error()!=tls::ServerKeyError::retry_required) return fail(connection,raw.error()==tls::ServerKeyError::crypto_error ? 80 : 40,ngtcp2::err_crypto,recovery...);
                auto response=tls::server_retry_hello(wire,schemes,tls_packet_ciphers,tls::HandshakeTransport::quic,recovery...); if (!response) return fail(connection,response.error()==tls::ServerKeyError::crypto_error ? 80 : 40,ngtcp2::err_crypto,recovery...);
                first_.assign(wire.begin(),wire.end()); retry_=std::move(*response);
                auto error=connection.submit_crypto(NGTCP2_ENCRYPTION_LEVEL_INITIAL,retry_);
                if (error) return fail(connection,80,error,recovery...);
                state_=State::retry_hello; return 0;
            }
            auto suite=tls_packet_suite(raw->secrets.cipher_suite); if (!suite) return fail(connection,47,ngtcp2::err_crypto,recovery...);
            auto error=connection.remote_transport_parameters(*parameters);
            if (!error) error=connection.install_secret(NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,false,*suite,raw->secrets.client_traffic.view());
            if (!error) error=connection.install_secret(NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,true,*suite,raw->secrets.server_traffic.view());
            if (error) return fail(connection,80,error,recovery...);
            auto local=local_quic_parameters(connection); if (!local) return fail(connection,80,local.error(),recovery...);
            error=connection.submit_crypto(NGTCP2_ENCRYPTION_LEVEL_INITIAL,raw->server_hello); if (error) return fail(connection,80,error,recovery...);
            std::array<crypto::Bytes,4> messages;
            std::optional<tls::TrafficSecrets> application;
            auto flight=tls::RawServerFlight::create(std::move(*raw),credential_,messages,application,alpn(),std::span<std::uint8_t const>(*local),recovery...);
            if (!flight) return fail(connection,flight.error().alert,ngtcp2::err_crypto,recovery...);
            error=connection.install_secret(NGTCP2_ENCRYPTION_LEVEL_1RTT,true,*suite,application->server.view());
            if (error) return fail(connection,80,error,recovery...);
            for (auto& message:messages) {
                if constexpr(Resumption::enabled) if (message.empty())continue;
                error=connection.submit_crypto(NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,message);
                if (error) return fail(connection,80,error,recovery...);
                crypto::Bytes{}.swap(message);
            }
            application_.emplace(ApplicationReadKey{*suite,std::move(application->client)}); flight_.emplace(std::move(*flight));
            cipher_hash_=application->hash; exporter_.emplace(std::move(application->exporter));
            crypto::Bytes{}.swap(first_); crypto::Bytes{}.swap(retry_); state_=State::finished; return 0;
        }
        template<class Connection,class... Recovery> auto finished_message(Connection& connection,std::uint8_t type,std::span<std::uint8_t const> wire,Recovery&... recovery) -> int {
            using Resumption=tls::RecoveryPolicy<Recovery...>;
            using namespace ngtcp2;
            if (state_!=State::finished || type!=20) return fail(connection,10,ngtcp2::err_crypto,recovery...);
            auto verified=flight_->client_finished(wire,recovery...); if (!verified) return fail(connection,verified.error().alert,ngtcp2::err_crypto,recovery...);
            auto error=connection.install_secret(NGTCP2_ENCRYPTION_LEVEL_1RTT,false,application_->suite,application_->secret.view());
            if (error) return fail(connection,80,error,recovery...);
            flight_.reset(); application_.reset(); state_=State::completing; return 0;
        }
    public:
        TlsServer(tls::ServerCredential const& credential,std::string_view required_alpn) noexcept : credential_(credential),alpn_(required_alpn) {}
        TlsServer(TlsServer const&)=delete;
        auto operator=(TlsServer const&) -> TlsServer& = delete;
        TlsServer(TlsServer&&)=delete;
        auto operator=(TlsServer&&) -> TlsServer& = delete;
        auto complete() const noexcept -> bool { return state_==State::complete; }
        auto alert() const noexcept -> std::uint8_t { return last_alert_; }
        auto pending_handshake_bytes() const noexcept -> std::size_t { return decoder_ ? decoder_->pending_bytes() : 0; }
        struct ExporterMaster { crypto::Hash hash; std::span<std::uint8_t const> secret; };
        [[nodiscard]] auto exporter_master() const noexcept -> std::optional<ExporterMaster> {
            return exporter_ ? std::optional(ExporterMaster{cipher_hash_,exporter_->view()}) : std::nullopt;
        }
        template<class... Recovery> auto cancel(Recovery&... recovery) noexcept -> void {
            using Resumption=tls::RecoveryPolicy<Recovery...>;
            if constexpr(Resumption::enabled) tls::recovery_policy(recovery...).cancel();
            state_=State::failed; flight_.reset(); application_.reset(); decoder_.reset(); exporter_.reset(); crypto::Bytes{}.swap(first_); crypto::Bytes{}.swap(retry_);
        }
        template<class Connection,class... Recovery> auto start(Connection&,Recovery&... recovery) -> int {
            using Resumption=tls::RecoveryPolicy<Recovery...>; return ngtcp2::err_callback_failure; } // Client-only callback is never used.
        template<class Connection,class... Recovery> auto receive(Connection& connection,ngtcp2::ngtcp2_encryption_level level,std::uint64_t,std::span<std::uint8_t const> bytes,Recovery&... recovery) -> int {
            using Resumption=tls::RecoveryPolicy<Recovery...>;
            using namespace ngtcp2;
            try {
                if ((state_==State::hello || state_==State::retry_hello) && level==NGTCP2_ENCRYPTION_LEVEL_INITIAL) {
                    if (!decoder_) {
                        auto decoder=tls::HandshakeDecoder::create(65535); if (!decoder) return fail(connection,80,ngtcp2::err_crypto,recovery...);
                        decoder_.emplace(std::move(*decoder));
                    }
                    auto error=feed_tls_messages(*decoder_,bytes,1,[&](auto type,auto wire) { return initial_message(connection,type,wire,recovery...); });
                    if (error) return state_==State::failed ? error : fail(connection,50,error,recovery...);
                    if (state_==State::finished) {
                        if (decoder_->pending_bytes()) return fail(connection,10,ngtcp2::err_crypto,recovery...);
                        auto decoder=tls::HandshakeDecoder::create(48); if (!decoder) return fail(connection,80,ngtcp2::err_crypto,recovery...);
                        decoder_.emplace(std::move(*decoder));
                    }
                    return 0;
                }
                if (state_==State::finished && level==NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE) {
                    auto error=feed_tls_messages(*decoder_,bytes,1,[&](auto type,auto wire) { return finished_message(connection,type,wire,recovery...); });
                    if (error) return state_==State::failed ? error : fail(connection,50,error,recovery...);
                    if (state_==State::completing) {
                        if (decoder_->pending_bytes()) return fail(connection,10,ngtcp2::err_crypto,recovery...);
                        decoder_.reset(); state_=State::complete;
                        error=connection.complete_handshake(); if (error) return fail(connection,80,error,recovery...);
                    }
                    return 0;
                }
                return fail(connection,10,ngtcp2::err_crypto,recovery...);
            } catch (...) { cancel(recovery...); throw; }
        }
    };
}
