export module quic.tls_client;
import std;
import crypto;
import quic.packet_keys;
import quic.tls_common;
import quic.ech_client;
import quic.ech_config;
import tls.client_hello_exchange;
import tls.raw_client_flight;
import tls.certificate_compression;
import tls.handshake_policy;
import tls.handshake;
import tls.hello_config;
import tls.post_handshake;
import tls.server_credential;
import nexus.thirdparty.ngtcp2;

export namespace quic {
    // CertificatePolicy is a direct concrete member; it authenticates the
    // parsed chain while the shared TLS core verifies CertificateVerify and
    // Finished. The profile, policy's borrowed data and ALPN outlive this owner.
    template<class CertificatePolicy>
    class TlsClient {
        enum class State { initial,hello,flight,completing,complete,failed } state_=State::initial;
        std::optional<tls::ClientHello> template_;
        CertificatePolicy policy_;
        std::string_view alpn_;
        std::array<std::uint16_t,2> groups_{};
        std::uint8_t group_count_=0;
        std::optional<tls::ClientHelloExchange> exchange_;
        std::optional<tls::RawClientFlight> flight_;
        std::optional<tls::HandshakeDecoder> decoder_;
        std::optional<tls::Secret> exporter_;
        std::unique_ptr<EchClient> ech_;
        crypto::Hash cipher_hash_=crypto::Hash::sha256;
        std::uint16_t cipher_suite_=0;
        std::uint8_t expected_message_=8,last_alert_=0;
        auto alpn() const noexcept -> std::span<std::uint8_t const> { return {reinterpret_cast<std::uint8_t const*>(alpn_.data()),alpn_.size()}; }
        template<class Connection,class... Recovery> auto fail(Connection& connection,std::uint8_t alert,int code=nex::ngtcp2::err_crypto,Recovery&... recovery) noexcept -> int {
            last_alert_=alert; connection.tls_alert(alert); cancel(recovery...); return code;
        }
        template<class Connection,class... Recovery> auto initial_message(Connection& connection,std::uint8_t type,std::span<std::uint8_t const> wire,Recovery&... recovery) -> int {
            using Resumption=tls::RecoveryPolicy<Recovery...>;
            using namespace nex::ngtcp2;
            if (state_!=State::hello || type!=2) return fail(connection,10,nex::ngtcp2::err_crypto,recovery...);
            if (ech_) {
                auto transcript=exchange_->hello_transcript();
                auto accepted=verify_ech_acceptance(transcript.first,wire,transcript.retry,transcript.second);
                if (!accepted) {
                    auto alert=accepted.error()==EchHandshakeError::rejected ? 121 :
                        accepted.error()==EchHandshakeError::crypto ? 80 : 50;
                    return fail(connection,alert,nex::ngtcp2::err_crypto,recovery...);
                }
            }
            auto received=exchange_->receive(wire,recovery...); if (!received) return fail(connection,received.error()==tls::ClientHelloDriverError::crypto_error ? 80 : 47,nex::ngtcp2::err_crypto,recovery...);
            if (!received->server_hello) {
                if constexpr(tls::EarlyDataPolicy<Resumption>) {
                    if (tls::recovery_policy(recovery...).offered_early()) {
                        auto status=connection.resolve_client_early_data(false);
                        if (status) return fail(connection,80,status,recovery...);
                    }
                }
                auto outbound=received->outbound;
                std::vector<std::uint8_t> outer;
                if (ech_) {
                    auto sealed=ech_->seal(exchange_->current_hello(),true);
                    if (!sealed) return fail(connection,80,nex::ngtcp2::err_crypto,recovery...);
                    outer=std::move(*sealed);
                    outbound=outer;
                }
                auto error=connection.submit_crypto(NGTCP2_ENCRYPTION_LEVEL_INITIAL,outbound);
                if (error) return fail(connection,80,error,recovery...);
                if (!exchange_->retry_sent()) return fail(connection,80,nex::ngtcp2::err_crypto,recovery...);
                return 0;
            }
            ech_.reset();
            auto raw=exchange_->take_flight(recovery...); if (!raw) return fail(connection,raw.error()==tls::ClientHelloDriverError::crypto_error ? 80 : 47,nex::ngtcp2::err_crypto,recovery...);
            auto keys=raw->handshake_secrets(); if (!keys) return fail(connection,80,nex::ngtcp2::err_crypto,recovery...);
            auto suite=tls_packet_suite(keys->cipher_suite); if (!suite) return fail(connection,47,nex::ngtcp2::err_crypto,recovery...);
            auto error=connection.install_secret(NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,false,*suite,keys->server);
            if (!error) error=connection.install_secret(NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,true,*suite,keys->client);
            if (error) return fail(connection,80,error,recovery...);
            cipher_suite_=keys->cipher_suite;
            flight_.emplace(std::move(*raw)); exchange_.reset(); state_=State::flight; return 0;
        }
        template<class Connection,class... Recovery> auto flight_message(Connection& connection,std::uint8_t type,std::span<std::uint8_t const> wire,Recovery&... recovery) -> int {
            using Resumption=tls::RecoveryPolicy<Recovery...>;
            using namespace nex::ngtcp2;
            auto compressed=expected_message_==11 && type==tls::compressed_certificate_message;
            if (state_!=State::flight || (type!=expected_message_ && !compressed)) return fail(connection,10,nex::ngtcp2::err_crypto,recovery...);
            if (type==8) {
                auto extensions=flight_->quic_encrypted_extensions(wire,alpn(),recovery...);
                if (!extensions) return fail(connection,extensions.error().alert,nex::ngtcp2::err_crypto,recovery...);
                if constexpr(tls::EarlyDataPolicy<Resumption>) {
                    auto& policy=tls::recovery_policy(recovery...);
                    if (extensions->accepted_early && (!policy.offered_early() || !policy.selected() ||
                        cipher_suite_!=policy.early_suite()))
                        return fail(connection,47,err_crypto,recovery...);
                    if (policy.offered_early()) {
                        auto status=connection.resolve_client_early_data(extensions->accepted_early);
                        if (status) return fail(connection,80,status,recovery...);
                    }
                }
                auto error=parameter_block_status(extensions->transport_parameters);
                if (!error) error=connection.remote_transport_parameters(extensions->transport_parameters);
                if (error) return fail(connection,47,error,recovery...);
                if constexpr(Resumption::enabled) expected_message_=tls::recovery_policy(recovery...).selected() ? 20 : 11;
                else expected_message_=11;
                return 0;
            }
            if (type==11 || compressed) {
                auto result=flight_->certificate_with(wire,policy_,tls::ServerCredential::max_certificate_list_size+4);
                if (!result) return fail(connection,result.error().alert,nex::ngtcp2::err_crypto,recovery...);
                expected_message_=15; return 0;
            }
            if (type==15) {
                auto result=flight_->certificate_verify(wire);
                if (!result) return fail(connection,result.error().alert,nex::ngtcp2::err_crypto,recovery...);
                expected_message_=20; return 0;
            }
            auto secrets=flight_->server_finished(wire,recovery...); if (!secrets) return fail(connection,secrets.error().alert,nex::ngtcp2::err_crypto,recovery...);
            auto finished=flight_->client_finished(recovery...); if (!finished) return fail(connection,finished.error().alert,nex::ngtcp2::err_crypto,recovery...);
            auto suite=tls_packet_suite(secrets->cipher_suite); if (!suite) return fail(connection,47,nex::ngtcp2::err_crypto,recovery...);
            auto error=connection.submit_crypto(NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,*finished);
            if (!error) error=connection.install_secret(NGTCP2_ENCRYPTION_LEVEL_1RTT,false,*suite,secrets->server.view());
            if (!error) error=connection.install_secret(NGTCP2_ENCRYPTION_LEVEL_1RTT,true,*suite,secrets->client.view());
            if (error) return fail(connection,80,error,recovery...);
            cipher_hash_=secrets->hash; exporter_.emplace(std::move(secrets->exporter));
            if constexpr(Resumption::enabled) {
                auto sent=tls::recovery_policy(recovery...).finished_sent();if (!sent) return fail(connection,80,nex::ngtcp2::err_crypto,recovery...);
            }
            flight_.reset(); state_=State::completing; return 0;
        }
    public:
        TlsClient(tls::ClientHello hello,std::uint16_t group,CertificatePolicy policy,std::string_view required_alpn)
            : template_(std::move(hello)),policy_(std::move(policy)),alpn_(required_alpn),groups_{group,0},group_count_(group ? 1 : 0) {}
        TlsClient(tls::ClientHello hello,std::span<std::uint16_t const> groups,CertificatePolicy policy,std::string_view required_alpn)
            : template_(std::move(hello)),policy_(std::move(policy)),alpn_(required_alpn),group_count_(groups.size()>2 ? 3 : static_cast<std::uint8_t>(groups.size())) {
            if (group_count_<=2) std::ranges::copy(groups,groups_.begin());
        }
        TlsClient(TlsClient const&)=delete;
        auto operator=(TlsClient const&) -> TlsClient& = delete;
        TlsClient(TlsClient&&)=delete;
        auto operator=(TlsClient&&) -> TlsClient& = delete;
        auto complete() const noexcept -> bool { return state_==State::complete; }
        auto alert() const noexcept -> std::uint8_t { return last_alert_; }
        [[nodiscard]] auto enable_ech(EchConfig const& config) -> bool {
            if (state_!=State::initial || ech_) return false;
            auto client=EchClient::create(config);
            if (!client) return false;
            ech_=std::make_unique<EchClient>(std::move(*client));
            return true;
        }
        auto pending_handshake_bytes() const noexcept -> std::size_t { return decoder_ ? decoder_->pending_bytes() : 0; }
        struct ExporterMaster { crypto::Hash hash; std::span<std::uint8_t const> secret; };
        [[nodiscard]] auto exporter_master() const noexcept -> std::optional<ExporterMaster> {
            return exporter_ ? std::optional(ExporterMaster{cipher_hash_,exporter_->view()}) : std::nullopt;
        }
        template<class... Recovery> auto cancel(Recovery&... recovery) noexcept -> void {
            using Resumption=tls::RecoveryPolicy<Recovery...>;
            if constexpr(Resumption::enabled) tls::recovery_policy(recovery...).cancel(); state_=State::failed; template_.reset(); exchange_.reset(); flight_.reset(); decoder_.reset(); exporter_.reset(); ech_.reset(); }
        template<class Connection,class... Recovery> auto start(Connection& connection,Recovery&... recovery) -> int {
            using Resumption=tls::RecoveryPolicy<Recovery...>;
            using namespace nex::ngtcp2;
            if (state_!=State::initial || !template_) return err_callback_failure;
            try {
                auto& hello=*template_;
                if constexpr(Resumption::enabled) {
                    static_assert(requires {policy_.resumption_binding(hello,alpn());}, "QUIC recovery requires an identity-bound certificate policy");
                    auto binding=policy_.resumption_binding(hello,alpn());
                    if (!binding || *binding!=tls::recovery_policy(recovery...).binding()) return fail(connection,
                        !binding && Resumption::local_error(binding.error()) ? 80 : 47,nex::ngtcp2::err_crypto,recovery...);
                }
                if (group_count_>2 || !hello.session_id.empty() || hello.cipher_suites.empty() ||
                    !std::ranges::all_of(hello.cipher_suites,[](auto suite) { return std::ranges::contains(tls_packet_ciphers,suite) || tls::is_grease(suite); })) return fail(connection,47,nex::ngtcp2::err_crypto,recovery...);
                auto template_size=hello.encoding_size(); if (!template_size) return fail(connection,47,nex::ngtcp2::err_crypto,recovery...);
                auto parameters=local_quic_parameters(connection); if (!parameters) return fail(connection,80,parameters.error(),recovery...);
                auto existing=std::ranges::find(hello.extensions,std::uint16_t{0x39},&tls::Extension::type);
                if (existing==hello.extensions.end()) hello.extensions.push_back({0x39,std::move(*parameters)}); else existing->data=std::move(*parameters);
                if (hello.extension(21) && !tls::repad_client_hello(hello,*template_size)) return fail(connection,47,nex::ngtcp2::err_crypto,recovery...);
                if (ech_) {
                    if (Resumption::enabled || hello.extension(ech_extension))
                        return fail(connection,47,nex::ngtcp2::err_crypto,recovery...);
                    hello.extensions.push_back({ech_extension,{1}});
                }
                auto valid=tls::quic_client_parameters<Resumption::enabled,tls::EarlyDataPolicy<Resumption>>(hello,alpn()); if (!valid) return fail(connection,valid.error()==tls::HandshakePolicyError::invalid_alpn ? 120 : 47,nex::ngtcp2::err_crypto,recovery...);
                auto exchange=tls::ClientHelloExchange::create(std::move(hello),std::span(groups_).first(group_count_),tls::HandshakeTransport::quic,recovery...); template_.reset(); if (!exchange) return fail(connection,exchange.error()==tls::ClientHelloDriverError::crypto_error ? 80 : 47,nex::ngtcp2::err_crypto,recovery...);
                auto decoder=tls::HandshakeDecoder::create(65535); if (!decoder) return fail(connection,80,nex::ngtcp2::err_crypto,recovery...);
                exchange_.emplace(std::move(*exchange)); decoder_.emplace(std::move(*decoder));
                auto outbound=exchange_->initial();
                std::vector<std::uint8_t> outer;
                if (ech_) {
                    auto sealed=ech_->seal(exchange_->first_hello());
                    if (!sealed) return fail(connection,80,nex::ngtcp2::err_crypto,recovery...);
                    outer=std::move(*sealed);
                    outbound=outer;
                }
                if constexpr(tls::EarlyDataPolicy<Resumption>) {
                    auto& policy=tls::recovery_policy(recovery...);
                    if (policy.offered_early()) {
                        auto suite=tls_packet_suite(policy.early_suite());
                        auto secret=policy.early_traffic(outbound);
                        if (!suite || !secret) return fail(connection,80,err_crypto,recovery...);
                        auto status=connection.install_client_early_data(*suite,secret->view(),policy.early_parameters());
                        if (status) return fail(connection,80,status,recovery...);
                    }
                }
                auto error=connection.submit_crypto(NGTCP2_ENCRYPTION_LEVEL_INITIAL,outbound);
                if (error) return fail(connection,80,error,recovery...);
                if (!exchange_->initial_sent()) return fail(connection,80,nex::ngtcp2::err_crypto,recovery...);
                state_=State::hello; return 0;
            } catch (...) { cancel(recovery...); throw; }
        }
        template<class Connection,class... Recovery> auto receive(Connection& connection,nex::ngtcp2::ngtcp2_encryption_level level,std::uint64_t,std::span<std::uint8_t const> bytes,Recovery&... recovery) -> int {
            using Resumption=tls::RecoveryPolicy<Recovery...>;
            using namespace nex::ngtcp2;
            try {
                if (state_==State::hello && level==NGTCP2_ENCRYPTION_LEVEL_INITIAL) {
                    auto error=feed_tls_messages(*decoder_,bytes,1,[&](auto type,auto wire) { return initial_message(connection,type,wire,recovery...); });
                    if (error) return state_==State::failed ? error : fail(connection,50,error,recovery...);
                    if (state_==State::flight) {
                        if (decoder_->pending_bytes()) return fail(connection,10,nex::ngtcp2::err_crypto,recovery...);
                        auto decoder=tls::HandshakeDecoder::create(tls::ServerCredential::max_certificate_list_size+4);
                        if (!decoder) return fail(connection,80,nex::ngtcp2::err_crypto,recovery...);
                        decoder_.emplace(std::move(*decoder));
                    }
                    return 0;
                }
                if (state_==State::flight && level==NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE) {
                    auto error=feed_tls_messages(*decoder_,bytes,4,[&](auto type,auto wire) { return flight_message(connection,type,wire,recovery...); });
                    if (error) return state_==State::failed ? error : fail(connection,50,error,recovery...);
                    if (state_==State::completing) {
                        if (decoder_->pending_bytes()) return fail(connection,10,nex::ngtcp2::err_crypto,recovery...);
                        auto decoder=tls::HandshakeDecoder::create(tls::max_new_session_ticket); if (!decoder) return fail(connection,80,nex::ngtcp2::err_crypto,recovery...);
                        decoder_.emplace(std::move(*decoder)); state_=State::complete;
                        error=connection.complete_handshake(); if (error) return fail(connection,80,error,recovery...);
                    }
                    return 0;
                }
                if (state_==State::complete && level==NGTCP2_ENCRYPTION_LEVEL_1RTT) {
                    auto error=feed_tls_messages(*decoder_,bytes,32,[&](std::uint8_t type,std::span<std::uint8_t const> wire) {
                        if constexpr(Resumption::enabled) {
                            if (type!=4)return fail(connection,10,nex::ngtcp2::err_crypto,recovery...);
                            auto& policy=tls::recovery_policy(recovery...);
                            auto accepted=[&] {
                                if constexpr(tls::EarlyDataPolicy<Resumption>) {
                                    std::array<std::uint8_t,256> parameters;
                                    return policy.ticket(wire.subspan(4),cipher_suite_,connection.early_transport_parameters(parameters));
                                } else {
                                    return policy.ticket(wire.subspan(4));
                                }
                            }();
                            // Fixed ngtcp2 public NGTCP2_ERR_PROTO; RFC9001
                            // requires PROTOCOL_VIOLATION for this sentinel.
                            if (!accepted && Resumption::transport_error(accepted.error())) return fail(connection,0,-203,recovery...);
                            return accepted ? 0 : fail(connection,Resumption::local_error(accepted.error()) ? 80 : 50,nex::ngtcp2::err_crypto,recovery...);
                        } else {
                            if (type!=4)return fail(connection,10,nex::ngtcp2::err_crypto,recovery...);
                            return tls::valid_quic_new_session_ticket(wire.subspan(4)) ? 0 : fail(connection,0,-203,recovery...);
                        }
                    });
                    return error && state_!=State::failed ? fail(connection,50,error,recovery...) : error;
                }
                return fail(connection,10,nex::ngtcp2::err_crypto,recovery...);
            } catch (...) { cancel(recovery...); throw; }
        }
    };
}
