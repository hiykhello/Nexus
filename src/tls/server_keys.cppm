export module tls.server_keys;
export import tls.server_negotiation;
export import tls.record;
export import tls.handshake_secrets;
export import tls.schedule;
export import tls.transcript;
import tls.server_hello;
import tls.handshake;
import tls.hybrid;
import tls.traffic_records;
import tls.ech_server;
export import tls.resumption_policy;
import std;
export namespace tls {
    enum class ServerKeyError { invalid_hello, negotiation_failed, retry_required, invalid_peer, crypto_error, invalid_psk };
    // Handshake epoch only: neither endpoint is authenticated until Finished is verified.
    struct ServerHandshakeKeys {
        crypto::Bytes server_hello;
        std::uint16_t signature_scheme;
        crypto::Hash hash;
        Transcript transcript;
        Secret handshake_secret, client_traffic, server_traffic;
        RecordLayer write, read;
    };
    // The input is the complete, exact ClientHello handshake message, without record headers.
    // The caller must ensure certificate_schemes match its configured certificate and key.
    // X25519 or X25519MLKEM768 retry, without cookies or PSK. Inputs are exact handshake messages.
    [[nodiscard]] auto server_retry_hello(std::span<std::uint8_t const> first,
        std::span<std::uint16_t const> certificate_schemes) -> std::expected<crypto::Bytes,ServerKeyError>;
    struct ServerHandshakeSecrets {
        crypto::Bytes server_hello;
        std::uint16_t signature_scheme;
        HandshakeSecrets secrets;
    };
    namespace detail {
        inline auto server_key_message_body(std::span<std::uint8_t const> wire,std::uint8_t type) -> std::optional<std::span<std::uint8_t const>> {
            if (wire.size()<4 || wire[0]!=type || ((std::size_t{wire[1]}<<16)|(std::size_t{wire[2]}<<8)|wire[3])!=wire.size()-4)return {};return wire.subspan(4);
        }
    }
    template<bool EchAccepted=false,class... Recovery>
    inline auto make_server_secrets(std::span<std::uint8_t const> client_wire, std::span<std::uint16_t const> schemes,
        std::span<std::uint8_t const> first_wire, std::span<std::uint8_t const> retry_wire, PeerSignaturePolicy policy,std::span<std::uint16_t const> permitted_ciphers,HandshakeTransport transport,Recovery&... recovery)
        -> std::expected<ServerHandshakeSecrets,ServerKeyError>{
        using PskPolicy=RecoveryPolicy<Recovery...>;
        auto input=detail::server_key_message_body(client_wire,1); if (!input) return std::unexpected(ServerKeyError::invalid_hello);
        auto client=ClientHello::parse(*input,65535);
        if (!client) return std::unexpected(ServerKeyError::invalid_hello);
        auto selection=negotiate_server<PskPolicy::enabled>(*client,schemes,policy,permitted_ciphers,transport);
        if (!selection) return std::unexpected(ServerKeyError::negotiation_failed);
        if (!selection->x25519_share && !selection->hybrid_share && !selection->ec_share) return std::unexpected(ServerKeyError::retry_required);
        std::conditional_t<PskPolicy::enabled,std::optional<std::span<std::uint8_t const>>,NoPsk> psk_secret;
        if constexpr(PskPolicy::enabled) {
            auto selected=recovery_policy(recovery...).select(*client,client_wire,selection->cipher_suite,first_wire,retry_wire);
            if (!selected) return std::unexpected(PskPolicy::local_error(selected.error()) ? ServerKeyError::crypto_error : ServerKeyError::invalid_psk);
            if (!*selected && !selection->signature_scheme) return std::unexpected(ServerKeyError::negotiation_failed);
            psk_secret=*selected;
        }
        std::optional<crypto::X25519Private> key;
        if (!selection->ec_share) {
            auto generated=crypto::X25519Private::generate(); if (!generated) return std::unexpected(ServerKeyError::crypto_error);
            key.emplace(std::move(*generated));
        }
        std::optional<crypto::Secret32> x_secret; std::optional<HybridServerResult> hybrid;
        std::optional<crypto::EcSecret> ec_secret; crypto::EcPublic ec_public;
        std::array<std::uint8_t,32> public_key{}; std::span<std::uint8_t const> public_share, shared;
        if (selection->group==0x001d && selection->x25519_share) {
            auto value=key->agree(*selection->x25519_share); if (!value) return std::unexpected(value.error()==crypto::Error::backend_failure ? ServerKeyError::crypto_error : ServerKeyError::invalid_peer);
            x_secret.emplace(std::move(*value)); shared=x_secret->view();
            auto value_public=key->public_key(); if (!value_public) return std::unexpected(ServerKeyError::crypto_error);
            public_key=*value_public; public_share=public_key;
        } else if (selection->group==x25519_mlkem768_group && selection->hybrid_share) {
            auto result=hybrid_server_accept(*selection->hybrid_share,std::move(*key));
            if (!result) return std::unexpected(result.error()==HybridError::crypto_error ? ServerKeyError::crypto_error : ServerKeyError::invalid_peer);
            hybrid.emplace(std::move(*result)); shared=hybrid->secret.view();
            public_share=hybrid->share;
        } else if (selection->ec_share && crypto::nist_curve(selection->group)) {
            auto ec_key=crypto::EcPrivate::generate(selection->group); if (!ec_key) return std::unexpected(ServerKeyError::crypto_error);
            auto secret=ec_key->agree(selection->ec_share->view()); if (!secret) return std::unexpected(secret.error()==crypto::Error::invalid_peer ? ServerKeyError::invalid_peer : ServerKeyError::crypto_error);
            auto value=ec_key->public_key(); if (!value) return std::unexpected(ServerKeyError::crypto_error);
            ec_public=*value; public_share=ec_public.view(); ec_secret.emplace(std::move(*secret)); shared=ec_secret->view();
        } else return std::unexpected(ServerKeyError::invalid_hello);
        // The private key is no longer needed once the shared secret and
        // public share have been obtained.
        key.reset();
        auto encoded_share=KeyShare::encode_server_view({selection->group,public_share});
        if (!encoded_share) return std::unexpected(ServerKeyError::crypto_error);
        ServerHello hello; hello.session_id_echo=client->session_id; hello.cipher_suite=selection->cipher_suite;
        hello.extensions={{43,{3,4}},{51,std::move(*encoded_share)}};
        if constexpr(PskPolicy::enabled) if (auto selected=recovery_policy(recovery...).selected_index()) hello.extensions.push_back({41,{static_cast<std::uint8_t>(*selected>>8),static_cast<std::uint8_t>(*selected)}});
        if (!crypto::random_bytes(hello.random) || hello.is_retry()) return std::unexpected(ServerKeyError::crypto_error);
        auto encoded_body=hello.encode(); if (!encoded_body) return std::unexpected(ServerKeyError::crypto_error);
        auto wire=HandshakeDecoder::encode(2,*encoded_body,65535); if (!wire) return std::unexpected(ServerKeyError::crypto_error);
        if constexpr (EchAccepted) {
            auto confirmed=apply_ech_accept_confirmation(
                retry_wire.empty() ? client_wire : first_wire,
                retry_wire,
                retry_wire.empty() ? std::span<std::uint8_t const>{} : client_wire,
                *wire);
            if (!confirmed) return std::unexpected(ServerKeyError::crypto_error);
            *wire=std::move(*confirmed);
        }
        if (!retry_wire.empty()) {
            auto first_body=detail::server_key_message_body(first_wire,1), retry_body=detail::server_key_message_body(retry_wire,2);
            if (!first_body || !retry_body) return std::unexpected(ServerKeyError::invalid_hello);
            auto first=ClientHello::parse(*first_body,65535); auto retry=ServerHello::parse(*retry_body);
            if (!first || !retry || !retry->template validate_retry<PskPolicy::enabled>(*first,*client,hello)) return std::unexpected(ServerKeyError::invalid_hello);
        }
        auto hash=selection->cipher_suite==0x1302 ? crypto::Hash::sha384 : crypto::Hash::sha256;
        auto transcript=Transcript::create(hash);
        if (!transcript || (!retry_wire.empty() && (!transcript->append(first_wire) || !transcript->hello_retry_request() || !transcript->append(retry_wire))) ||
            !transcript->append(client_wire) || !transcript->append(*wire)) return std::unexpected(ServerKeyError::crypto_error);
        auto digest=transcript->snapshot(); auto early=[&]() __attribute__((always_inline)) {if constexpr(PskPolicy::enabled)return early_secret(hash,psk_secret);else return early_secret(hash);}();
        if (!digest || !early) return std::unexpected(ServerKeyError::crypto_error);
        auto hs=handshake_secret(hash,early->view(),shared); if (!hs) return std::unexpected(ServerKeyError::crypto_error);
        // No later computation reads the exchange secret or the early secret.
        shared={}; public_share={}; x_secret.reset(); hybrid.reset(); ec_secret.reset();
        early=std::unexpected(crypto::Error::invalid_state);
        auto ct=derive_secret(hash,hs->view(),"c hs traffic",*digest), st=derive_secret(hash,hs->view(),"s hs traffic",*digest);
        if (!ct || !st) return std::unexpected(ServerKeyError::crypto_error);
        return ServerHandshakeSecrets{std::move(*wire),selection->signature_scheme,
            HandshakeSecrets{selection->cipher_suite,hash,std::move(*transcript),std::move(*hs),std::move(*ct),std::move(*st)}};
        }
    template<class... Recovery>
    inline auto server_retry_hello(std::span<std::uint8_t const> first_wire,std::span<std::uint16_t const> schemes,std::span<std::uint16_t const> permitted_ciphers,HandshakeTransport transport,Recovery&... recovery)
        -> std::expected<crypto::Bytes,ServerKeyError>{
        using PskPolicy=RecoveryPolicy<Recovery...>;
        auto input=detail::server_key_message_body(first_wire,1); if (!input) return std::unexpected(ServerKeyError::invalid_hello);
        auto first=ClientHello::parse(*input,65535); if (!first) return std::unexpected(ServerKeyError::invalid_hello);
        auto selection=negotiate_server<PskPolicy::enabled>(*first,schemes,PeerSignaturePolicy::require_offered,permitted_ciphers,transport); if (!selection) return std::unexpected(ServerKeyError::negotiation_failed);
        if (selection->x25519_share || selection->hybrid_share || selection->ec_share) return std::unexpected(ServerKeyError::invalid_hello);
        ServerHello retry; retry.random={0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
        retry.session_id_echo=first->session_id; retry.cipher_suite=selection->cipher_suite;
        retry.extensions={{43,{3,4}},{51,KeyShare::encode_retry(selection->group)}};
        if (!retry.template validate_retry_request<PskPolicy::enabled>(*first)) return std::unexpected(ServerKeyError::invalid_hello);
        auto encoded=retry.encode(); if (!encoded) return std::unexpected(ServerKeyError::crypto_error);
        auto wire=HandshakeDecoder::encode(2,*encoded,65535); if (!wire) return std::unexpected(ServerKeyError::crypto_error);
        return std::move(*wire);
        }
    template<class Policy> requires(Policy::enabled)
    inline auto server_retry_hello(std::span<std::uint8_t const> first,std::span<std::uint16_t const> schemes,Policy& policy)
        -> std::expected<crypto::Bytes,ServerKeyError> {return server_retry_hello(first,schemes,{},HandshakeTransport::tcp,policy);}
    template<class... Recovery>
    inline auto server_handshake_secrets_retry(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,std::span<std::uint8_t const> second,
        std::span<std::uint16_t const> schemes,std::span<std::uint16_t const> permitted_ciphers={},HandshakeTransport transport=HandshakeTransport::tcp,Recovery&... recovery) -> std::expected<ServerHandshakeSecrets,ServerKeyError>{
        using PskPolicy=RecoveryPolicy<Recovery...>;
        if (first.empty() || retry.empty()) return std::unexpected(ServerKeyError::invalid_hello);
        auto expected=server_retry_hello(first,schemes,permitted_ciphers,transport,recovery...);
        if (!expected) return std::unexpected(expected.error());
        if (!std::ranges::equal(*expected,retry)) return std::unexpected(ServerKeyError::invalid_hello);
        return make_server_secrets(second,schemes,first,retry,PeerSignaturePolicy::require_offered,permitted_ciphers,transport,recovery...);
        }
    inline auto server_record_keys(ServerHandshakeSecrets&& raw) -> std::expected<ServerHandshakeKeys,ServerKeyError> {
        auto& secrets=raw.secrets;
        auto records=traffic_records(secrets.cipher_suite,secrets.client_traffic.view(),secrets.server_traffic.view(),true);
        if (!records) return std::unexpected(ServerKeyError::crypto_error);
        return ServerHandshakeKeys{std::move(raw.server_hello),raw.signature_scheme,secrets.hash,std::move(secrets.transcript),std::move(secrets.handshake_secret),
            std::move(secrets.client_traffic),std::move(secrets.server_traffic),std::move(records->write),std::move(records->read)};
    }
    template<class... Recovery>
    inline auto server_handshake_secrets(std::span<std::uint8_t const> client,std::span<std::uint16_t const> schemes,
        PeerSignaturePolicy policy=PeerSignaturePolicy::require_offered,std::span<std::uint16_t const> permitted_ciphers={},HandshakeTransport transport=HandshakeTransport::tcp,Recovery&... recovery)
        -> std::expected<ServerHandshakeSecrets,ServerKeyError> {
        return make_server_secrets(client,schemes,{},{},policy,permitted_ciphers,transport,recovery...);
    }
    template<class... Recovery>
    inline auto server_handshake_keys(std::span<std::uint8_t const> client,std::span<std::uint16_t const> schemes,
        PeerSignaturePolicy signature_policy=PeerSignaturePolicy::require_offered,Recovery&... recovery) -> std::expected<ServerHandshakeKeys,ServerKeyError> {
        using PskPolicy=RecoveryPolicy<Recovery...>;
        auto secrets=server_handshake_secrets(client,schemes,signature_policy,{},HandshakeTransport::tcp,recovery...);
        if (!secrets)return std::unexpected(secrets.error());return server_record_keys(std::move(*secrets));
    }
    template<class... Recovery>
    inline auto server_handshake_keys_retry(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,
        std::span<std::uint8_t const> second,std::span<std::uint16_t const> schemes,Recovery&... recovery) -> std::expected<ServerHandshakeKeys,ServerKeyError> {
        using PskPolicy=RecoveryPolicy<Recovery...>;
        auto secrets=server_handshake_secrets_retry(first,retry,second,schemes,{},HandshakeTransport::tcp,recovery...);
        if (!secrets)return std::unexpected(secrets.error());return server_record_keys(std::move(*secrets));
    }
    template<class... Recovery>
    inline auto server_retry_hello_ech(std::span<std::uint8_t const> first,std::span<std::uint16_t const> schemes,Recovery&... recovery)
        -> std::expected<crypto::Bytes,ServerKeyError> {
        auto raw=server_retry_hello(first,schemes,{},HandshakeTransport::tcp,recovery...);
        if (!raw) return std::unexpected(raw.error());
        auto confirmed=apply_ech_hrr_confirmation(first,*raw);
        if (!confirmed) return std::unexpected(ServerKeyError::crypto_error);
        return std::move(*confirmed);
    }
    template<class... Recovery>
    inline auto server_handshake_keys_ech(std::span<std::uint8_t const> client,std::span<std::uint16_t const> schemes,
        PeerSignaturePolicy signature_policy=PeerSignaturePolicy::require_offered,Recovery&... recovery) -> std::expected<ServerHandshakeKeys,ServerKeyError> {
        auto secrets=make_server_secrets<true>(client,schemes,{},{},signature_policy,{},HandshakeTransport::tcp,recovery...);
        if (!secrets) return std::unexpected(secrets.error());
        return server_record_keys(std::move(*secrets));
    }
    template<class... Recovery>
    inline auto server_handshake_keys_retry_ech(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,
        std::span<std::uint8_t const> second,std::span<std::uint16_t const> schemes,Recovery&... recovery) -> std::expected<ServerHandshakeKeys,ServerKeyError> {
        if (first.empty() || retry.empty()) return std::unexpected(ServerKeyError::invalid_hello);
        auto expected=server_retry_hello_ech(first,schemes,recovery...);
        if (!expected) return std::unexpected(expected.error());
        if (!std::ranges::equal(*expected,retry)) return std::unexpected(ServerKeyError::invalid_hello);
        auto secrets=make_server_secrets<true>(second,schemes,first,retry,PeerSignaturePolicy::require_offered,{},HandshakeTransport::tcp,recovery...);
        if (!secrets) return std::unexpected(secrets.error());
        return server_record_keys(std::move(*secrets));
    }
    [[nodiscard]] auto server_retry_hello(std::span<std::uint8_t const> first,std::span<std::uint16_t const> schemes,
        std::span<std::uint16_t const> permitted_ciphers) -> std::expected<crypto::Bytes,ServerKeyError>;


}
