export module tls.raw_client_flight;
export import tls.client_auth;
export import tls.encrypted_extensions;
export import tls.hybrid_client_keys;
export import tls.flight_types;
import std;

export namespace tls {
    class RawClientFlight {
        enum class State { extensions,certificate,signature,finished,client_finished,complete,failed } state_=State::extensions;
        ClientHello hello_;
        std::vector<std::uint16_t> offered_;
        std::optional<HandshakeSecrets> keys_;
        std::optional<ClientAuth> auth_;
        std::optional<std::uint16_t> alps_;
        RawClientFlight(ClientHello&& hello,std::vector<std::uint16_t>&& offered,HandshakeSecrets&& keys) noexcept;
        auto fail(RawClientError error) noexcept -> std::unexpected<RawClientError>;
        static auto extension_error(EncryptedExtensionsError error) noexcept -> RawClientError;
        static auto certificate_error(ClientAuthError error) noexcept -> RawClientError;
        auto certificate_for_parsing(std::span<std::uint8_t const> message,std::size_t maximum_body) const
            -> std::expected<crypto::Bytes,RawClientError>;
        template<class... Recovery>
        inline auto accept_extensions(std::span<std::uint8_t const> message,Recovery&... recovery) -> std::expected<void,RawClientError>{
        using Policy=RecoveryPolicy<Recovery...>;
        if (!keys_->transcript.append(message)) return fail({ClientFlightError::crypto_error});
        if constexpr(Policy::enabled) if (recovery_policy(recovery...).selected()) {
            auth_.emplace(ClientAuth::resumed(keys_->hash,std::move(keys_->transcript),std::move(keys_->client_traffic),std::move(keys_->server_traffic)));
            state_=State::finished;return {};
        }
        auth_.emplace(keys_->hash,std::move(keys_->transcript),std::move(keys_->client_traffic),std::move(keys_->server_traffic),
            hello_.extension(5)!=nullptr,hello_.extension(18)!=nullptr);
        state_=State::certificate; return {};
        }
    public:
        RawClientFlight(RawClientFlight const&)=delete;
        auto operator=(RawClientFlight const&) -> RawClientFlight& = delete;
        RawClientFlight(RawClientFlight&&) noexcept;
        auto operator=(RawClientFlight&&) noexcept -> RawClientFlight&;
        // Keys must come from a matching raw Hello factory, with its exact transcript.
        [[nodiscard]] static auto from_keys(std::span<std::uint8_t const> client_hello,HandshakeSecrets&& keys)
            -> std::expected<RawClientFlight,RawClientError>;
        template<class Policy,class Private>
        static inline auto create_psk(std::span<std::uint8_t const> client,std::span<std::uint8_t const> server,
            Private&& key,std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,HandshakeTransport transport,Policy& policy)
            -> std::expected<RawClientFlight,RawClientError> {
            auto keys=[&] {
                if constexpr(std::same_as<std::remove_cvref_t<Private>,HybridClient>)
                    return client_hybrid_handshake_secrets_with(client,server,std::forward<Private>(key),first,retry,transport,policy);
                else return client_handshake_secrets_with(client,server,std::forward<Private>(key),first,retry,transport,policy);
            }();
            if (!keys) return std::unexpected(keys.error()==ClientKeyError::crypto_error ? RawClientError{ClientFlightError::crypto_error,80} : RawClientError{ClientFlightError::invalid_hello,47});
            if constexpr(Policy::enabled) policy.offer_consumed();
            return from_keys(client,std::move(*keys));
        }
        [[nodiscard]] static auto create_x25519(std::span<std::uint8_t const> client,std::span<std::uint8_t const> server,crypto::X25519Private&& key,HandshakeTransport transport=HandshakeTransport::tcp)
            -> std::expected<RawClientFlight,RawClientError>;
        [[nodiscard]] static auto create_hybrid(std::span<std::uint8_t const> client,std::span<std::uint8_t const> server,HybridClient&& key,HandshakeTransport transport=HandshakeTransport::tcp)
            -> std::expected<RawClientFlight,RawClientError>;
        [[nodiscard]] static auto create_x25519_retry(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,std::span<std::uint8_t const> second,
            std::span<std::uint8_t const> server,crypto::X25519Private&& key,HandshakeTransport transport=HandshakeTransport::tcp) -> std::expected<RawClientFlight,RawClientError>;
        [[nodiscard]] static auto create_hybrid_retry(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,std::span<std::uint8_t const> second,
            std::span<std::uint8_t const> server,HybridClient&& key,HandshakeTransport transport=HandshakeTransport::tcp) -> std::expected<RawClientFlight,RawClientError>;
        [[nodiscard]] static auto create_ecdh(std::span<std::uint8_t const> client,std::span<std::uint8_t const> server,crypto::EcPrivate&& key,HandshakeTransport transport=HandshakeTransport::tcp)
            -> std::expected<RawClientFlight,RawClientError>;
        [[nodiscard]] static auto create_ecdh_retry(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,std::span<std::uint8_t const> second,
            std::span<std::uint8_t const> server,crypto::EcPrivate&& key,HandshakeTransport transport=HandshakeTransport::tcp) -> std::expected<RawClientFlight,RawClientError>;
        [[nodiscard]] auto client_hello() const noexcept -> ClientHello const&;
        [[nodiscard]] auto handshake_secrets() const noexcept -> std::expected<TrafficSecretView,RawClientError>;
        [[nodiscard]] auto can_read_handshake() const noexcept -> bool;
        [[nodiscard]] auto complete() const noexcept -> bool;
        auto cancel() noexcept -> void;
        [[nodiscard]] auto certificate(std::span<std::uint8_t const> message,std::span<std::span<std::uint8_t const> const> anchors,
            PeerNameKind kind,std::span<std::uint8_t const> name,std::int64_t time) -> std::expected<void,RawClientError>;
        [[nodiscard]] auto certificate(std::span<std::uint8_t const> message,CertificateVerifier const& verifier) -> std::expected<void,RawClientError>;
        template<class Verifier>
        [[nodiscard]] auto certificate_with(std::span<std::uint8_t const> message,Verifier&& verifier,std::size_t maximum_body=4194300) -> std::expected<void,RawClientError> {
            if (state_!=State::certificate) return std::unexpected(RawClientError{ClientFlightError::invalid_state});
            state_=State::failed;
            try {
                auto decompressed=certificate_for_parsing(message,maximum_body);
                if (!decompressed) return fail(decompressed.error());
                auto decoded=decompressed->empty() ? message : std::span<std::uint8_t const>(*decompressed);
                auto result=auth_->certificate_with(decoded,std::forward<Verifier>(verifier),message);
                if (!result) return fail(certificate_error(result.error()));
                state_=State::signature; return {};
            } catch (...) { cancel(); throw; }
        }
        [[nodiscard]] auto certificate_verify(std::span<std::uint8_t const> message) -> std::expected<void,RawClientError>;
        template<class... Recovery>
        inline auto encrypted_extensions(std::span<std::uint8_t const> message,Recovery&... recovery) -> std::expected<EncryptedExtensions,RawClientError>{
        using Policy=RecoveryPolicy<Recovery...>;
        if (state_!=State::extensions) return std::unexpected(RawClientError{ClientFlightError::invalid_state});
        state_=State::failed;
        try {
            auto parsed=validate_encrypted_extensions(hello_,message);
            if (!parsed) return fail(extension_error(parsed.error()));
            if constexpr(Policy::enabled) {
                auto bound=recovery_policy(recovery...).extensions(parsed->alpn ? std::span<std::uint8_t const>(*parsed->alpn) : std::span<std::uint8_t const>{});
                if (!bound)return fail({ClientFlightError::invalid_extensions,120});
            }
            alps_=parsed->application_settings_code;
            auto accepted=accept_extensions(message,recovery...); if (!accepted) return std::unexpected(accepted.error());
            return std::move(*parsed);
        } catch (...) { cancel(); throw; }
        }
        template<class... Recovery>
        inline auto quic_encrypted_extensions(std::span<std::uint8_t const> message,std::span<std::uint8_t const> required,Recovery&... recovery) -> std::expected<QuicEncryptedExtensions,RawClientError>{
        using Policy=RecoveryPolicy<Recovery...>;
        if (state_!=State::extensions) return std::unexpected(RawClientError{ClientFlightError::invalid_state});
        state_=State::failed;
        try {
            auto parsed=validate_quic_encrypted_extensions<Policy::enabled,EarlyDataPolicy<Policy>>(hello_,message,required);
            if (!parsed) return fail(extension_error(parsed.error()));
            if constexpr(Policy::enabled) {
                auto bound=recovery_policy(recovery...).extensions(parsed->common.alpn ? std::span<std::uint8_t const>(*parsed->common.alpn) : std::span<std::uint8_t const>{});
                if (!bound)return fail({ClientFlightError::invalid_extensions,120});
            }
            auto accepted=accept_extensions(message,recovery...); if (!accepted) return std::unexpected(accepted.error());
            return std::move(*parsed);
        } catch (...) { cancel(); throw; }
        }
        template<class... Recovery>
        inline auto server_finished(std::span<std::uint8_t const> message,Recovery&... recovery) -> std::expected<TrafficSecrets,RawClientError>{
        using Policy=RecoveryPolicy<Recovery...>;
        if (state_!=State::finished) return std::unexpected(RawClientError{ClientFlightError::invalid_state});
        state_=State::failed;
        try {
            auto result=auth_->server_finished(message);
            if (!result) return fail(result.error()==ClientAuthError::crypto_error ? RawClientError{ClientFlightError::crypto_error,80} : RawClientError{ClientFlightError::invalid_finished,51});
            auto hash=auth_->server_finished_hash();
            if (!hash) return fail({ClientFlightError::crypto_error});
            auto secrets=application_traffic_secrets(keys_->cipher_suite,keys_->hash,keys_->handshake_secret.view(),*hash,recovery...);
            if (!secrets) return fail({ClientFlightError::crypto_error});
            keys_.reset(); state_=State::client_finished; return std::move(*secrets);
        } catch (...) { cancel(); throw; }
        }
        template<class... Recovery>
        inline auto client_finished(Recovery&... recovery) -> std::expected<crypto::Bytes,RawClientError>{
        using Policy=RecoveryPolicy<Recovery...>;
        if (state_!=State::client_finished) return std::unexpected(RawClientError{ClientFlightError::invalid_state});
        state_=State::failed;
        try {
            std::array<std::uint8_t,10> settings{8,0,0,6,0,4,0,0,0,0};
            if (alps_) {
                settings[6]=static_cast<std::uint8_t>(*alps_>>8);
                settings[7]=static_cast<std::uint8_t>(*alps_);
            }
            auto result=auth_->client_finished(alps_ ? std::span<std::uint8_t const>(settings) : std::span<std::uint8_t const>{}); if (!result) return fail({ClientFlightError::crypto_error});
            if constexpr(Policy::enabled) {
                auto hash=auth_->completed_transcript_hash();if (!hash)return fail({ClientFlightError::crypto_error});
                auto retained=recovery_policy(recovery...).client_finished(*hash);if (!retained)return fail({ClientFlightError::crypto_error});
            }
            auth_.reset(); state_=State::complete; return std::move(*result);
        } catch (...) { cancel(); throw; }
        }
    };
}
