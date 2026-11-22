export module tls.client_keys;
export import tls.record;
export import crypto.ecdh;
export import tls.handshake_secrets;
export import tls.handshake_policy;
export import tls.schedule;
export import tls.transcript;
import tls.server_hello;
export import tls.resumption_policy;
import std;

export namespace tls {
    enum class ClientKeyError { malformed_hello, invalid_offer, invalid_server, key_mismatch, invalid_peer, crypto_error };
    // Internal handshake epoch, not an authenticated TLS connection.
    struct ClientHandshakeKeys {
        crypto::Hash hash;
        Transcript transcript;
        Secret handshake_secret;
        Secret client_traffic;
        Secret server_traffic;
        RecordLayer write;
        RecordLayer read;
    };
    namespace detail {
        [[gnu::always_inline]] inline auto client_key_message_body(std::span<std::uint8_t const> wire,std::uint8_t type) -> std::optional<std::span<std::uint8_t const>> {
            if (wire.size()<4 || wire[0]!=type) return {};
            auto size=(std::size_t{wire[1]}<<16)|(std::size_t{wire[2]}<<8)|wire[3];
            if (size!=wire.size()-4)return {};return wire.subspan(4);
        }
        template<class Policy>
        [[gnu::always_inline]] inline auto client_policy_early_secret(crypto::Hash hash,ClientHello const& client,ServerHello const& server,Policy& policy)
            -> std::expected<Secret,crypto::Error> {
            if constexpr(Policy::enabled) {
                auto selected=policy.select(client,server);if (!selected)return std::unexpected(crypto::Error::invalid_peer);
                return early_secret(hash,*selected);
            } else return early_secret(hash);
        }
    }
    template<class Private,class... Recovery>
    inline auto client_handshake_secrets_with(std::span<std::uint8_t const> client_wire, std::span<std::uint8_t const> server_wire,
                               Private&& private_key, std::span<std::uint8_t const> first_wire, std::span<std::uint8_t const> retry_wire,HandshakeTransport transport,Recovery&... recovery) -> std::expected<HandshakeSecrets,ClientKeyError> {
        using Policy=RecoveryPolicy<Recovery...>;
        auto key=std::move(private_key);
        auto cb=detail::client_key_message_body(client_wire,1), sb=detail::client_key_message_body(server_wire,2);
        if (!cb || !sb) return std::unexpected(ClientKeyError::malformed_hello);
        auto client=ClientHello::parse(*cb); auto server=ServerHello::parse(*sb);
        if (!client || !client->validate_tls13()) return std::unexpected(ClientKeyError::invalid_offer);
        if (!validate_handshake_transport(*client,transport)) return std::unexpected(ClientKeyError::invalid_offer);
        if (!server) return std::unexpected(ClientKeyError::invalid_server);
        if (!retry_wire.empty()) {
            auto fb=detail::client_key_message_body(first_wire,1), rb=detail::client_key_message_body(retry_wire,2);
            if (!fb || !rb) return std::unexpected(ClientKeyError::malformed_hello);
            auto first=ClientHello::parse(*fb); auto retry=ServerHello::parse(*rb);
            if (!first || !retry || !retry->template validate_retry<Policy::enabled,EarlyDataPolicy<Policy>>(*first,*client,*server)) return std::unexpected(ClientKeyError::invalid_server);
        } else if (!first_wire.empty()) return std::unexpected(ClientKeyError::malformed_hello);
        auto group=[&] { if constexpr (std::same_as<Private,crypto::X25519Private>) return std::uint16_t{29}; else return key.group(); }();
        auto peer=[&] {
            if constexpr(Policy::enabled) {
                if constexpr(std::same_as<Private,crypto::X25519Private>)return server->template validate_x25519<true>(*client);
                else return server->template validate_nist<true>(*client,group);
            } else {if constexpr(std::same_as<Private,crypto::X25519Private>)return server->validate_x25519(*client);else return server->validate_nist(*client,group);}
        }();
        if (!peer) return std::unexpected(ClientKeyError::invalid_server);
        auto public_key=key.public_key(); if (!public_key) return std::unexpected(public_key.error()==crypto::Error::backend_failure ? ClientKeyError::crypto_error : ClientKeyError::key_mismatch);
        auto ext=client->extension(51); if (!ext) return std::unexpected(ClientKeyError::invalid_offer);
        auto offered=KeyShare::parse_client(ext->data); if (!offered) return std::unexpected(ClientKeyError::invalid_offer);
        auto found=std::ranges::find(*offered,group,&KeyShareEntry::group);
        auto public_bytes=[&] { if constexpr (std::same_as<Private,crypto::X25519Private>) return std::span<std::uint8_t const>(*public_key); else return public_key->view(); }();
        if (found==offered->end() || !std::ranges::equal(found->key_exchange,public_bytes)) return std::unexpected(ClientKeyError::key_mismatch);
        auto shared=key.agree(peer->key_exchange); if (!shared) return std::unexpected(shared.error()==crypto::Error::backend_failure ? ClientKeyError::crypto_error : ClientKeyError::invalid_peer);
        auto hash=server->cipher_suite==0x1302 ? crypto::Hash::sha384 : crypto::Hash::sha256;
        auto transcript=Transcript::create(hash); if (!transcript) return std::unexpected(ClientKeyError::crypto_error);
        if (!retry_wire.empty() && (!transcript->append(first_wire) || !transcript->hello_retry_request() || !transcript->append(retry_wire))) return std::unexpected(ClientKeyError::crypto_error);
        if (!transcript->append(client_wire) || !transcript->append(server_wire)) return std::unexpected(ClientKeyError::crypto_error);
        auto digest=transcript->snapshot(); auto early=[&]() __attribute__((always_inline)) {if constexpr(Policy::enabled)return detail::client_policy_early_secret(hash,*client,*server,recovery_policy(recovery...));else return early_secret(hash);}();
        if (!digest || !early) {
            if constexpr(Policy::enabled) if (digest && !early && early.error()==crypto::Error::invalid_peer) return std::unexpected(ClientKeyError::invalid_server);
            return std::unexpected(ClientKeyError::crypto_error);
        }
        auto hs=handshake_secret(hash,early->view(),shared->view()); if (!hs) return std::unexpected(ClientKeyError::crypto_error);
        auto client_traffic=derive_secret(hash,hs->view(),"c hs traffic",*digest), server_traffic=derive_secret(hash,hs->view(),"s hs traffic",*digest);
        if (!client_traffic || !server_traffic) return std::unexpected(ClientKeyError::crypto_error);
        return HandshakeSecrets{server->cipher_suite,hash,std::move(*transcript),std::move(*hs),std::move(*client_traffic),std::move(*server_traffic)};
    }
    // Consumes the ephemeral key, verifies it matches the offered X25519 share, and binds exact wire messages.
    // Direct TLS 1.3 without PSK. This does not authenticate the server.
    [[nodiscard]] auto client_handshake_keys(std::span<std::uint8_t const> client_hello,
        std::span<std::uint8_t const> server_hello, crypto::X25519Private&& private_key)
        -> std::expected<ClientHandshakeKeys,ClientKeyError>;
    // Validates the complete retry sequence and consumes the second ClientHello key.
    [[nodiscard]] auto client_handshake_keys_retry(std::span<std::uint8_t const> first, std::span<std::uint8_t const> retry,
        std::span<std::uint8_t const> second, std::span<std::uint8_t const> server, crypto::X25519Private&& key)
        -> std::expected<ClientHandshakeKeys,ClientKeyError>;
    [[nodiscard]] auto client_handshake_secrets(std::span<std::uint8_t const> client_hello,
        std::span<std::uint8_t const> server_hello,crypto::X25519Private&& key,HandshakeTransport transport=HandshakeTransport::tcp)
        -> std::expected<HandshakeSecrets,ClientKeyError>;
    [[nodiscard]] auto client_handshake_secrets_retry(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,
        std::span<std::uint8_t const> second,std::span<std::uint8_t const> server,crypto::X25519Private&& key,HandshakeTransport transport=HandshakeTransport::tcp)
        -> std::expected<HandshakeSecrets,ClientKeyError>;

    [[nodiscard]] auto client_handshake_secrets(std::span<std::uint8_t const> client,std::span<std::uint8_t const> server,
        crypto::EcPrivate&& key,HandshakeTransport transport=HandshakeTransport::tcp) -> std::expected<HandshakeSecrets,ClientKeyError>;
    [[nodiscard]] auto client_handshake_secrets_retry(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,
        std::span<std::uint8_t const> second,std::span<std::uint8_t const> server,crypto::EcPrivate&& key,
        HandshakeTransport transport=HandshakeTransport::tcp) -> std::expected<HandshakeSecrets,ClientKeyError>;
}
