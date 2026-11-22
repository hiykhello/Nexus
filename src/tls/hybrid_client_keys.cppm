export module tls.hybrid_client_keys;
export import tls.client_keys;
export import tls.hybrid;
import tls.server_hello;
import std;

export namespace tls {
    template<class... Recovery>
    inline auto client_hybrid_handshake_secrets_with(std::span<std::uint8_t const> client_wire,std::span<std::uint8_t const> server_wire,
        HybridClient&& ephemeral, std::span<std::uint8_t const> first_wire, std::span<std::uint8_t const> retry_wire,HandshakeTransport transport,Recovery&... recovery) -> std::expected<HandshakeSecrets,ClientKeyError> {
        using Policy=RecoveryPolicy<Recovery...>;
        auto state=std::move(ephemeral);
        auto cb=detail::client_key_message_body(client_wire,1), sb=detail::client_key_message_body(server_wire,2); if (!cb || !sb) return std::unexpected(ClientKeyError::malformed_hello);
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
        auto peer=server->template validate_x25519_mlkem768<Policy::enabled>(*client); if (!peer) return std::unexpected(ClientKeyError::invalid_server);
        auto actual=state.share(); if (!actual) return std::unexpected(actual.error()==HybridError::crypto_error ? ClientKeyError::crypto_error : ClientKeyError::key_mismatch);
        auto extension=client->extension(51); if (!extension) return std::unexpected(ClientKeyError::invalid_offer);
        auto offers=KeyShare::parse_client(extension->data); if (!offers) return std::unexpected(ClientKeyError::invalid_offer);
        auto found=std::ranges::find(*offers,x25519_mlkem768_group,&KeyShareEntry::group);
        if (found==offers->end() || !std::ranges::equal(found->key_exchange,*actual)) return std::unexpected(ClientKeyError::key_mismatch);
        auto shared=state.finish(peer->key_exchange); if (!shared) return std::unexpected(shared.error()==HybridError::crypto_error ? ClientKeyError::crypto_error : ClientKeyError::invalid_peer);
        auto hash=server->cipher_suite==0x1302 ? crypto::Hash::sha384 : crypto::Hash::sha256;
        auto transcript=Transcript::create(hash); if (!transcript) return std::unexpected(ClientKeyError::crypto_error);
        if (!retry_wire.empty() && (!transcript->append(first_wire) || !transcript->hello_retry_request() || !transcript->append(retry_wire))) return std::unexpected(ClientKeyError::crypto_error);
        if (!transcript->append(client_wire) || !transcript->append(server_wire)) return std::unexpected(ClientKeyError::crypto_error);
        auto digest=transcript->snapshot(); auto early=[&]() __attribute__((always_inline)) {if constexpr(Policy::enabled)return detail::client_policy_early_secret(hash,*client,*server,recovery_policy(recovery...));else return early_secret(hash);}(); if (!digest || !early) {
            if constexpr(Policy::enabled) if (digest && !early && early.error()==crypto::Error::invalid_peer) return std::unexpected(ClientKeyError::invalid_server);
            return std::unexpected(ClientKeyError::crypto_error);
        }
        auto hs=handshake_secret(hash,early->view(),shared->view()); if (!hs) return std::unexpected(ClientKeyError::crypto_error);
        auto client_traffic=derive_secret(hash,hs->view(),"c hs traffic",*digest), server_traffic=derive_secret(hash,hs->view(),"s hs traffic",*digest);
        if (!client_traffic || !server_traffic) return std::unexpected(ClientKeyError::crypto_error);
        return HandshakeSecrets{server->cipher_suite,hash,std::move(*transcript),std::move(*hs),std::move(*client_traffic),std::move(*server_traffic)};
    }
    // Consumes hybrid ephemeral keys, validates actual Hello messages and initializes unauthenticated handshake keys.
    // This direct path does not authenticate the server.
    [[nodiscard]] auto client_hybrid_handshake_keys(std::span<std::uint8_t const> client_hello,
        std::span<std::uint8_t const> server_hello, HybridClient&& ephemeral)
        -> std::expected<ClientHandshakeKeys,ClientKeyError>;
    // Validates the complete retry sequence and consumes the second ClientHello key.
    [[nodiscard]] auto client_hybrid_handshake_keys_retry(std::span<std::uint8_t const> first, std::span<std::uint8_t const> retry,
        std::span<std::uint8_t const> second, std::span<std::uint8_t const> server, HybridClient&& key)
        -> std::expected<ClientHandshakeKeys,ClientKeyError>;
    [[nodiscard]] auto client_hybrid_handshake_secrets(std::span<std::uint8_t const> client,std::span<std::uint8_t const> server,HybridClient&& key,HandshakeTransport transport=HandshakeTransport::tcp)
        -> std::expected<HandshakeSecrets,ClientKeyError>;
    [[nodiscard]] auto client_hybrid_handshake_secrets_retry(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,
        std::span<std::uint8_t const> second,std::span<std::uint8_t const> server,HybridClient&& key,HandshakeTransport transport=HandshakeTransport::tcp) -> std::expected<HandshakeSecrets,ClientKeyError>;

}
