module nexus.tls.hybrid_client_keys;
import nexus.tls.server_hello;
import std;

namespace nexus::tls {
    namespace {
        auto body(std::span<std::uint8_t const> wire,std::uint8_t type) -> std::optional<std::span<std::uint8_t const>> {
            if (wire.size()<4 || wire[0]!=type) return {};
            auto n=(std::size_t{wire[1]}<<16)|(std::size_t{wire[2]}<<8)|wire[3];
            if (n!=wire.size()-4) return {}; return wire.subspan(4);
        }
    }
    static auto client_hybrid_handshake_keys_impl(std::span<std::uint8_t const> client_wire,std::span<std::uint8_t const> server_wire,
        HybridClient&& ephemeral, std::span<std::uint8_t const> first_wire, std::span<std::uint8_t const> retry_wire) -> std::expected<ClientHandshakeKeys,ClientKeyError> {
        auto state=std::move(ephemeral);
        auto cb=body(client_wire,1), sb=body(server_wire,2); if (!cb || !sb) return std::unexpected(ClientKeyError::malformed_hello);
        auto client=ClientHello::parse(*cb); auto server=ServerHello::parse(*sb);
        if (!client || !client->validate_tls13()) return std::unexpected(ClientKeyError::invalid_offer);
        if (!server) return std::unexpected(ClientKeyError::invalid_server);
        if (!retry_wire.empty()) {
            auto fb=body(first_wire,1), rb=body(retry_wire,2);
            if (!fb || !rb) return std::unexpected(ClientKeyError::malformed_hello);
            auto first=ClientHello::parse(*fb); auto retry=ServerHello::parse(*rb);
            if (!first || !retry || !retry->validate_retry(*first,*client,*server)) return std::unexpected(ClientKeyError::invalid_server);
        } else if (!first_wire.empty()) return std::unexpected(ClientKeyError::malformed_hello);
        auto peer=server->validate_x25519_mlkem768(*client); if (!peer) return std::unexpected(ClientKeyError::invalid_server);
        auto actual=state.share(); if (!actual) return std::unexpected(ClientKeyError::key_mismatch);
        auto extension=client->extension(51); if (!extension) return std::unexpected(ClientKeyError::invalid_offer);
        auto offers=KeyShare::parse_client(extension->data); if (!offers) return std::unexpected(ClientKeyError::invalid_offer);
        auto found=std::ranges::find(*offers,x25519_mlkem768_group,&KeyShareEntry::group);
        if (found==offers->end() || !std::ranges::equal(found->key_exchange,*actual)) return std::unexpected(ClientKeyError::key_mismatch);
        auto shared=state.finish(peer->key_exchange); if (!shared) return std::unexpected(ClientKeyError::invalid_peer);
        auto hash=server->cipher_suite==0x1302 ? crypto::Hash::sha384 : crypto::Hash::sha256;
        auto algorithm=server->cipher_suite==0x1301 ? crypto::Aead::aes_128_gcm : server->cipher_suite==0x1302 ? crypto::Aead::aes_256_gcm : crypto::Aead::chacha20_poly1305;
        auto key_size=server->cipher_suite==0x1301 ? 16u : 32u;
        auto transcript=Transcript::create(hash); if (!transcript) return std::unexpected(ClientKeyError::crypto_error);
        if (!retry_wire.empty() && (!transcript->append(first_wire) || !transcript->hello_retry_request() || !transcript->append(retry_wire))) return std::unexpected(ClientKeyError::crypto_error);
        if (!transcript->append(client_wire) || !transcript->append(server_wire)) return std::unexpected(ClientKeyError::crypto_error);
        auto digest=transcript->snapshot(); auto early=early_secret(hash); if (!digest || !early) return std::unexpected(ClientKeyError::crypto_error);
        auto hs=handshake_secret(hash,early->view(),shared->view()); if (!hs) return std::unexpected(ClientKeyError::crypto_error);
        auto client_traffic=derive_secret(hash,hs->view(),"c hs traffic",*digest), server_traffic=derive_secret(hash,hs->view(),"s hs traffic",*digest);
        if (!client_traffic || !server_traffic) return std::unexpected(ClientKeyError::crypto_error);
        auto ck=expand_label(hash,client_traffic->view(),"key",{},key_size), ci=expand_label(hash,client_traffic->view(),"iv",{},12);
        auto sk=expand_label(hash,server_traffic->view(),"key",{},key_size), si=expand_label(hash,server_traffic->view(),"iv",{},12);
        if (!ck || !ci || !sk || !si) return std::unexpected(ClientKeyError::crypto_error);
        auto write=RecordLayer::create(RecordDirection::send,algorithm,ck->view(),ci->view());
        auto read=RecordLayer::create(RecordDirection::receive,algorithm,sk->view(),si->view());
        if (!write || !read) return std::unexpected(ClientKeyError::crypto_error);
        return ClientHandshakeKeys{hash,std::move(*transcript),std::move(*hs),std::move(*client_traffic),std::move(*server_traffic),std::move(*write),std::move(*read)};
    }
    auto client_hybrid_handshake_keys(std::span<std::uint8_t const> client, std::span<std::uint8_t const> server, HybridClient&& key) -> std::expected<ClientHandshakeKeys,ClientKeyError> {
        return client_hybrid_handshake_keys_impl(client,server,std::move(key),{},{});
    }
    auto client_hybrid_handshake_keys_retry(std::span<std::uint8_t const> first, std::span<std::uint8_t const> retry, std::span<std::uint8_t const> second,
        std::span<std::uint8_t const> server, HybridClient&& key) -> std::expected<ClientHandshakeKeys,ClientKeyError> {
        if (retry.empty() || first.empty()) return std::unexpected(ClientKeyError::malformed_hello);
        return client_hybrid_handshake_keys_impl(second,server,std::move(key),first,retry);
    }
}
