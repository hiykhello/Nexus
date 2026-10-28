module nexus.tls.server_keys;
import nexus.tls.server_hello;
import nexus.tls.handshake;
import nexus.tls.hybrid;
import std;
namespace nexus::tls {
    namespace {
    auto body(std::span<std::uint8_t const> wire, std::uint8_t type) -> std::optional<std::span<std::uint8_t const>> {
        if (wire.size()<4 || wire[0]!=type ||
            ((std::size_t{wire[1]}<<16)|(std::size_t{wire[2]}<<8)|wire[3])!=wire.size()-4) return {};
        return wire.subspan(4);
    }
    auto make_keys(std::span<std::uint8_t const> client_wire, std::span<std::uint16_t const> schemes,
        std::span<std::uint8_t const> first_wire, std::span<std::uint8_t const> retry_wire)
        -> std::expected<ServerHandshakeKeys,ServerKeyError> {
        auto input=body(client_wire,1); if (!input) return std::unexpected(ServerKeyError::invalid_hello);
        auto client=ClientHello::parse(*input,65535);
        if (!client) return std::unexpected(ServerKeyError::invalid_hello);
        auto selection=negotiate_server(*client,schemes);
        if (!selection) return std::unexpected(ServerKeyError::negotiation_failed);
        if (!selection->x25519_share && !selection->hybrid_share) return std::unexpected(ServerKeyError::retry_required);
        auto key=crypto::X25519Private::generate(); if (!key) return std::unexpected(ServerKeyError::crypto_error);
        std::optional<crypto::Secret32> x_secret; std::optional<HybridServerResult> hybrid;
        crypto::Bytes public_share; std::span<std::uint8_t const> shared;
        if (selection->group==0x001d && selection->x25519_share) {
            auto value=key->agree(*selection->x25519_share); if (!value) return std::unexpected(ServerKeyError::invalid_peer);
            x_secret.emplace(std::move(*value)); shared=x_secret->view();
            auto public_key=key->public_key(); if (!public_key) return std::unexpected(ServerKeyError::crypto_error);
            public_share.assign(public_key->begin(),public_key->end());
        } else if (selection->group==x25519_mlkem768_group && selection->hybrid_share) {
            auto result=hybrid_server_accept(*selection->hybrid_share,std::move(*key));
            if (!result) return std::unexpected(result.error()==HybridError::crypto_error ? ServerKeyError::crypto_error : ServerKeyError::invalid_peer);
            hybrid.emplace(std::move(*result)); shared=hybrid->secret.view();
            public_share.assign(hybrid->share.begin(),hybrid->share.end());
        } else return std::unexpected(ServerKeyError::invalid_hello);
        auto encoded_share=KeyShare::encode_server({selection->group,std::move(public_share)});
        if (!encoded_share) return std::unexpected(ServerKeyError::crypto_error);
        ServerHello hello; hello.session_id_echo=client->session_id; hello.cipher_suite=selection->cipher_suite;
        hello.extensions={{43,{3,4}},{51,std::move(*encoded_share)}};
        if (!crypto::random_bytes(hello.random) || hello.is_retry()) return std::unexpected(ServerKeyError::crypto_error);
        auto encoded_body=hello.encode(); if (!encoded_body) return std::unexpected(ServerKeyError::crypto_error);
        auto wire=HandshakeDecoder::encode(2,*encoded_body,65535); if (!wire) return std::unexpected(ServerKeyError::crypto_error);
        if (!retry_wire.empty()) {
            auto first_body=body(first_wire,1), retry_body=body(retry_wire,2);
            if (!first_body || !retry_body) return std::unexpected(ServerKeyError::invalid_hello);
            auto first=ClientHello::parse(*first_body,65535); auto retry=ServerHello::parse(*retry_body);
            if (!first || !retry || !retry->validate_retry(*first,*client,hello)) return std::unexpected(ServerKeyError::invalid_hello);
        }
        auto hash=selection->cipher_suite==0x1302 ? crypto::Hash::sha384 : crypto::Hash::sha256;
        auto algorithm=selection->cipher_suite==0x1301 ? crypto::Aead::aes_128_gcm :
            selection->cipher_suite==0x1302 ? crypto::Aead::aes_256_gcm : crypto::Aead::chacha20_poly1305;
        auto key_size=selection->cipher_suite==0x1301 ? 16u : 32u;
        auto transcript=Transcript::create(hash);
        if (!transcript || (!retry_wire.empty() && (!transcript->append(first_wire) || !transcript->hello_retry_request() || !transcript->append(retry_wire))) ||
            !transcript->append(client_wire) || !transcript->append(*wire)) return std::unexpected(ServerKeyError::crypto_error);
        auto digest=transcript->snapshot(); auto early=early_secret(hash);
        if (!digest || !early) return std::unexpected(ServerKeyError::crypto_error);
        auto hs=handshake_secret(hash,early->view(),shared); if (!hs) return std::unexpected(ServerKeyError::crypto_error);
        auto ct=derive_secret(hash,hs->view(),"c hs traffic",*digest), st=derive_secret(hash,hs->view(),"s hs traffic",*digest);
        if (!ct || !st) return std::unexpected(ServerKeyError::crypto_error);
        auto ck=expand_label(hash,ct->view(),"key",{},key_size), ci=expand_label(hash,ct->view(),"iv",{},12);
        auto sk=expand_label(hash,st->view(),"key",{},key_size), si=expand_label(hash,st->view(),"iv",{},12);
        if (!ck || !ci || !sk || !si) return std::unexpected(ServerKeyError::crypto_error);
        auto read=RecordLayer::create(RecordDirection::receive,algorithm,ck->view(),ci->view());
        auto write=RecordLayer::create(RecordDirection::send,algorithm,sk->view(),si->view());
        if (!read || !write) return std::unexpected(ServerKeyError::crypto_error);
        return ServerHandshakeKeys{std::move(*wire),selection->signature_scheme,hash,std::move(*transcript),std::move(*hs),
            std::move(*ct),std::move(*st),std::move(*write),std::move(*read)};
    }
    }
    auto server_handshake_keys(std::span<std::uint8_t const> wire, std::span<std::uint16_t const> schemes)
        -> std::expected<ServerHandshakeKeys,ServerKeyError> { return make_keys(wire,schemes,{},{}); }
    auto server_retry_hello(std::span<std::uint8_t const> first_wire,std::span<std::uint16_t const> schemes)
        -> std::expected<crypto::Bytes,ServerKeyError> {
        auto input=body(first_wire,1); if (!input) return std::unexpected(ServerKeyError::invalid_hello);
        auto first=ClientHello::parse(*input,65535); if (!first) return std::unexpected(ServerKeyError::invalid_hello);
        auto selection=negotiate_server(*first,schemes); if (!selection) return std::unexpected(ServerKeyError::negotiation_failed);
        if (selection->x25519_share || selection->hybrid_share) return std::unexpected(ServerKeyError::invalid_hello);
        ServerHello retry; retry.random={0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c};
        retry.session_id_echo=first->session_id; retry.cipher_suite=selection->cipher_suite;
        retry.extensions={{43,{3,4}},{51,KeyShare::encode_retry(selection->group)}};
        if (!retry.validate_retry_request(*first)) return std::unexpected(ServerKeyError::invalid_hello);
        auto encoded=retry.encode(); if (!encoded) return std::unexpected(ServerKeyError::crypto_error);
        auto wire=HandshakeDecoder::encode(2,*encoded,65535); if (!wire) return std::unexpected(ServerKeyError::crypto_error);
        return std::move(*wire);
    }
    auto server_handshake_keys_retry(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,
        std::span<std::uint8_t const> second,std::span<std::uint16_t const> schemes) -> std::expected<ServerHandshakeKeys,ServerKeyError> {
        if (first.empty() || retry.empty()) return std::unexpected(ServerKeyError::invalid_hello);
        auto expected=server_retry_hello(first,schemes);
        if (!expected || !std::ranges::equal(*expected,retry)) return std::unexpected(ServerKeyError::invalid_hello);
        return make_keys(second,schemes,first,retry);
    }
}
