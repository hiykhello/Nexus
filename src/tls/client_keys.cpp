module tls.client_keys;
import tls.server_hello;
import tls.traffic_records;
import std;

namespace tls {


    static auto record_keys(HandshakeSecrets&& secrets) -> std::expected<ClientHandshakeKeys,ClientKeyError> {
        auto records=traffic_records(secrets.cipher_suite,secrets.client_traffic.view(),secrets.server_traffic.view(),false);
        if (!records) return std::unexpected(ClientKeyError::crypto_error);
        return ClientHandshakeKeys{secrets.hash,std::move(secrets.transcript),std::move(secrets.handshake_secret),std::move(secrets.client_traffic),std::move(secrets.server_traffic),std::move(records->write),std::move(records->read)};
    }
    auto client_handshake_keys(std::span<std::uint8_t const> client, std::span<std::uint8_t const> server, crypto::X25519Private&& key) -> std::expected<ClientHandshakeKeys,ClientKeyError> {
        auto secrets=client_handshake_secrets(client,server,std::move(key));
        if (!secrets) return std::unexpected(secrets.error());
        return record_keys(std::move(*secrets));
    }
    auto client_handshake_keys_retry(std::span<std::uint8_t const> first, std::span<std::uint8_t const> retry, std::span<std::uint8_t const> second,
        std::span<std::uint8_t const> server, crypto::X25519Private&& key) -> std::expected<ClientHandshakeKeys,ClientKeyError> {
        if (retry.empty() || first.empty()) return std::unexpected(ClientKeyError::malformed_hello);
        auto secrets=client_handshake_secrets_retry(first,retry,second,server,std::move(key));
        if (!secrets) return std::unexpected(secrets.error());
        return record_keys(std::move(*secrets));
    }
    auto client_handshake_secrets(std::span<std::uint8_t const> client,std::span<std::uint8_t const> server,crypto::X25519Private&& key,HandshakeTransport transport) -> std::expected<HandshakeSecrets,ClientKeyError> {

        return client_handshake_secrets_with(client,server,std::move(key),{},{},transport);
    }
    auto client_handshake_secrets_retry(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,std::span<std::uint8_t const> second,
        std::span<std::uint8_t const> server,crypto::X25519Private&& key,HandshakeTransport transport) -> std::expected<HandshakeSecrets,ClientKeyError> {
        if (retry.empty() || first.empty()) return std::unexpected(ClientKeyError::malformed_hello);

        return client_handshake_secrets_with(second,server,std::move(key),first,retry,transport);
    }

    auto client_handshake_secrets(std::span<std::uint8_t const> client,std::span<std::uint8_t const> server,crypto::EcPrivate&& key,HandshakeTransport transport) -> std::expected<HandshakeSecrets,ClientKeyError> {

        return client_handshake_secrets_with(client,server,std::move(key),{},{},transport);
    }
    auto client_handshake_secrets_retry(std::span<std::uint8_t const> first,std::span<std::uint8_t const> retry,std::span<std::uint8_t const> second,
        std::span<std::uint8_t const> server,crypto::EcPrivate&& key,HandshakeTransport transport) -> std::expected<HandshakeSecrets,ClientKeyError> {
        if (retry.empty() || first.empty()) return std::unexpected(ClientKeyError::malformed_hello);

        return client_handshake_secrets_with(second,server,std::move(key),first,retry,transport);
    }
}
