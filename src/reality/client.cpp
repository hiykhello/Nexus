module reality.client;
import std;

namespace reality {
    namespace {
        struct CertificatePolicy {
            AuthKey key;
            auto operator()(std::span<std::span<std::uint8_t const> const> chain) const -> bool {
                return !chain.empty() && key.verify_certificate(chain.front()).has_value();
            }
        };
        static_assert(tls::PendingCertificateVerifier::stores_inline<CertificatePolicy>);

        // Called synchronously while the driver still owns its initial share.
        struct ClientHelloAuthenticator {
            std::span<std::uint8_t const> server_public;
            Identity identity;
            auto operator()(std::span<std::uint8_t const> wire,crypto::X25519Private const& share) const
                -> std::expected<tls::ClientHelloAuthentication,tls::ClientHelloDriverError> {
                auto sealed=seal_client_hello(wire,share,server_public,identity);
                if (!sealed || sealed->wire.size()<71) return std::unexpected(tls::ClientHelloDriverError::crypto_error);
                tls::ClientHelloAuthentication result;
                result.session_id_size=32;
                std::copy_n(sealed->wire.begin()+39,32,result.session_id.begin());
                result.verifier=CertificatePolicy{std::move(sealed->key)};
                return result;
            }
        };
    }
    auto authenticate_client_hello(tls::ClientHelloDriver& driver,
        std::span<std::uint8_t const> server_public,Identity identity) -> std::expected<void,tls::ClientHelloDriverError> {
        return driver.authenticate_first(ClientHelloAuthenticator{server_public,identity});
    }
    auto create_client_session(tls::ClientHello hello,std::span<std::uint8_t const> server_public,
        Identity identity,std::uint16_t initial_group) -> std::expected<tls::ClientSessionHandshake,tls::ClientSessionHandshakeError> {
        return create_client_session(std::move(hello),std::span<std::uint16_t const>(&initial_group,1),server_public,identity);
    }
    auto create_client_session(tls::ClientHello hello,std::span<std::uint16_t const> groups,std::span<std::uint8_t const> server_public,
        Identity identity) -> std::expected<tls::ClientSessionHandshake,tls::ClientSessionHandshakeError> {
        if (groups.empty() || groups.size()>2) return std::unexpected(tls::ClientSessionHandshakeError::invalid_configuration);
        if (server_public.size()!=32) return std::unexpected(tls::ClientSessionHandshakeError::invalid_configuration);
        if (!crypto::random_bytes(hello.random)) return std::unexpected(tls::ClientSessionHandshakeError::invalid_configuration);
        hello.session_id.assign(32,0);
        auto driver=tls::ClientHelloDriver::create(std::move(hello),groups);
        if (!driver || !authenticate_client_hello(*driver,server_public,identity))
            return std::unexpected(tls::ClientSessionHandshakeError::invalid_configuration);
        return tls::ClientSessionHandshake::create_authenticated(std::move(*driver));
    }
}
