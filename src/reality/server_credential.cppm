export module reality.server_credential;
import std;
import reality.auth;
import tls.server_credential;
import tls.certificate_verify;

export namespace reality {
    enum class CredentialError { invalid_key, invalid_certificate, crypto_failure };
    // A DER Ed25519 certificate template and matching DER private key belong to
    // the server profile. This returns a separate per-handshake credential;
    // neither input nor AuthKey is retained by reference.
    [[nodiscard]] auto make_server_credential(AuthKey const& auth,tls::ServerCredential const& template_credential)
        -> std::expected<tls::ServerCredential,CredentialError>;
    [[nodiscard]] auto make_server_credential(AuthKey const& auth,std::span<std::uint8_t const> certificate,
        std::span<std::uint8_t const> private_key) -> std::expected<tls::ServerCredential,CredentialError>;
}
namespace reality {
    auto make_server_credential(AuthKey const& auth,tls::ServerCredential const& template_credential)
        -> std::expected<tls::ServerCredential,CredentialError> {
        if (auth.view().size()!=32) return std::unexpected(CredentialError::invalid_key);
        auto certificate=template_credential.certificate();
        auto fields=tls::ed25519_certificate_fields(certificate);
        if (!fields || template_credential.scheme()!=0x0807 || certificate.size()<67 ||
            certificate[certificate.size()-67]!=3 || certificate[certificate.size()-66]!=65 || certificate[certificate.size()-65]!=0 ||
            !std::ranges::equal(certificate.last(64),fields->signature)) return std::unexpected(CredentialError::invalid_certificate);
        auto mac=crypto::hmac(crypto::Hash::sha512,auth.view(),fields->public_key);
        if (!mac || mac->size()!=64) return std::unexpected(CredentialError::crypto_failure);
        struct Wipe { crypto::Bytes& bytes; ~Wipe(){ crypto::cleanse(bytes); } } wipe{*mac};
        crypto::Bytes encoded(certificate.begin(),certificate.end()); std::ranges::copy(*mac,encoded.end()-64);
        auto credential=template_credential.with_certificate(encoded);
        if (!credential) return std::unexpected(CredentialError::invalid_certificate);
        return std::move(*credential);
    }
    auto make_server_credential(AuthKey const& auth,std::span<std::uint8_t const> certificate,
        std::span<std::uint8_t const> private_key) -> std::expected<tls::ServerCredential,CredentialError> {
        if (auth.view().size()!=32) return std::unexpected(CredentialError::invalid_key);
        auto fields=tls::ed25519_certificate_fields(certificate);
        // A DER X.509 certificate's final element is its signature BIT STRING.
        // Verify its exact suffix before replacing the 64 bytes.
        if (!fields || certificate.size()<67 || certificate[certificate.size()-67]!=3 ||
            certificate[certificate.size()-66]!=65 || certificate[certificate.size()-65]!=0 ||
            !std::ranges::equal(certificate.last(64),fields->signature)) return std::unexpected(CredentialError::invalid_certificate);
        auto mac=crypto::hmac(crypto::Hash::sha512,auth.view(),fields->public_key);
        if (!mac || mac->size()!=64) return std::unexpected(CredentialError::crypto_failure);
        struct Wipe { crypto::Bytes& bytes; ~Wipe(){ crypto::cleanse(bytes); } } wipe{*mac};
        crypto::Bytes signed_certificate(certificate.begin(),certificate.end());
        std::ranges::copy(*mac,signed_certificate.end()-64);
        auto credential=tls::ServerCredential::create(signed_certificate,private_key);
        if (!credential || credential->scheme()!=0x0807) return std::unexpected(CredentialError::invalid_certificate);
        return std::move(*credential);
    }
}
