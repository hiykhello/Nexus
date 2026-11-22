export module tls.certificate_verify;
export import crypto;
import std;

export namespace tls {
    enum class CertificateVerifyError { invalid_certificate, invalid_message, unsupported_scheme, unoffered_scheme, invalid_transcript, invalid_signature, crypto_error };
    struct Ed25519CertificateFields { std::array<std::uint8_t,32> public_key; std::array<std::uint8_t,64> signature; };
    // Extracts fields only; does not authenticate the certificate.
    [[nodiscard]] auto ed25519_certificate_fields(std::span<std::uint8_t const> certificate_der)
        -> std::expected<Ed25519CertificateFields,CertificateVerifyError>;
    // Checks only the TLS 1.3 server CertificateVerify signature. Does not validate trust, hostname,
    // certificate validity, certificate usage, or handshake ordering. Certificate is one complete DER X.509 object.
    // Supports RSA-PSS rsae SHA256/384/512, ECDSA P256/384/521 and Ed25519, when offered.
    [[nodiscard]] auto verify_server_certificate_signature(std::span<std::uint8_t const> certificate_der,
        crypto::Hash transcript_algorithm, std::span<std::uint8_t const> transcript_hash,
        std::span<std::uint16_t const> offered_schemes, std::span<std::uint8_t const> handshake_message)
        -> std::expected<void,CertificateVerifyError>;
}
