export module nexus.tls.certificate_verify;
export import nexus.crypto;
import std;

export namespace nexus::tls {
    enum class CertificateVerifyError { invalid_certificate, invalid_message, unsupported_scheme, unoffered_scheme, invalid_transcript, invalid_signature, crypto_error };
    // Checks only the TLS 1.3 server CertificateVerify signature. Does not validate trust, hostname,
    // certificate validity, certificate usage, or handshake ordering. Certificate is one complete DER X.509 object.
    // Supports rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256 and ed25519, when offered.
    [[nodiscard]] auto verify_server_certificate_signature(std::span<std::uint8_t const> certificate_der,
        crypto::Hash transcript_algorithm, std::span<std::uint8_t const> transcript_hash,
        std::span<std::uint16_t const> offered_schemes, std::span<std::uint8_t const> handshake_message)
        -> std::expected<void,CertificateVerifyError>;
}
