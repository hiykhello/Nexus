export module nexus.tls.certificate_trust;
import std;

export namespace nexus::tls {
    enum class CertificateTrustError { invalid_input, invalid_certificate, verification_failed, crypto_error };
    enum class PeerNameKind { dns, ip };
    enum class TrustBundleError { invalid_input, invalid_pem, invalid_certificate, limit_exceeded, io_error };
    // CERTIFICATE-only PEM bundle; each decoded block must contain exactly one certificate.
    // Returned DER owns its bytes. No partial result on error.
    [[nodiscard]] auto parse_trust_bundle(std::string_view pem) -> std::expected<std::vector<std::vector<std::uint8_t>>, TrustBundleError>;
    // Linux regular file, read through one descriptor; symlinks are allowed for system bundles.
    [[nodiscard]] auto load_trust_bundle(std::string_view path) -> std::expected<std::vector<std::vector<std::uint8_t>>, TrustBundleError>;
    // DER leaf followed by untrusted intermediates; trust anchors are explicitly supplied DER.
    // DNS names are ASCII; IP names are binary (4 or 16 bytes). The caller supplies POSIX time.
    // Uses TLS server purpose, SAN-only identity, up to 16 presented certificates and 1024 anchors;
    // the verified path has a maximum depth of 8 intermediates.
    // Does not check revocation, CertificateVerify, Finished, or handshake ordering.
    [[nodiscard]] auto verify_server_certificate_chain(
        std::span<std::span<std::uint8_t const> const> chain,
        std::span<std::span<std::uint8_t const> const> anchors,
        PeerNameKind name_kind, std::span<std::uint8_t const> name, std::int64_t verification_time)
        -> std::expected<void, CertificateTrustError>;
}
