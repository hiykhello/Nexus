module;
#include <openssl/base.h>
export module nexus.tls.server_credential;
export import nexus.crypto;
import std;
export namespace nexus::tls {
    enum class ServerCredentialError { invalid_certificate, invalid_private_key, key_mismatch, unsupported_key,
        invalid_transcript, invalid_state, crypto_error };
    // Owns a parsed private key; the caller owns and must protect/erase the input bytes.
    // This validates key matching and supported key type, not certificate chain, names or validity.
    class ServerCredential {
        evp_pkey_st* key_;
        std::uint16_t scheme_;
        crypto::Bytes certificate_;
        std::vector<crypto::Bytes> chain_;
        explicit ServerCredential(evp_pkey_st* key, std::uint16_t scheme, crypto::Bytes certificate) noexcept;
    public:
        static constexpr std::size_t max_certificate_list_size=1048576;
        ~ServerCredential();
        ServerCredential(ServerCredential const&)=delete;
        auto operator=(ServerCredential const&) -> ServerCredential& = delete;
        ServerCredential(ServerCredential&&) noexcept;
        auto operator=(ServerCredential&&) noexcept -> ServerCredential&;
        // DER certificate and unencrypted DER private key; exactly one object each.
        [[nodiscard]] static auto create(std::span<std::uint8_t const> certificate, std::span<std::uint8_t const> private_key)
            -> std::expected<ServerCredential,ServerCredentialError>;
        // Accepts one DER leaf or a PEM leaf-first chain, and a DER or PEM unencrypted key.
        [[nodiscard]] static auto create_file_contents(std::span<std::uint8_t const> certificate, std::span<std::uint8_t const> private_key)
            -> std::expected<ServerCredential,ServerCredentialError>;
        // Retains the key for another independent handshake; concurrent signing uses separate contexts.
        [[nodiscard]] auto clone() const -> std::expected<ServerCredential,ServerCredentialError>;
        [[nodiscard]] auto scheme() const noexcept -> std::optional<std::uint16_t>;
        // Borrowed DER leaf certificate; valid only while the credential remains alive and unmoved.
        [[nodiscard]] auto certificate() const noexcept -> std::span<std::uint8_t const>;
        // Intermediate certificates in configured order; borrowed until destruction or move.
        [[nodiscard]] auto chain() const noexcept -> std::span<crypto::Bytes const>;
        // Returns a complete TLS 1.3 CertificateVerify handshake message.
        [[nodiscard]] auto sign(crypto::Hash hash, std::span<std::uint8_t const> transcript_hash) const
            -> std::expected<crypto::Bytes,ServerCredentialError>;
    };
}
