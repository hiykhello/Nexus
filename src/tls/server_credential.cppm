export module tls.server_credential;
export import boringssl;
export import crypto;
import std;
using namespace boringssl;
export namespace tls {
    enum class ServerCredentialError { invalid_certificate, invalid_private_key, key_mismatch, unsupported_key,
        invalid_transcript, invalid_state, crypto_error };
    // Owns a parsed private key; the caller owns and must protect/erase the input bytes.
    // This validates key matching and supported key type, not certificate chain, names or validity.
    class ServerCredential {
        evp_pkey_st* key_;
        std::uint16_t scheme_;
        struct Certificates { crypto::Bytes leaf; std::vector<crypto::Bytes> chain; };
        Certificates certificates_;
        explicit ServerCredential(evp_pkey_st* key, std::uint16_t scheme, Certificates&& certificates) noexcept;
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
        // Create an in-memory, self-signed Ed25519 template. It is
        // not a public PKI credential and the private key is never serialized.
        [[nodiscard]] static auto generate_ed25519() -> std::expected<ServerCredential,ServerCredentialError>;
        // Replace the leaf while retaining the same key; validates key match.
        [[nodiscard]] auto with_certificate(std::span<std::uint8_t const> certificate) const
            -> std::expected<ServerCredential,ServerCredentialError>;
        // Copies certificate storage and retains the key for another independent
        // handshake; concurrent signing uses separate contexts.
        [[nodiscard]] auto clone() const -> std::expected<ServerCredential,ServerCredentialError>;
        [[nodiscard]] auto scheme() const noexcept -> std::optional<std::uint16_t>;
        [[nodiscard]] auto signature_schemes() const noexcept -> std::span<std::uint16_t const>;
        [[nodiscard]] auto max_signature_size() const noexcept -> std::optional<std::size_t>;
        // Borrowed DER leaf certificate; valid only while the credential remains alive and unmoved.
        [[nodiscard]] auto certificate() const noexcept -> std::span<std::uint8_t const>;
        // Intermediate certificates in configured order; borrowed until destruction or move.
        [[nodiscard]] auto chain() const noexcept -> std::span<crypto::Bytes const>;
        // Returns a complete TLS 1.3 CertificateVerify handshake message.
        [[nodiscard]] auto sign(crypto::Hash hash, std::span<std::uint8_t const> transcript_hash) const
            -> std::expected<crypto::Bytes,ServerCredentialError>;
        [[nodiscard]] auto sign(std::uint16_t signature_scheme,crypto::Hash hash, std::span<std::uint8_t const> transcript_hash) const
            -> std::expected<crypto::Bytes,ServerCredentialError>;
    };

    // Thread-safe hot-swappable holder for ACME and dynamic TLS ServerCredential updates.
    class AtomicServerCredential {
        mutable std::mutex mutex_;
        std::shared_ptr<ServerCredential const> current_;
        std::atomic<std::uint64_t> generation_{0};
    public:
        AtomicServerCredential() = default;
        auto update(ServerCredential credential) -> std::uint64_t;
        [[nodiscard]] auto update_pem(std::string_view cert_pem, std::string_view key_pem)
            -> std::expected<std::uint64_t, ServerCredentialError>;
        [[nodiscard]] auto clone_current() const -> std::expected<ServerCredential, ServerCredentialError>;
        [[nodiscard]] auto generation() const noexcept -> std::uint64_t {
            return generation_.load(std::memory_order_acquire);
        }
        [[nodiscard]] auto empty() const noexcept -> bool { return generation() == 0; }
    };
}
