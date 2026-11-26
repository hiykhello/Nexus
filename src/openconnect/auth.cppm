export module openconnect.auth;
import std;
import crypto;
import tls.server_credential;
export import openconnect.types;

export namespace openconnect {
    // Pure BoringSSL-libcrypto mTLS client certificate credential for OpenConnect
    // XML/HTTP mutual-TLS authentication phase.
    class ClientMtlsAuth {
        tls::ServerCredential cred_;
        std::array<std::uint8_t, 32> leaf_sha256_{};
        std::string fingerprint_hex_;
        explicit ClientMtlsAuth(tls::ServerCredential&& cred, std::array<std::uint8_t, 32> fp, std::string hex) noexcept;
    public:
        [[nodiscard]] static auto load(std::span<std::uint8_t const> cert_pem_or_der,
                                       std::span<std::uint8_t const> key_pem_or_der)
            -> std::expected<ClientMtlsAuth, std::string>;

        [[nodiscard]] static auto generate_ephemeral_ed25519()
            -> std::expected<ClientMtlsAuth, std::string>;

        [[nodiscard]] auto certificate_der() const noexcept -> std::span<std::uint8_t const>;
        [[nodiscard]] auto chain_der() const noexcept -> std::span<crypto::Bytes const>;
        [[nodiscard]] auto sha256_fingerprint() const noexcept -> std::span<std::uint8_t const, 32> { return leaf_sha256_; }
        [[nodiscard]] auto fingerprint_hex() const noexcept -> std::string_view { return fingerprint_hex_; }
        [[nodiscard]] auto signature_schemes() const noexcept -> std::span<std::uint16_t const>;
        [[nodiscard]] auto sign_certificate_verify(std::uint16_t scheme, crypto::Hash hash,
                                                   std::span<std::uint8_t const> transcript_hash) const
            -> std::expected<crypto::Bytes, std::string>;
        [[nodiscard]] auto credential() const noexcept -> tls::ServerCredential const& { return cred_; }
    };

    [[nodiscard]] auto build_config_auth_xml(AuthRequest const& req) -> std::string;
    [[nodiscard]] auto build_http_auth_request(std::string_view host, AuthRequest const& req,
                                               bool init_only = false) -> std::string;
    [[nodiscard]] auto parse_config_auth_response(std::string_view xml) -> std::expected<AuthResult, std::string>;
    [[nodiscard]] auto build_cstp_connect_headers(std::string_view host, std::string_view cookie,
                                                  std::uint16_t mtu = 1400,
                                                  std::string_view dtls_master_secret_hex = {},
                                                  std::string_view user_agent = "AnyConnect Linux_64 5.0",
                                                  bool offer_dtls13 = true) -> std::string;
    [[nodiscard]] auto parse_cstp_connect_headers(std::string_view raw_headers) -> std::expected<AuthResult, std::string>;
}
