export module acme.jws;
import std;
export import acme.types;

export namespace acme {
    [[nodiscard]] auto base64url_encode(std::span<std::uint8_t const> bytes) -> std::string;
    [[nodiscard]] auto base64url_decode(std::string_view text) -> std::expected<std::vector<std::uint8_t>, std::string>;
    [[nodiscard]] auto sha256_bytes(std::span<std::uint8_t const> bytes) -> std::expected<std::array<std::uint8_t, 32>, std::string>;

    class EcAccountKey {
        std::string private_pem_;
        std::array<std::uint8_t, 32> x_{};
        std::array<std::uint8_t, 32> y_{};
        EcAccountKey(std::string pem, std::array<std::uint8_t, 32> x, std::array<std::uint8_t, 32> y) noexcept
            : private_pem_(std::move(pem)), x_(x), y_(y) {}
    public:
        [[nodiscard]] static auto generate_p256() -> std::expected<EcAccountKey, std::string>;
        [[nodiscard]] static auto from_pem(std::string_view pem) -> std::expected<EcAccountKey, std::string>;
        [[nodiscard]] auto to_pem() const noexcept -> std::string_view { return private_pem_; }
        [[nodiscard]] auto jwk_json() const -> std::string;
        [[nodiscard]] auto jwk_thumbprint() const -> std::expected<std::string, std::string>;
        [[nodiscard]] auto key_authorization(std::string_view token) const -> std::expected<std::string, std::string>;
        [[nodiscard]] auto dns01_txt_value(std::string_view token) const -> std::expected<std::string, std::string>;
        [[nodiscard]] auto tls_alpn01_digest(std::string_view token) const -> std::expected<std::array<std::uint8_t, 32>, std::string>;
        [[nodiscard]] auto sign_es256_raw(std::span<std::uint8_t const> msg) const -> std::expected<std::array<std::uint8_t, 64>, std::string>;
    };

    [[nodiscard]] auto sign_jws(EcAccountKey const& key, std::string_view url, std::string_view nonce,
                                std::string_view payload_json, std::string_view kid = {}) -> std::expected<std::string, std::string>;
    [[nodiscard]] auto sign_eab_jws(EcAccountKey const& account_key, std::string_view new_account_url,
                                    std::string_view eab_kid, std::span<std::uint8_t const> eab_hmac_key)
        -> std::expected<std::string, std::string>;

    struct GeneratedCsr {
        std::string csr_der_base64url;
        std::string key_pem;
    };
    [[nodiscard]] auto generate_csr_p256(std::span<std::string const> domains) -> std::expected<GeneratedCsr, std::string>;

    struct AlpnValidationCert {
        std::string cert_pem;
        std::string key_pem;
    };
    [[nodiscard]] auto generate_alpn01_cert(std::string_view domain, std::array<std::uint8_t, 32> const& acme_digest)
        -> std::expected<AlpnValidationCert, std::string>;

    struct CertValidity {
        std::int64_t not_before_epoch = 0;
        std::int64_t not_after_epoch = 0;
    };
    [[nodiscard]] auto parse_cert_validity(std::string_view cert_pem) -> std::expected<CertValidity, std::string>;
}
