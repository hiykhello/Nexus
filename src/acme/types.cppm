export module acme.types;
import std;
import nexus.compat;

export namespace acme {
    enum class ChallengeType : std::uint8_t { http01, tls_alpn01, dns01 };

    struct AcmeConfig {
        std::string directory_url;
        std::vector<std::string> domains;
        std::string email;
        ChallengeType challenge = ChallengeType::http01;
        std::filesystem::path state_dir;
        std::int64_t renew_before_seconds = 30 * 24 * 3600;
        std::uint32_t max_poll_attempts = 10;
    };

    struct AcmeDirectory {
        std::string new_nonce;
        std::string new_account;
        std::string new_order;
    };

    struct AcmeChallenge {
        ChallengeType type = ChallengeType::http01;
        std::string url;
        std::string token;
        std::string status;
        std::string key_authorization;
        std::string validation_record; // HTTP path, ALPN domain, or DNS TXT value
    };

    struct AcmeOrder {
        std::string url;
        std::string status;
        std::string finalize_url;
        std::string certificate_url;
        std::vector<std::string> authorizations;
    };

    struct CertificateBundle {
        std::string cert_pem;
        std::string key_pem;
        std::int64_t not_before_epoch = 0;
        std::int64_t not_after_epoch = 0;
        std::vector<std::string> domains;
    };

    struct HttpRequest {
        std::string_view method;
        std::string_view url;
        std::string_view content_type;
        std::string_view body;
    };

    struct HttpResponse {
        unsigned status = 0;
        std::string replay_nonce;
        std::string location;
        std::string body;
    };

    using HttpExchangeFn = nexus::function_ref<std::expected<HttpResponse, std::string>(HttpRequest const&)>;

    struct ChallengeHooks {
        std::optional<nexus::function_ref<bool(std::string_view token, std::string_view key_auth)>> publish_http01;
        std::optional<nexus::function_ref<bool(std::string_view domain, std::string_view cert_pem, std::string_view key_pem)>> publish_alpn01;
        std::optional<nexus::function_ref<bool(std::string_view domain, std::string_view txt_value)>> publish_dns01;
        std::optional<nexus::function_ref<void()>> cleanup;
    };
}
