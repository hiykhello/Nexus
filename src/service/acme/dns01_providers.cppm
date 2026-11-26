export module acme.dns01_providers;
import std;
import crypto;
export import acme.types;

export namespace acme {
    struct Dns01RecordHandle {
        std::string zone;
        std::string record_id;
        auto operator==(Dns01RecordHandle const&) const -> bool = default;
    };

    [[nodiscard]] auto normalize_acme_domain(std::string_view domain) -> std::expected<std::string, std::string>;
    [[nodiscard]] auto percent_encode_rfc3986(std::string_view input) -> std::string;
    [[nodiscard]] auto alidns_build_signed_query(
        std::span<std::pair<std::string, std::string> const> params,
        std::string_view access_key_secret,
        std::string_view http_method = "GET") -> std::expected<std::string, std::string>;

    class CloudflareDns01Provider {
        std::string api_token_;
        std::string api_base_;
        auto cleanse() noexcept -> void {
            if (!api_token_.empty())
                crypto::cleanse({reinterpret_cast<std::uint8_t*>(api_token_.data()), api_token_.size()});
        }
    public:
        explicit CloudflareDns01Provider(std::string api_token,
            std::string api_base = "https://api.cloudflare.com/client/v4");
        CloudflareDns01Provider(CloudflareDns01Provider const&) = delete;
        auto operator=(CloudflareDns01Provider const&) -> CloudflareDns01Provider& = delete;
        CloudflareDns01Provider(CloudflareDns01Provider&& other) noexcept
            : api_token_(std::move(other.api_token_)), api_base_(std::move(other.api_base_)) {}
        auto operator=(CloudflareDns01Provider&& other) noexcept -> CloudflareDns01Provider& {
            if (this != &other) { cleanse(); api_token_ = std::move(other.api_token_); api_base_ = std::move(other.api_base_); }
            return *this;
        }
        ~CloudflareDns01Provider() { cleanse(); }

        [[nodiscard]] auto publish(std::string_view domain, std::string_view txt_value, HttpExchangeFn http) const
            -> std::expected<Dns01RecordHandle, std::string>;
        [[nodiscard]] auto cleanup(Dns01RecordHandle const& handle, HttpExchangeFn http) const
            -> std::expected<void, std::string>;
    };

    class AliDns01Provider {
        std::string access_key_id_;
        std::string access_key_secret_;
        std::string api_base_;
        auto cleanse() noexcept -> void {
            if (!access_key_id_.empty())
                crypto::cleanse({reinterpret_cast<std::uint8_t*>(access_key_id_.data()), access_key_id_.size()});
            if (!access_key_secret_.empty())
                crypto::cleanse({reinterpret_cast<std::uint8_t*>(access_key_secret_.data()), access_key_secret_.size()});
        }
    public:
        AliDns01Provider(std::string access_key_id, std::string access_key_secret,
            std::string api_base = "https://alidns.aliyuncs.com");
        AliDns01Provider(AliDns01Provider const&) = delete;
        auto operator=(AliDns01Provider const&) -> AliDns01Provider& = delete;
        AliDns01Provider(AliDns01Provider&& other) noexcept
            : access_key_id_(std::move(other.access_key_id_)),
              access_key_secret_(std::move(other.access_key_secret_)),
              api_base_(std::move(other.api_base_)) {}
        auto operator=(AliDns01Provider&& other) noexcept -> AliDns01Provider& {
            if (this != &other) {
                cleanse();
                access_key_id_ = std::move(other.access_key_id_);
                access_key_secret_ = std::move(other.access_key_secret_);
                api_base_ = std::move(other.api_base_);
            }
            return *this;
        }
        ~AliDns01Provider() { cleanse(); }

        [[nodiscard]] auto publish(std::string_view domain, std::string_view txt_value, HttpExchangeFn http,
            std::string_view timestamp_utc = {}, std::string_view nonce = {}) const
            -> std::expected<Dns01RecordHandle, std::string>;
        [[nodiscard]] auto cleanup(Dns01RecordHandle const& handle, HttpExchangeFn http,
            std::string_view timestamp_utc = {}, std::string_view nonce = {}) const
            -> std::expected<void, std::string>;
    };
}
