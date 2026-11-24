export module provider;
import std;
export import provider.types;

export namespace provider {
    using SecretWriter = std::function<std::expected<std::string, std::string>(
        std::string_view key_hint, std::string_view content)>;

    [[nodiscard]] auto parse_subscription_userinfo(std::string_view header)
        -> std::optional<SubscriptionUserinfo>;
    [[nodiscard]] auto parse_share_uri(std::string_view uri) -> std::expected<ParsedProxy, std::string>;
    [[nodiscard]] auto parse_subscription(std::string_view body, ProviderFormat fmt = ProviderFormat::auto_detect)
        -> std::expected<ParsedDocument, std::string>;
    [[nodiscard]] auto apply_filter(std::vector<ParsedProxy>& proxies, ProviderFilter const& filter)
        -> std::expected<void, std::string>;
    [[nodiscard]] auto emit_outbound_kdl(ParsedProxy const& proxy, SecretWriter write_secret,
                                         std::string_view fallback_ca) -> std::expected<std::string, std::string>;
    [[nodiscard]] auto convert_config_to_kdl(std::string_view input, ConvertOptions const& opts)
        -> std::expected<std::pair<std::string, std::vector<std::string>>, std::string>;
    [[nodiscard]] auto expand_providers_in_kdl(
        std::string_view raw_kdl,
        std::map<std::string, std::vector<std::pair<std::string, std::string>>> const& provider_outbounds_kdl)
        -> std::expected<std::string, std::string>;
}
