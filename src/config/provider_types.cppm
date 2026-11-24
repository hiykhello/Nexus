export module config.provider_types;
import std;
import provider.types;

export namespace config {
    enum class ProxyProviderType { file, http };

    struct ProxyProviderConfig {
        std::string name;
        ProxyProviderType type = ProxyProviderType::file;
        std::string path, url, http_client, cache_dir;
        provider::ProviderFormat format = provider::ProviderFormat::auto_detect;
        std::uint32_t update_interval_ms = 3600000;
        provider::ProviderFilter filter;
        auto operator==(ProxyProviderConfig const&) const -> bool = default;
    };
}
