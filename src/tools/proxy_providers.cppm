export module cli.proxy_providers;
import std;
import config;
import logging;
import logging.cli;
import provider;

export namespace cli {
    struct ManagedProviderFetchResult {
        std::string body;
        std::string etag;
        std::optional<provider::SubscriptionUserinfo> userinfo;
        bool unchanged = false;
    };

    using ManagedProviderFetcher = std::expected<ManagedProviderFetchResult, std::string> (*)(
        config::Config const& cfg, config::ProxyProviderConfig const& spec,
        std::string_view previous_etag, bool offline_fallback, std::stop_token stop, void* client_pool);

    auto register_managed_provider_fetcher(ManagedProviderFetcher fetcher) noexcept -> void;

    [[nodiscard]] auto fetch_managed_provider(
        config::Config const& cfg, config::ProxyProviderConfig const& spec,
        std::string_view previous_etag = {}, bool offline_fallback = true,
        std::stop_token stop = {}, void* client_pool = nullptr)
        -> std::expected<ManagedProviderFetchResult, std::string>;

    [[nodiscard]] auto canonical_provider_url(std::string_view url) -> std::string;
    [[nodiscard]] auto provider_cache_paths(std::filesystem::path const& cache_root, std::string_view name, std::string_view url)
        -> std::tuple<std::filesystem::path, std::filesystem::path, std::filesystem::path>;
    [[nodiscard]] auto read_provider_cache(std::filesystem::path const& cache_root, std::string_view name, std::string_view url)
        -> std::optional<ManagedProviderFetchResult>;
    [[nodiscard]] auto write_provider_cache(std::filesystem::path const& cache_root, std::string_view name, std::string_view url,
        ManagedProviderFetchResult const& res) -> std::expected<void, std::string>;

    struct ProviderSummary {
        std::string name;
        config::ProxyProviderType type = config::ProxyProviderType::file;
        std::size_t proxy_count = 0;
        std::string etag;
        std::optional<provider::SubscriptionUserinfo> userinfo;
        std::vector<std::string> warnings;
    };

    class ProxyProviderManager {
        struct Entry {
            config::ProxyProviderConfig spec;
            std::filesystem::file_time_type file_mtime{};
            std::string body, etag;
            std::optional<provider::SubscriptionUserinfo> userinfo;
            std::vector<std::pair<std::string, std::string>> outbounds_kdl;
            std::vector<std::string> warnings;
            std::chrono::steady_clock::time_point next_refresh{};
        };
        mutable std::mutex mutex_;
        config::Config manifest_;
        std::filesystem::path base_dir_;
        std::vector<Entry> entries_;
        std::uint64_t generation_ = 0;
        std::atomic<bool> updated_{false};
        std::mutex wake_mutex_;
        std::condition_variable_any wake_cv_;
        std::shared_ptr<void> http_pool_;
        std::jthread worker_;

        static auto load_entry(Entry& entry, config::Config const& manifest,
            std::filesystem::path const& base_dir, bool offline_fallback,
            std::stop_token stop = {}, void* http_pool = nullptr) -> std::expected<bool, std::string>;
    public:
        class StagedReload {
            friend class ProxyProviderManager;
            config::Config manifest_;
            std::filesystem::path base_dir_;
            std::vector<Entry> entries_;
        public:
            std::string expanded_kdl;
            [[nodiscard]] auto has_providers() const noexcept -> bool { return !entries_.empty(); }
        };

        ~ProxyProviderManager();
        [[nodiscard]] auto prepare_candidate(std::string_view raw_kdl, std::string_view config_path,
            bool offline_fallback = true) const -> std::expected<StagedReload, std::string>;
        auto commit_candidate(StagedReload&& staged) -> void;
        [[nodiscard]] auto prepare_initial(std::string_view raw_kdl, std::string_view config_path,
            bool offline_fallback = true) -> std::expected<std::string, std::string>;
        [[nodiscard]] auto expand_kdl(std::string_view raw_kdl) const -> std::expected<std::string, std::string>;
        [[nodiscard]] auto sync_once(bool offline_fallback = false) -> std::expected<bool, std::string>;
        [[nodiscard]] auto summaries() const -> std::vector<ProviderSummary>;
        [[nodiscard]] auto has_providers() const noexcept -> bool;
        [[nodiscard]] auto has_http_providers() const noexcept -> bool;
        [[nodiscard]] auto consume_updated() noexcept -> bool { return updated_.exchange(false, std::memory_order_acq_rel); }
        auto start_background(logging::Runtime& logs) -> void;
        auto stop() noexcept -> void;
    };
}
