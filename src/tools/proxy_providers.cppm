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
        std::uint64_t fetched_at = 0;
        std::string http_client_sig;
        provider::ProviderFormat format = provider::ProviderFormat::auto_detect;
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

    [[nodiscard]] inline auto canonical_provider_url(std::string_view raw) -> std::string {
        auto hash = raw.find('#');
        if (hash != raw.npos) raw = raw.substr(0, hash);
        auto scheme_end = raw.find("://");
        if (scheme_end == raw.npos) return std::string(raw);
        std::string scheme(raw.substr(0, scheme_end));
        for (auto& ch : scheme)
            if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
        auto rest = raw.substr(scheme_end + 3);
        auto sep = rest.find_first_of("/?");
        auto authority = rest.substr(0, sep);
        std::string_view target = sep == rest.npos ? std::string_view{} : rest.substr(sep);
        std::string host, port;
        if (authority.starts_with('[')) {
            auto close = authority.find(']');
            if (close != authority.npos) {
                host = std::string(authority.substr(0, close + 1));
                if (close + 1 < authority.size() && authority[close + 1] == ':')
                    port = std::string(authority.substr(close + 2));
            } else host = std::string(authority);
        } else {
            auto colon = authority.rfind(':');
            if (colon != authority.npos) {
                host = std::string(authority.substr(0, colon));
                port = std::string(authority.substr(colon + 1));
            } else host = std::string(authority);
        }
        for (auto& ch : host)
            if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
        if ((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) port.clear();
        std::string out = scheme + "://" + host;
        if (!port.empty()) out += ":" + port;
        if (target.empty()) out += '/';
        else if (target.starts_with('?')) { out += '/'; out.append(target); }
        else out.append(target);
        return out;
    }

    [[nodiscard]] auto provider_cache_paths(std::filesystem::path const& cache_root, std::string_view name, std::string_view url)
        -> std::tuple<std::filesystem::path, std::filesystem::path, std::filesystem::path>;
    [[nodiscard]] auto provider_cache_meta_path(std::filesystem::path const& cache_root, std::string_view name, std::string_view url)
        -> std::filesystem::path;
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
            std::string body, etag, client_sig;
            std::optional<provider::SubscriptionUserinfo> userinfo;
            std::vector<std::pair<std::string, std::string>> outbounds_kdl;
            std::vector<std::string> warnings;
            std::uint64_t fetched_at = 0;
            std::chrono::steady_clock::time_point fetched_steady{};
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

        static auto materialize_entry(Entry& entry, config::Config const& manifest,
            std::filesystem::path const& base_dir, std::string next_body, std::string next_etag,
            std::optional<provider::SubscriptionUserinfo> next_ui) -> std::expected<void, std::string>;
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

        ~ProxyProviderManager() { stop(); }
        [[nodiscard]] auto prepare_candidate(std::string_view raw_kdl, std::string_view config_path,
            bool offline_fallback = true) const -> std::expected<StagedReload, std::string>;
        auto commit_candidate(StagedReload&& staged) -> void {
            bool now_empty = staged.entries_.empty();
            {
                std::lock_guard lock(mutex_);
                manifest_ = std::move(staged.manifest_);
                base_dir_ = std::move(staged.base_dir_);
                entries_ = std::move(staged.entries_);
                ++generation_;
            }
            if (now_empty) stop();
        }
        [[nodiscard]] auto prepare_initial(std::string_view raw_kdl, std::string_view config_path,
            bool offline_fallback = true) -> std::expected<std::string, std::string> {
            auto staged = prepare_candidate(raw_kdl, config_path, offline_fallback);
            if (!staged) return std::unexpected(std::move(staged.error()));
            auto out = std::move(staged->expanded_kdl);
            commit_candidate(std::move(*staged));
            return out;
        }
        [[nodiscard]] auto expand_kdl(std::string_view raw_kdl) const -> std::expected<std::string, std::string> {
            std::map<std::string, std::vector<std::pair<std::string, std::string>>> map;
            {
                std::lock_guard lock(mutex_);
                if (entries_.empty()) return std::string(raw_kdl);
                for (auto const& e : entries_) map.emplace(e.spec.name, e.outbounds_kdl);
            }
            return provider::expand_providers_in_kdl(raw_kdl, map);
        }
        [[nodiscard]] auto sync_once(bool offline_fallback = false) -> std::expected<bool, std::string>;
        [[nodiscard]] auto summaries() const -> std::vector<ProviderSummary> {
            std::lock_guard lock(mutex_);
            std::vector<ProviderSummary> out;
            out.reserve(entries_.size());
            for (auto const& e : entries_)
                out.push_back({e.spec.name, e.spec.type, e.outbounds_kdl.size(), e.etag, e.userinfo, e.warnings});
            return out;
        }
        [[nodiscard]] auto next_refresh_for(std::string_view name) const
            -> std::optional<std::chrono::steady_clock::time_point> {
            std::lock_guard lock(mutex_);
            auto it = std::ranges::find_if(entries_, [&](Entry const& e) { return e.spec.name == name; });
            return it != entries_.end() ? std::optional(it->next_refresh) : std::nullopt;
        }
        [[nodiscard]] auto fetched_at_for(std::string_view name) const -> std::optional<std::uint64_t> {
            std::lock_guard lock(mutex_);
            auto it = std::ranges::find_if(entries_, [&](Entry const& e) { return e.spec.name == name; });
            return it != entries_.end() ? std::optional(it->fetched_at) : std::nullopt;
        }
        [[nodiscard]] auto has_providers() const noexcept -> bool {
            std::lock_guard lock(mutex_);
            return !entries_.empty();
        }
        [[nodiscard]] auto has_http_providers() const noexcept -> bool {
            std::lock_guard lock(mutex_);
            return std::ranges::any_of(entries_, [](Entry const& e) {
                return e.spec.type == config::ProxyProviderType::http;
            });
        }
        [[nodiscard]] auto consume_updated() noexcept -> bool { return updated_.exchange(false, std::memory_order_acq_rel); }
        auto start_background(logging::Runtime& logs) -> void;
        auto stop() noexcept -> void {
            if (worker_.joinable()) {
                worker_.request_stop();
                wake_cv_.notify_all();
                worker_.join();
            }
            http_pool_.reset();
        }
    };
}
