// Signal handling & trust dependency tracking for rule watch clients.
module;
#include <csignal>
#include <sys/stat.h>

export module cli.rule_watch_client;
import std;
import cli.dns_transports;
import cli.rule_fetch_alternative;
import config;
import http.named_client;

export namespace cli::rule_fetch_detail {
    inline volatile std::sig_atomic_t interrupted = 0;
    extern "C" inline void stop_rule_watch(int) { interrupted = 1; }

    struct Signals {
        using Handler = void (*)(int);
        Handler interrupt = std::signal(SIGINT, stop_rule_watch);
        Handler terminate = std::signal(SIGTERM, stop_rule_watch);
        ~Signals() {
            if (interrupt != SIG_ERR) std::signal(SIGINT, interrupt);
            if (terminate != SIG_ERR) std::signal(SIGTERM, terminate);
        }
        auto installed() const noexcept -> bool { return interrupt != SIG_ERR && terminate != SIG_ERR; }
    };

    using FileIdentity = std::tuple<dev_t, ino_t, off_t, time_t, long, time_t, long>;
    using WatchDependencies = std::vector<FileIdentity>;

    struct WatchState {
        std::string config;
        std::optional<Alternative> alternative;
        std::optional<PublishedValidator> validator;
        std::optional<WatchDependencies> dependencies;
        std::unique_ptr<http::NamedHttpClient> client;
    };

    inline auto watch_dependencies(config::Config const& config, std::string_view name)
        -> std::optional<WatchDependencies> {
        using config::NamedHttpClient;
        auto selected = std::ranges::find(config.http_clients, name, &NamedHttpClient::name);
        // Proxied clients also own outbound credentials and state. Rebuild
        // those clients each refresh until their dependencies can be tracked.
        if (selected == config.http_clients.end() || selected->outbound_index || !config.dns ||
            cli::uses_proxy_dns(config.dns)) return {};

        WatchDependencies result;
        auto record = [&](char const* path, bool follow = true) {
            struct stat file{};
            auto status = follow ? ::stat(path, &file) : ::lstat(path, &file);
            if (status != 0 || !S_ISREG(file.st_mode)) return false;
            result.emplace_back(file.st_dev, file.st_ino, file.st_size,
                file.st_mtim.tv_sec, file.st_mtim.tv_nsec, file.st_ctim.tv_sec, file.st_ctim.tv_nsec);
            return true;
        };
        if (!record(selected->ca_file.c_str()) ||
            (!selected->ech_config_file.empty() && !record(selected->ech_config_file.c_str(), false))) return {};
        bool local = false;
        for (auto const& server : config.dns->servers) {
            if (!server.upstream) local = true;
            else if (server.upstream->tls && !record(server.upstream->tls->ca_file.c_str())) return {};
        }
        if (local && (!record("/etc/resolv.conf") || !record("/etc/hosts"))) return {};
        return result;
    }

    // Bounded persistent NamedHttpClient pool owned via std::shared_ptr<void> on managers.
    class ManagedClientPool {
        struct Entry {
            std::string key;
            WatchDependencies deps;
            std::unique_ptr<http::NamedHttpClient> client;
            std::uint64_t seq = 0;
        };
        static constexpr std::size_t max_entries = 16;
        std::mutex mutex_;
        std::vector<Entry> entries_;
        std::uint64_t seq_ = 0;

        static auto make_key(std::string_view name, std::string_view authority) -> std::string {
            std::string key;
            key.reserve(name.size() + 1 + authority.size());
            key.append(name);
            key.push_back('\0');
            key.append(authority);
            return key;
        }
    public:
        struct Acquired {
            std::unique_ptr<http::NamedHttpClient> client;
            std::optional<WatchDependencies> deps;
        };
        auto acquire(config::Config const& config, std::string_view name, std::string_view authority)
            -> std::expected<Acquired, std::string> {
            auto deps = watch_dependencies(config, name);
            if (deps) {
                auto key = make_key(name, authority);
                std::lock_guard lock(mutex_);
                auto it = std::ranges::find(entries_, key, &Entry::key);
                if (it != entries_.end()) {
                    if (it->deps == *deps && it->client) {
                        auto client = std::move(it->client);
                        entries_.erase(it);
                        return Acquired{std::move(client), std::move(deps)};
                    }
                    entries_.erase(it);
                }
            }
            auto created = http::NamedHttpClient::create(config, name, authority);
            if (!created) return std::unexpected(std::move(created.error()));
            return Acquired{std::move(*created), std::move(deps)};
        }
        auto release(std::string_view name, std::string_view authority, std::optional<WatchDependencies> deps,
            std::unique_ptr<http::NamedHttpClient> client) -> void {
            if (!deps || !client) return;
            auto key = make_key(name, authority);
            std::lock_guard lock(mutex_);
            if (auto it = std::ranges::find(entries_, key, &Entry::key); it != entries_.end()) {
                it->deps = std::move(*deps);
                it->client = std::move(client);
                it->seq = ++seq_;
                return;
            }
            if (entries_.size() >= max_entries) {
                auto oldest = std::ranges::min_element(entries_, {}, &Entry::seq);
                if (oldest != entries_.end()) entries_.erase(oldest);
            }
            entries_.push_back(Entry{std::move(key), std::move(*deps), std::move(client), ++seq_});
        }
    };

    inline auto acquire_pooled_client(void* pool_ptr, config::Config const& config, std::string_view name,
        std::string_view authority) -> std::expected<ManagedClientPool::Acquired, std::string> {
        if (pool_ptr) return static_cast<ManagedClientPool*>(pool_ptr)->acquire(config, name, authority);
        auto created = http::NamedHttpClient::create(config, name, authority);
        if (!created) return std::unexpected(std::move(created.error()));
        return ManagedClientPool::Acquired{std::move(*created), std::nullopt};
    }

    inline auto release_pooled_client(void* pool_ptr, std::string_view name, std::string_view authority,
        std::optional<WatchDependencies> deps, std::unique_ptr<http::NamedHttpClient> client) -> void {
        if (pool_ptr && deps && client)
            static_cast<ManagedClientPool*>(pool_ptr)->release(name, authority, std::move(deps), std::move(client));
    }
}
