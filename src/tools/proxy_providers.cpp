module;
#if !defined(_WIN32)
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

module cli.proxy_providers;
import std;
import cli.route_files;
import config;
import logging;
import logging.cli;
import provider;
import rulefile;

namespace cli {
    namespace {
        std::atomic<ManagedProviderFetcher> g_provider_fetcher{nullptr};

        auto sanitize_key(std::string_view raw) -> std::string {
            std::string out;
            for (unsigned char c : raw) {
                if (std::isalnum(c) || c == '-' || c == '_') out.push_back(static_cast<char>(c));
                else out.push_back('-');
            }
            if (out.empty()) out = "provider";
            return out;
        }

        auto ensure_dir_0700(std::filesystem::path const& dir) -> std::expected<void, std::string> {
            std::error_code ec;
            std::filesystem::create_directories(dir, ec);
            if (ec) return std::unexpected("cannot create provider directory: " + ec.message());
#if !defined(_WIN32)
            int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (dfd < 0) return std::unexpected("cannot open provider directory safely: " + dir.string());
            struct stat st{};
            bool ok = (::fstat(dfd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == ::geteuid() && ::fchmod(dfd, 0700) == 0);
            ::close(dfd);
            if (!ok) return std::unexpected("unsafe provider directory ownership or permissions: " + dir.string());
#else
            std::filesystem::permissions(dir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace, ec);
#endif
            return {};
        }

        auto write_file_0600(std::filesystem::path const& path, std::string_view data) -> std::expected<void, std::string> {
#if !defined(_WIN32)
            static std::atomic<std::uint64_t> seq{0};
            auto parent = path.parent_path();
            auto base = path.filename().string();
            if (parent.empty() || base.empty()) return std::unexpected("invalid file path: " + path.string());
            int dfd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (dfd < 0) return std::unexpected("cannot open parent directory: " + parent.string());
            struct DirFd { int fd; ~DirFd() { if (fd >= 0) ::close(fd); } } d{dfd};
            struct stat dst{};
            if (::fstat(dfd, &dst) != 0 || !S_ISDIR(dst.st_mode) || dst.st_uid != ::geteuid())
                return std::unexpected("unsafe parent directory: " + parent.string());
            auto tmp = std::format(".{}.tmp.{}.{}", base, ::getpid(), seq.fetch_add(1, std::memory_order_relaxed));
            int fd = ::openat(dfd, tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (fd < 0) return std::unexpected("cannot create file: " + path.string());
            auto drop = [&] { ::close(fd); (void)::unlinkat(dfd, tmp.c_str(), 0); };
            if (::fchmod(fd, 0600) != 0) { drop(); return std::unexpected("cannot chmod file: " + path.string()); }
            for (std::size_t off = 0; off < data.size();) {
                auto n = ::write(fd, data.data() + off, data.size() - off);
                if (n < 0) { if (errno == EINTR) continue; drop(); return std::unexpected("failed writing file: " + path.string()); }
                off += static_cast<std::size_t>(n);
            }
            if (::close(fd) != 0 || ::renameat(dfd, tmp.c_str(), dfd, base.c_str()) != 0) {
                (void)::unlinkat(dfd, tmp.c_str(), 0);
                return std::unexpected("failed installing file: " + path.string());
            }
            return {};
#else
            std::ofstream out(path, std::ios::out | std::ios::binary | std::ios::trunc);
            if (!out) return std::unexpected("cannot write file: " + path.string());
            out.write(data.data(), static_cast<std::streamsize>(data.size()));
            out.close();
            if (!out) return std::unexpected("failed flushing file: " + path.string());
            std::error_code ec;
            std::filesystem::permissions(path,
                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace, ec);
            return {};
#endif
        }

        auto base_directory_for(std::string_view config_path) -> std::filesystem::path {
            auto wd = cli::working_directory();
            if (config_path.empty()) return wd.value_or(std::filesystem::current_path());
            std::filesystem::path p(config_path);
            if (p.is_relative() && wd) p = *wd / p;
            std::error_code ec;
            if (std::filesystem::is_directory(p, ec) && !ec) return std::filesystem::weakly_canonical(p, ec);
            auto parent = p.parent_path();
            if (parent.empty()) return wd.value_or(std::filesystem::current_path());
            auto canon = std::filesystem::weakly_canonical(parent, ec);
            return ec ? std::filesystem::absolute(parent, ec) : canon;
        }

        auto format_userinfo_file(provider::SubscriptionUserinfo const& u) -> std::string {
            std::ostringstream os;
            if (u.upload) os << "upload=" << *u.upload << "; ";
            if (u.download) os << "download=" << *u.download << "; ";
            if (u.total) os << "total=" << *u.total << "; ";
            if (u.expire) os << "expire=" << *u.expire << ";";
            return os.str();
        }
    }

    auto register_managed_provider_fetcher(ManagedProviderFetcher fetcher) noexcept -> void {
        g_provider_fetcher.store(fetcher, std::memory_order_release);
    }

    auto fetch_managed_provider(config::Config const& cfg, config::ProxyProviderConfig const& spec,
        std::string_view previous_etag, bool offline_fallback, std::stop_token stop, void* client_pool)
        -> std::expected<ManagedProviderFetchResult, std::string> {
        cli::ensure_http_fetchers_registered();
        auto fn = g_provider_fetcher.load(std::memory_order_acquire);
        if (!fn) return std::unexpected("HTTPS proxy-provider requires the http-client build feature");
        return fn(cfg, spec, previous_etag, offline_fallback, std::move(stop), client_pool);
    }

    auto provider_cache_paths(std::filesystem::path const& cache_root, std::string_view name)
        -> std::tuple<std::filesystem::path, std::filesystem::path, std::filesystem::path> {
        auto dir = cache_root / "providers";
        auto stem = sanitize_key(name);
        return {dir / (stem + ".sub"), dir / (stem + ".etag"), dir / (stem + ".userinfo")};
    }

    auto read_provider_cache(std::filesystem::path const& cache_root, std::string_view name)
        -> std::optional<ManagedProviderFetchResult> {
        auto [body_p, etag_p, ui_p] = provider_cache_paths(cache_root, name);
        auto body = ::rulefile::read_regular_file(body_p.string());
        if (!body || body->empty()) return std::nullopt;
        ManagedProviderFetchResult res;
        res.body = std::move(*body);
        res.unchanged = true;
        if (auto et = ::rulefile::read_regular_file(etag_p.string())) res.etag = std::move(*et);
        if (auto ui = ::rulefile::read_regular_file(ui_p.string()))
            res.userinfo = provider::parse_subscription_userinfo(*ui);
        return res;
    }

    auto write_provider_cache(std::filesystem::path const& cache_root, std::string_view name,
        ManagedProviderFetchResult const& res) -> std::expected<void, std::string> {
        auto [body_p, etag_p, ui_p] = provider_cache_paths(cache_root, name);
        if (auto ok = ensure_dir_0700(body_p.parent_path()); !ok) return ok;
        if (auto ok = write_file_0600(body_p, res.body); !ok) return ok;
        if (auto ok = write_file_0600(etag_p, res.etag); !ok) return ok;
        if (res.userinfo) {
            if (auto ok = write_file_0600(ui_p, format_userinfo_file(*res.userinfo)); !ok) return ok;
        }
        return {};
    }

    ProxyProviderManager::~ProxyProviderManager() { stop(); }

    auto ProxyProviderManager::stop() noexcept -> void {
        if (worker_.joinable()) {
            worker_.request_stop();
            wake_cv_.notify_all();
            worker_.join();
        }
        http_pool_.reset();
    }

    auto ProxyProviderManager::load_entry(Entry& entry, config::Config const& manifest,
        std::filesystem::path const& base_dir, bool offline_fallback, std::stop_token stop, void* http_pool)
        -> std::expected<bool, std::string> {
        std::string next_body, next_etag = entry.etag;
        std::optional<provider::SubscriptionUserinfo> next_ui = entry.userinfo;
        if (entry.spec.type == config::ProxyProviderType::file) {
            std::filesystem::path src(entry.spec.path);
            if (src.is_relative()) src = base_dir / src;
            std::error_code ec;
            auto mtime = std::filesystem::last_write_time(src, ec);
            if (!ec && !entry.body.empty() && mtime == entry.file_mtime) return false;
            auto content = ::rulefile::read_regular_file(src.string());
            if (!content) return std::unexpected("proxy-provider '" + entry.spec.name + "': " + content.error());
            next_body = std::move(*content);
            entry.file_mtime = mtime;
        } else {
            auto fetched = fetch_managed_provider(manifest, entry.spec, entry.etag, offline_fallback, std::move(stop), http_pool);
            if (!fetched) return std::unexpected("proxy-provider '" + entry.spec.name + "': " + fetched.error());
            if (!fetched->etag.empty()) next_etag = fetched->etag;
            if (fetched->userinfo) next_ui = fetched->userinfo;
            if (fetched->unchanged && !entry.body.empty()) {
                entry.etag = std::move(next_etag);
                entry.userinfo = next_ui;
                return false;
            }
            next_body = std::move(fetched->body);
        }
        if (next_body == entry.body && !entry.outbounds_kdl.empty()) {
            entry.etag = std::move(next_etag);
            entry.userinfo = next_ui;
            return false;
        }

        auto parsed = provider::parse_subscription(next_body, entry.spec.format);
        if (!parsed) return std::unexpected("proxy-provider '" + entry.spec.name + "': " + parsed.error());
        auto doc = std::move(*parsed);
        if (auto ok = provider::apply_filter(doc.proxies, entry.spec.filter); !ok)
            return std::unexpected("proxy-provider '" + entry.spec.name + "': " + ok.error());

        std::filesystem::path sec_dir;
        if (!entry.spec.cache_dir.empty()) sec_dir = std::filesystem::path(entry.spec.cache_dir) / "secrets";
        else if (manifest.state && !manifest.state->cache_directory.empty())
            sec_dir = std::filesystem::path(manifest.state->cache_directory) / "provider-secrets" / sanitize_key(entry.spec.name);
        else sec_dir = base_dir / ".nexus-provider-secrets" / sanitize_key(entry.spec.name);
        if (auto ok = ensure_dir_0700(sec_dir); !ok) return std::unexpected(ok.error());

        std::error_code ec;
        auto sec_abs = std::filesystem::weakly_canonical(sec_dir, ec);
        if (ec) sec_abs = std::filesystem::absolute(sec_dir, ec);
        std::string pname = sanitize_key(entry.spec.name);

        std::set<std::string> used_secrets;
        provider::SecretWriter writer = [&](std::string_view hint, std::string_view content) -> std::expected<std::string, std::string> {
            auto stem = pname + "-" + sanitize_key(hint);
            auto unique = stem;
            for (std::size_t n = 2; !used_secrets.insert(unique).second; ++n) unique = stem + "-" + std::to_string(n);
            auto f = sec_abs / (unique + ".secret");
            if (auto ok = write_file_0600(f, content); !ok) return std::unexpected(ok.error());
            return f.string();
        };
        std::string fallback_ca = !entry.spec.filter.ca_file.empty() ? entry.spec.filter.ca_file :
            (manifest.certificate ? manifest.certificate->ca_file : std::string{});

        std::vector<std::pair<std::string, std::string>> next_outbounds;
        for (auto const& proxy : doc.proxies) {
            auto kdl = provider::emit_outbound_kdl(proxy, writer, fallback_ca);
            if (!kdl) { doc.warnings.push_back(kdl.error()); continue; }
            next_outbounds.emplace_back(proxy.tag, std::move(*kdl));
        }
        if (next_outbounds.empty())
            return std::unexpected("proxy-provider '" + entry.spec.name + "' yielded no valid Nexus outbounds");

        entry.body = std::move(next_body);
        entry.etag = std::move(next_etag);
        entry.userinfo = next_ui;
        entry.outbounds_kdl = std::move(next_outbounds);
        entry.warnings = std::move(doc.warnings);
        return true;
    }

    auto ProxyProviderManager::prepare_initial(std::string_view raw_kdl, std::string_view config_path,
        bool offline_fallback) -> std::expected<std::string, std::string> {
        auto manifest = config::parse_provider_manifest(raw_kdl);
        if (!manifest) return std::unexpected(manifest.error());
        if (manifest->proxy_providers.empty()) {
            std::lock_guard lock(mutex_);
            manifest_ = std::move(*manifest);
            entries_.clear();
            ++generation_;
            return std::string(raw_kdl);
        }
        auto bdir = base_directory_for(config_path);
        std::vector<Entry> next_entries;
        next_entries.reserve(manifest->proxy_providers.size());
        auto now = std::chrono::steady_clock::now();
        for (auto const& spec : manifest->proxy_providers) {
            Entry e{.spec = spec, .next_refresh = now + std::chrono::milliseconds(spec.update_interval_ms)};
            if (auto ok = load_entry(e, *manifest, bdir, offline_fallback); !ok) return std::unexpected(ok.error());
            next_entries.push_back(std::move(e));
        }
        {
            std::lock_guard lock(mutex_);
            manifest_ = std::move(*manifest);
            base_dir_ = std::move(bdir);
            entries_ = std::move(next_entries);
            ++generation_;
        }
        return expand_kdl(raw_kdl);
    }

    auto ProxyProviderManager::expand_kdl(std::string_view raw_kdl) const -> std::expected<std::string, std::string> {
        std::map<std::string, std::vector<std::pair<std::string, std::string>>> map;
        {
            std::lock_guard lock(mutex_);
            if (entries_.empty()) return std::string(raw_kdl);
            for (auto const& e : entries_) map.emplace(e.spec.name, e.outbounds_kdl);
        }
        return provider::expand_providers_in_kdl(raw_kdl, map);
    }

    auto ProxyProviderManager::sync_once(bool offline_fallback) -> std::expected<bool, std::string> {
        std::vector<Entry> snap;
        config::Config manifest_snap;
        std::filesystem::path bdir_snap;
        std::uint64_t gen_snap = 0;
        {
            std::lock_guard lock(mutex_);
            snap = entries_;
            manifest_snap = manifest_;
            bdir_snap = base_dir_;
            gen_snap = generation_;
        }
        bool any = false;
        for (auto& e : snap) {
            auto changed = load_entry(e, manifest_snap, bdir_snap, offline_fallback);
            if (!changed) return std::unexpected(changed.error());
            if (*changed) any = true;
            e.next_refresh = std::chrono::steady_clock::now() + std::chrono::milliseconds(e.spec.update_interval_ms);
        }
        std::lock_guard lock(mutex_);
        if (generation_ == gen_snap) entries_ = std::move(snap);
        return any;
    }

    auto ProxyProviderManager::summaries() const -> std::vector<ProviderSummary> {
        std::lock_guard lock(mutex_);
        std::vector<ProviderSummary> out;
        out.reserve(entries_.size());
        for (auto const& e : entries_)
            out.push_back({e.spec.name, e.spec.type, e.outbounds_kdl.size(), e.etag, e.userinfo, e.warnings});
        return out;
    }

    auto ProxyProviderManager::has_providers() const noexcept -> bool {
        std::lock_guard lock(mutex_);
        return !entries_.empty();
    }

    auto ProxyProviderManager::has_http_providers() const noexcept -> bool {
        std::lock_guard lock(mutex_);
        return std::ranges::any_of(entries_, [](Entry const& e) {
            return e.spec.type == config::ProxyProviderType::http;
        });
    }

    auto ProxyProviderManager::start_background(logging::Runtime& logs) -> void {
        if (worker_.joinable() || !has_providers()) return;
        if (!http_pool_ && has_http_providers()) http_pool_ = cli::create_managed_http_pool();
        worker_ = std::jthread([this, &logs](std::stop_token token) {
            while (!token.stop_requested()) {
                {
                    std::unique_lock wlk(wake_mutex_);
                    wake_cv_.wait_for(wlk, token, std::chrono::milliseconds(200), [] { return false; });
                }
                if (token.stop_requested()) break;
                auto now = std::chrono::steady_clock::now();
                std::vector<std::pair<std::size_t, Entry>> due;
                config::Config manifest_snap;
                std::filesystem::path bdir_snap;
                std::uint64_t gen_snap = 0;
                {
                    std::lock_guard lock(mutex_);
                    gen_snap = generation_;
                    manifest_snap = manifest_;
                    bdir_snap = base_dir_;
                    for (std::size_t i = 0; i < entries_.size(); ++i)
                        if (now >= entries_[i].next_refresh) due.emplace_back(i, entries_[i]);
                }
                bool any_changed = false;
                for (auto& [idx, copy] : due) {
                    if (token.stop_requested()) break;
                    auto res = load_entry(copy, manifest_snap, bdir_snap, false, token, http_pool_.get());
                    if (token.stop_requested()) break;
                    auto next_at = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(copy.spec.update_interval_ms);
                    std::lock_guard lock(mutex_);
                    if (generation_ != gen_snap || idx >= entries_.size() || entries_[idx].spec.name != copy.spec.name)
                        continue;
                    entries_[idx].next_refresh = next_at;
                    if (!res) {
                        logs.emit(logging::Level::warn, logging::Domain::route, 104, {},
                            "proxy-provider refresh failed: {}", logs.private_text(res.error()));
                        continue;
                    }
                    if (*res) {
                        entries_[idx] = std::move(copy);
                        entries_[idx].next_refresh = next_at;
                        any_changed = true;
                    } else {
                        entries_[idx].etag = std::move(copy.etag);
                        entries_[idx].userinfo = copy.userinfo;
                    }
                }
                if (any_changed) updated_.store(true, std::memory_order_release);
            }
        });
    }
}
