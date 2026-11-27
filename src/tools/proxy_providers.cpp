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
import blake3;
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
            for (unsigned char c : raw) out.push_back((std::isalnum(c) || c == '-' || c == '_') ? static_cast<char>(c) : '-');
            return out.empty() ? std::string("provider") : out;
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
        auto provider_cache_stem(std::string_view name, std::string_view canonical_url) -> std::string {
            auto key = sanitize_key(name);
            if (key.size() > 64) key.resize(64);
            blake3::blake3_hasher hasher{};
            blake3::blake3_hasher_init(&hasher);
            blake3::blake3_hasher_update(&hasher, canonical_url.data(), canonical_url.size());
            std::array<std::uint8_t, 16> digest{};
            blake3::blake3_hasher_finalize(&hasher, digest.data(), digest.size());
            static constexpr char kHex[] = "0123456789abcdef";
            key.push_back('-');
            for (auto b : digest) { key.push_back(kHex[b >> 4]); key.push_back(kHex[b & 0x0fu]); }
            return key;
        }
        auto parse_provider_meta(std::string_view text, ManagedProviderFetchResult& res) noexcept -> void {
            std::uint64_t ts = 0; std::string sig; unsigned fmt = 0;
            bool ok_ts = false, ok_sig = false, ok_fmt = false;
            constexpr auto kMaxFmt = static_cast<unsigned>(provider::ProviderFormat::sip008_json);
            while (!text.empty()) {
                auto nl = text.find('\n');
                auto line = nl == text.npos ? text : text.substr(0, nl);
                text = nl == text.npos ? std::string_view{} : text.substr(nl + 1);
                if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
                if (line.starts_with("fetched_at=")) {
                    auto sv = line.substr(11);
                    auto [end, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), ts);
                    ok_ts = !ok_ts && ec == std::errc{} && end == sv.data() + sv.size() && ts > 0;
                } else if (line.starts_with("client=")) {
                    auto sv = line.substr(7);
                    ok_sig = !ok_sig && !sv.empty();
                    if (ok_sig) sig.assign(sv);
                } else if (line.starts_with("format=")) {
                    auto sv = line.substr(7);
                    auto [end, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), fmt);
                    ok_fmt = !ok_fmt && ec == std::errc{} && end == sv.data() + sv.size() && fmt <= kMaxFmt;
                }
            }
            if (ok_ts && ok_sig && ok_fmt) {
                res.fetched_at = ts; res.http_client_sig = std::move(sig);
                res.format = static_cast<provider::ProviderFormat>(fmt);
            } else { res.fetched_at = 0; res.http_client_sig.clear(); res.format = provider::ProviderFormat::auto_detect; }
        }

        auto resolve_cache_root(config::Config const& manifest, config::ProxyProviderConfig const& spec) -> std::filesystem::path {
            if (!spec.cache_dir.empty()) return std::filesystem::path(spec.cache_dir);
            if (manifest.state && !manifest.state->cache_directory.empty()) return std::filesystem::path(manifest.state->cache_directory);
            return {};
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

    auto provider_cache_paths(std::filesystem::path const& cache_root, std::string_view name, std::string_view url)
        -> std::tuple<std::filesystem::path, std::filesystem::path, std::filesystem::path> {
        auto dir = cache_root / "providers";
        auto stem = provider_cache_stem(name, canonical_provider_url(url));
        return {dir / (stem + ".sub"), dir / (stem + ".etag"), dir / (stem + ".userinfo")};
    }

    auto provider_cache_meta_path(std::filesystem::path const& cache_root, std::string_view name, std::string_view url)
        -> std::filesystem::path {
        return (cache_root / "providers") / (provider_cache_stem(name, canonical_provider_url(url)) + ".meta");
    }

    auto read_provider_cache(std::filesystem::path const& cache_root, std::string_view name, std::string_view url)
        -> std::optional<ManagedProviderFetchResult> {
        auto canon = canonical_provider_url(url);
        if (canon.empty()) return std::nullopt;
        auto dir = cache_root / "providers";
        auto stem = provider_cache_stem(name, canon);
        auto stored_url = ::rulefile::read_regular_file((dir / (stem + ".url")).string());
        if (!stored_url || *stored_url != canon) return std::nullopt;
        auto body = ::rulefile::read_regular_file((dir / (stem + ".sub")).string());
        if (!body || body->empty()) return std::nullopt;
        ManagedProviderFetchResult res;
        res.body = std::move(*body);
        res.unchanged = true;
        if (auto et = ::rulefile::read_regular_file((dir / (stem + ".etag")).string())) res.etag = std::move(*et);
        if (auto ui = ::rulefile::read_regular_file((dir / (stem + ".userinfo")).string()))
            res.userinfo = provider::parse_subscription_userinfo(*ui);
        if (auto meta = ::rulefile::read_regular_file((dir / (stem + ".meta")).string()))
            parse_provider_meta(*meta, res);
        return res;
    }

    auto write_provider_cache(std::filesystem::path const& cache_root, std::string_view name, std::string_view url,
        ManagedProviderFetchResult const& res) -> std::expected<void, std::string> {
        auto canon = canonical_provider_url(url);
        if (canon.empty()) return std::unexpected("provider cache requires resource URL");
        auto dir = cache_root / "providers";
        auto stem = provider_cache_stem(name, canon);
        if (auto ok = ensure_dir_0700(dir); !ok) return ok;
        if (auto ok = write_file_0600(dir / (stem + ".url"), canon); !ok) return ok;
        if (auto ok = write_file_0600(dir / (stem + ".sub"), res.body); !ok) return ok;
        if (auto ok = write_file_0600(dir / (stem + ".etag"), res.etag); !ok) return ok;
        auto meta = std::format("fetched_at={}\nclient={}\nformat={}\n",
            res.fetched_at, res.http_client_sig, static_cast<unsigned>(res.format));
        if (auto ok = write_file_0600(dir / (stem + ".meta"), meta); !ok) return ok;
        auto ui_p = dir / (stem + ".userinfo");
        if (res.userinfo) {
            if (auto ok = write_file_0600(ui_p, format_userinfo_file(*res.userinfo)); !ok) return ok;
        } else {
            std::error_code ec;
            std::filesystem::remove(ui_p, ec);
        }
        return {};
    }

    auto ProxyProviderManager::materialize_entry(Entry& entry, config::Config const& manifest,
        std::filesystem::path const& base_dir, std::string next_body, std::string next_etag,
        std::optional<provider::SubscriptionUserinfo> next_ui) -> std::expected<void, std::string> {
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
        std::vector<std::pair<std::filesystem::path, std::string>> all_staged_secrets;
        std::string fallback_ca = !entry.spec.filter.ca_file.empty() ? entry.spec.filter.ca_file :
            (manifest.certificate ? manifest.certificate->ca_file : std::string{});

        std::vector<std::pair<std::string, std::string>> next_outbounds;
        for (auto const& proxy : doc.proxies) {
            std::set<std::string> pending_secrets;
            std::vector<std::pair<std::filesystem::path, std::string>> node_staged;
            provider::SecretWriter writer = [&](std::string_view hint, std::string_view content) -> std::expected<std::string, std::string> {
                auto stem = pname + "-" + sanitize_key(hint);
                auto unique = stem;
                for (std::size_t n = 2; used_secrets.contains(unique) || pending_secrets.contains(unique); ++n)
                    unique = stem + "-" + std::to_string(n);
                pending_secrets.insert(unique);
                auto f = sec_abs / (unique + ".secret");
                node_staged.emplace_back(f, std::string(content));
                return f.string();
            };
            auto kdl = provider::emit_outbound_kdl(proxy, writer, fallback_ca);
            if (!kdl) { doc.warnings.push_back(kdl.error()); continue; }
            for (auto const& u : pending_secrets) used_secrets.insert(u);
            for (auto& item : node_staged) all_staged_secrets.push_back(std::move(item));
            next_outbounds.emplace_back(proxy.tag, std::move(*kdl));
        }
        if (next_outbounds.empty())
            return std::unexpected("proxy-provider '" + entry.spec.name + "' yielded no valid Nexus outbounds");
        for (auto const& [f, content] : all_staged_secrets)
            if (auto ok = write_file_0600(f, content); !ok) return std::unexpected(ok.error());

        entry.body = std::move(next_body);
        entry.etag = std::move(next_etag);
        entry.userinfo = next_ui;
        entry.outbounds_kdl = std::move(next_outbounds);
        entry.warnings = std::move(doc.warnings);
        return {};
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
            entry.fetched_at = fetched->fetched_at ? fetched->fetched_at : cli::current_unix_seconds();
            entry.fetched_steady = std::chrono::steady_clock::now();
            entry.client_sig = cli::http_client_signature(manifest, entry.spec.http_client);
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
        if (auto ok = materialize_entry(entry, manifest, base_dir, std::move(next_body), std::move(next_etag), next_ui); !ok)
            return std::unexpected(std::move(ok.error()));
        return true;
    }

    auto ProxyProviderManager::prepare_candidate(std::string_view raw_kdl, std::string_view config_path,
        bool offline_fallback) const -> std::expected<StagedReload, std::string> {
        auto manifest = config::parse_provider_manifest(raw_kdl);
        if (!manifest) return std::unexpected(manifest.error());
        StagedReload staged{};
        staged.manifest_ = std::move(*manifest);
        if (staged.manifest_.proxy_providers.empty()) {
            staged.expanded_kdl.assign(raw_kdl);
            return staged;
        }
        std::vector<Entry> prior;
        {
            std::lock_guard lock(mutex_);
            prior = entries_;
        }
        auto bdir = base_directory_for(config_path);
        std::vector<Entry> next_entries;
        next_entries.reserve(staged.manifest_.proxy_providers.size());
        auto now = std::chrono::steady_clock::now();
        auto now_unix = cli::current_unix_seconds();
        std::map<std::string, std::vector<std::pair<std::string, std::string>>> map;
        for (auto const& spec : staged.manifest_.proxy_providers) {
            bool reused = false;
            if (spec.type == config::ProxyProviderType::http) {
                auto canon = canonical_provider_url(spec.url);
                auto csig = cli::http_client_signature(staged.manifest_, spec.http_client);
                auto pit = std::ranges::find_if(prior, [&](Entry const& e) { return e.spec.name == spec.name; });
                if (pit != prior.end()) {
                    bool const same_fetch = pit->spec.type == config::ProxyProviderType::http &&
                        canonical_provider_url(pit->spec.url) == canon && pit->client_sig == csig &&
                        pit->spec.format == spec.format && !pit->body.empty();
                    if (same_fetch) {
                        auto rem_unix = cli::compute_remaining_refresh_ms(pit->fetched_at, now_unix, spec.update_interval_ms);
                        auto steady_elapsed_ms = (pit->fetched_steady != std::chrono::steady_clock::time_point{})
                            ? std::chrono::duration_cast<std::chrono::milliseconds>(now - pit->fetched_steady).count() : 0;
                        if (rem_unix && steady_elapsed_ms >= 0 &&
                            static_cast<std::uint64_t>(steady_elapsed_ms) < spec.update_interval_ms) {
                            Entry e = *pit;
                            e.spec = spec;
                            if (pit->spec.update_interval_ms != spec.update_interval_ms) {
                                auto rem_ms = std::min<std::uint64_t>(*rem_unix,
                                    static_cast<std::uint64_t>(spec.update_interval_ms) - static_cast<std::uint64_t>(steady_elapsed_ms));
                                e.next_refresh = now + std::chrono::milliseconds(rem_ms);
                            }
                            if (pit->spec.filter != spec.filter || pit->spec.cache_dir != spec.cache_dir || e.outbounds_kdl.empty()) {
                                if (auto ok = materialize_entry(e, staged.manifest_, bdir, pit->body, pit->etag, pit->userinfo); !ok)
                                    return std::unexpected(std::move(ok.error()));
                            }
                            map.emplace(e.spec.name, e.outbounds_kdl);
                            next_entries.push_back(std::move(e));
                            reused = true;
                        }
                    }
                } else if (prior.empty()) {
                    auto cache_root = resolve_cache_root(staged.manifest_, spec);
                    if (!cache_root.empty()) {
                        auto cached = read_provider_cache(cache_root, spec.name, spec.url);
                        if (cached && !cached->body.empty() && !cached->http_client_sig.empty() &&
                            cached->http_client_sig == csig && cached->format == spec.format) {
                            if (auto rem = cli::compute_remaining_refresh_ms(cached->fetched_at, now_unix, spec.update_interval_ms)) {
                                Entry e{.spec = spec, .client_sig = csig, .fetched_at = cached->fetched_at};
                                if (materialize_entry(e, staged.manifest_, bdir, std::move(cached->body),
                                        std::move(cached->etag), cached->userinfo).has_value()) {
                                    auto elapsed_ms = static_cast<std::uint64_t>(spec.update_interval_ms) - *rem;
                                    e.fetched_steady = now - std::chrono::milliseconds(elapsed_ms);
                                    e.next_refresh = now + std::chrono::milliseconds(*rem);
                                    map.emplace(e.spec.name, e.outbounds_kdl);
                                    next_entries.push_back(std::move(e));
                                    reused = true;
                                }
                            }
                        }
                    }
                }
            }
            if (reused) continue;
            Entry e{.spec = spec, .next_refresh = now + std::chrono::milliseconds(spec.update_interval_ms)};
            if (auto ok = load_entry(e, staged.manifest_, bdir, offline_fallback); !ok) return std::unexpected(ok.error());
            e.next_refresh = (e.fetched_steady != std::chrono::steady_clock::time_point{} ? e.fetched_steady : now) +
                std::chrono::milliseconds(spec.update_interval_ms);
            map.emplace(e.spec.name, e.outbounds_kdl);
            next_entries.push_back(std::move(e));
        }
        auto expanded = provider::expand_providers_in_kdl(raw_kdl, map);
        if (!expanded) return std::unexpected(std::move(expanded.error()));
        staged.base_dir_ = std::move(bdir);
        staged.entries_ = std::move(next_entries);
        staged.expanded_kdl = std::move(*expanded);
        return staged;
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
                        entries_[idx].fetched_at = copy.fetched_at;
                        entries_[idx].fetched_steady = copy.fetched_steady;
                    }
                }
                if (any_changed) updated_.store(true, std::memory_order_release);
            }
        });
    }
}
