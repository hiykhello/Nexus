// Private DNS rule file loading, reverse cache creation and remote rule-set lifecycle.
export module cli.proxy_dns_reload;
import std;
import cli.route_files;
import config;
import dns.message_program;
import dns.policy;
import dns.reverse;
import logging;
import logging.cli;
import relay;
import rules;
import rules.rule_input;
import state.core;

export namespace cli::run_detail {
    inline auto make_reverse_cache() -> std::shared_ptr<dns::ReverseCache> {
        std::random_device rd;
        std::array<std::uint64_t, 2> key{
            (std::uint64_t(rd()) << 32) | std::uint64_t(rd()),
            (std::uint64_t(rd()) << 32) | std::uint64_t(rd())
        };
        return std::make_shared<dns::ReverseCache>(dns::ReverseCache::max_capacity, 1, key);
    }

    inline auto load_dns_rules(config::DnsRouting& routing, RuleFileInput& input) -> std::expected<void, std::string> {
        if (routing.rule_files.empty()) return {};
        routing.cache_rule_fingerprints.clear();
        std::vector<std::string> keys;
        std::size_t total = 0, nodes = 0;
        for (auto const& reference : routing.rule_files) {
            std::optional<::rules::RuleSet> parsed;
            if (reference.file.inline_rules) {
                parsed = *reference.file.inline_rules;
                if (!routing.unified_cache_root.empty() || !routing.message_cache_directory.empty() ||
                    (routing.fakeip && routing.fakeip->unified)) {
                    auto hash = ::state::fingerprint(std::as_bytes(std::span(reference.file.inline_kdl)));
                    routing.cache_rule_fingerprints.append(reinterpret_cast<char const*>(hash.data()), hash.size());
                }
            } else {
                auto const& key = !reference.file.url.empty() ? reference.file.url : reference.file.path;
                auto data = input.read(key);
                if (!data) return std::unexpected("DNS rule-set: " + data.error());
                if (!reference.file.url.empty()) {
                    if (auto ok = cli::verify_remote_ruleset_sha256(reference.file, *data); !ok)
                        return std::unexpected("DNS rule-set: " + ok.error());
                }
                if (std::ranges::find(keys, key) == keys.end()) {
                    total += data->size();
                    if (total > ::rules::max_input_bytes) return std::unexpected("DNS rule sets exceed 256 MiB total");
                    keys.push_back(key);
                }
                if (!routing.unified_cache_root.empty() || !routing.message_cache_directory.empty() ||
                    (routing.fakeip && routing.fakeip->unified)) {
                    auto hash = ::state::fingerprint(std::as_bytes(std::span(*data)));
                    routing.cache_rule_fingerprints.append(reinterpret_cast<char const*>(hash.data()), hash.size());
                }
                auto format = cli::rule_input_format(reference.file.format);
                auto decoded = ::rules::parse_rule_input(*data, format, reference.file.ip_cidr_match_source);
                if (!decoded) return std::unexpected("DNS rule-set: " + decoded.error().message);
                parsed = std::move(*decoded);
            }
            auto count = [&](auto&& self, ::rules::Rule const& rule) -> bool {
                if (++nodes > ::rules::max_rules) return false;
                return std::ranges::all_of(rule.children, [&](auto const& child) { return self(self, child); });
            };
            if (!std::ranges::all_of(parsed->rules, [&](auto const& rule) { return count(count, rule); })) {
                return std::unexpected("DNS rule-set predicates exceed limit");
            }
            if (!::policy::bind_dns_rule_set(routing.rules[reference.rule], std::move(*parsed))) {
                return std::unexpected("DNS rule-set contains unsupported conditions or exceeds limits");
            }
        }
        return {};
    }

    struct DnsRuleSource {
        std::shared_ptr<relay::RouteSnapshots> snapshots;
        auto operator()() const -> dns::MessageRuleSnapshot {
            if (!snapshots) return {};
            auto generation = snapshots->load(std::memory_order_acquire);
            if (!generation || generation->empty() || !generation->front().dns) return {};
            auto const& dns = generation->front().dns;
            auto result = dns::MessageRuleSnapshot{{dns, &dns->rules}, dns->view};
            result.transports = generation->front().dns_transports;
            return result;
        }
    };

    inline auto dns_rule_source(std::shared_ptr<relay::RouteSnapshots> snapshots) -> DnsRuleSource {
        return {std::move(snapshots)};
    }

    class RemoteRulesetManager {
        struct Entry {
            config::BlockRules spec;
            std::string body, etag, client_sig;
            std::uint64_t fetched_at = 0;
            std::chrono::steady_clock::time_point fetched_steady{};
            std::chrono::steady_clock::time_point next_refresh{};
        };
        mutable std::mutex mutex_;
        std::vector<Entry> entries_;
        std::uint64_t generation_ = 0;
        std::uint64_t active_generation_ = 0;
        std::string active_source_;
        std::atomic<bool> updated_{false};
        std::mutex wake_mutex_;
        std::condition_variable_any wake_cv_;
        std::shared_ptr<void> http_pool_;
        std::jthread worker_;

        static auto sha256_equal_ci(std::string_view a, std::string_view b) noexcept -> bool {
            if (a.size() != b.size()) return false;
            auto lower = [](char c) noexcept { return (c >= 'A' && c <= 'F') ? static_cast<char>(c - 'A' + 'a') : c; };
            return std::ranges::equal(a, b, {}, lower, lower);
        }

        static auto same_identity(Entry const& e, config::BlockRules const& spec, std::string_view csig) noexcept -> bool {
            return e.spec.url == spec.url && e.spec.format == spec.format &&
                sha256_equal_ci(e.spec.sha256, spec.sha256) && e.client_sig == csig;
        }

        static auto collect(config::Config const& config) -> std::expected<std::vector<config::BlockRules>, std::string> {
            std::vector<config::BlockRules> out;
            auto add = [&](config::BlockRules const& spec) -> std::expected<void, std::string> {
                if (spec.url.empty()) return {};
                auto it = std::ranges::find_if(out, [&](auto const& e) { return e.url == spec.url; });
                if (it != out.end()) {
                    if (!sha256_equal_ci(it->sha256, spec.sha256))
                        return std::unexpected("conflicting sha256 declarations for remote rule-set URL: " + spec.url);
                    return {};
                }
                out.push_back(spec);
                return {};
            };
            for (auto const& r : config.routes)
                if (auto ok = add(r.file); !ok) return std::unexpected(std::move(ok.error()));
            if (config.ordered_tcp) {
                for (auto const& [tag, spec] : config.ordered_tcp->sets)
                    if (auto ok = add(spec); !ok) return std::unexpected(std::move(ok.error()));
                for (auto const& r : config.ordered_tcp->rules)
                    if (r.file) if (auto ok = add(*r.file); !ok) return std::unexpected(std::move(ok.error()));
            }
            if (config.dns) for (auto const& ref : config.dns->rule_files)
                if (auto ok = add(ref.file); !ok) return std::unexpected(std::move(ok.error()));
            return out;
        }
    public:
        class StagedReload {
            friend class RemoteRulesetManager;
            std::vector<Entry> entries_;
        };

        ~RemoteRulesetManager() { stop(); }
        auto stop() noexcept -> void {
            if (worker_.joinable()) {
                worker_.request_stop();
                wake_cv_.notify_all();
                worker_.join();
            }
            active_source_.clear();
            active_generation_ = 0;
            http_pool_.reset();
        }
        [[nodiscard]] auto has_remote() const noexcept -> bool {
            std::lock_guard lock(mutex_);
            return !entries_.empty();
        }
        [[nodiscard]] auto next_refresh_for(std::string_view url) const -> std::optional<std::chrono::steady_clock::time_point> {
            std::lock_guard lock(mutex_);
            auto it = std::ranges::find_if(entries_, [&](auto const& e) { return e.spec.url == url; });
            return it != entries_.end() ? std::optional(it->next_refresh) : std::nullopt;
        }
        [[nodiscard]] auto fetched_at_for(std::string_view url) const -> std::optional<std::uint64_t> {
            std::lock_guard lock(mutex_);
            auto it = std::ranges::find_if(entries_, [&](auto const& e) { return e.spec.url == url; });
            return it != entries_.end() ? std::optional(it->fetched_at) : std::nullopt;
        }
        [[nodiscard]] auto consume_updated() noexcept -> bool { return updated_.exchange(false, std::memory_order_acq_rel); }

        auto fetch_initial(config::Config const& config, std::string_view source, RuleFileInput& input)
            -> std::expected<void, std::string> {
            auto specs_exp = collect(config);
            if (!specs_exp) return std::unexpected(std::move(specs_exp.error()));
            auto const& specs = *specs_exp;
            if (specs.empty()) {
                std::lock_guard lock(mutex_);
                entries_.clear();
                ++generation_;
                return {};
            }
            auto now = std::chrono::steady_clock::now();
            auto now_unix = cli::current_unix_seconds();
            std::vector<Entry> loaded;
            loaded.reserve(specs.size());
            for (auto const& spec : specs) {
                auto csig = cli::http_client_signature(config, spec.http_client);
                if (auto fresh = cli::probe_fresh_managed_ruleset_cache(config, source, spec, now_unix)) {
                    input.seed(spec.url, fresh->body);
                    auto elapsed_ms = static_cast<std::uint64_t>(spec.update_interval_ms) - fresh->remaining_ms;
                    loaded.push_back({spec, std::move(fresh->body), std::move(fresh->etag), std::move(csig),
                        fresh->fetched_at, now - std::chrono::milliseconds(elapsed_ms),
                        now + std::chrono::milliseconds(fresh->remaining_ms)});
                    continue;
                }
                auto fetched = cli::fetch_managed_ruleset(config, source, spec, {}, true);
                if (!fetched) return std::unexpected("remote rule-set " + spec.url + ": " + fetched.error());
                if (auto ok = cli::verify_remote_ruleset_sha256(spec, fetched->body); !ok)
                    return std::unexpected(std::move(ok.error()));
                auto done_steady = std::chrono::steady_clock::now();
                auto fetched_at = fetched->fetched_at ? fetched->fetched_at : cli::current_unix_seconds();
                input.seed(spec.url, fetched->body);
                loaded.push_back({spec, std::move(fetched->body), std::move(fetched->etag), std::move(csig),
                    fetched_at, done_steady, done_steady + std::chrono::milliseconds(spec.update_interval_ms)});
            }
            std::lock_guard lock(mutex_);
            entries_ = std::move(loaded);
            ++generation_;
            return {};
        }

        auto seed_cached(RuleFileInput& input) -> void {
            std::lock_guard lock(mutex_);
            for (auto const& entry : entries_) input.seed(entry.spec.url, entry.body);
        }

        auto prepare_reload(config::Config const& config, std::string_view source, RuleFileInput& input)
            -> std::expected<StagedReload, std::string> {
            auto specs_exp = collect(config);
            if (!specs_exp) return std::unexpected(std::move(specs_exp.error()));
            auto const& specs = *specs_exp;
            std::vector<Entry> existing;
            {
                std::lock_guard lock(mutex_);
                existing = entries_;
            }
            StagedReload staged{};
            staged.entries_.reserve(specs.size());
            auto now = std::chrono::steady_clock::now();
            auto now_unix = cli::current_unix_seconds();
            for (auto const& spec : specs) {
                auto csig = cli::http_client_signature(config, spec.http_client);
                auto it = std::ranges::find_if(existing, [&](auto const& e) {
                    return same_identity(e, spec, csig) && !e.body.empty();
                });
                if (it != existing.end() && cli::verify_remote_ruleset_sha256(spec, it->body).has_value()) {
                    auto rem_unix = cli::compute_remaining_refresh_ms(it->fetched_at, now_unix, spec.update_interval_ms);
                    auto steady_elapsed_ms = (it->fetched_steady != std::chrono::steady_clock::time_point{})
                        ? std::chrono::duration_cast<std::chrono::milliseconds>(now - it->fetched_steady).count() : 0;
                    if (rem_unix && steady_elapsed_ms >= 0 &&
                        static_cast<std::uint64_t>(steady_elapsed_ms) < spec.update_interval_ms) {
                        auto next_refresh = it->next_refresh;
                        if (it->spec.update_interval_ms != spec.update_interval_ms) {
                            auto rem_ms = std::min<std::uint64_t>(*rem_unix,
                                static_cast<std::uint64_t>(spec.update_interval_ms) - static_cast<std::uint64_t>(steady_elapsed_ms));
                            next_refresh = now + std::chrono::milliseconds(rem_ms);
                        }
                        input.seed(spec.url, it->body);
                        staged.entries_.push_back({spec, it->body, it->etag, std::move(csig),
                            it->fetched_at, it->fetched_steady, next_refresh});
                        continue;
                    }
                }
                auto fetched = cli::fetch_managed_ruleset(config, source, spec, {}, true);
                if (!fetched) return std::unexpected("remote rule-set " + spec.url + ": " + fetched.error());
                if (auto ok = cli::verify_remote_ruleset_sha256(spec, fetched->body); !ok)
                    return std::unexpected(std::move(ok.error()));
                auto done_steady = std::chrono::steady_clock::now();
                auto fetched_at = fetched->fetched_at ? fetched->fetched_at : cli::current_unix_seconds();
                input.seed(spec.url, fetched->body);
                staged.entries_.push_back({spec, std::move(fetched->body), std::move(fetched->etag), std::move(csig),
                    fetched_at, done_steady, done_steady + std::chrono::milliseconds(spec.update_interval_ms)});
            }
            return staged;
        }

        auto commit_reload(StagedReload&& staged) -> void {
            bool now_empty = staged.entries_.empty();
            {
                std::lock_guard lock(mutex_);
                entries_ = std::move(staged.entries_);
                ++generation_;
            }
            if (now_empty) stop();
        }

        auto start_background(config::Config config, std::string source, logging::Runtime& logs) -> void {
            auto specs_exp = collect(config);
            if (!specs_exp) return;
            auto const& specs = *specs_exp;
            std::uint64_t current_gen = 0;
            {
                auto now = std::chrono::steady_clock::now();
                std::lock_guard lock(mutex_);
                bool changed = specs.size() != entries_.size();
                if (!changed) {
                    for (std::size_t i = 0; i < specs.size(); ++i) {
                        auto const& a = entries_[i].spec;
                        auto const& b = specs[i];
                        auto csig = cli::http_client_signature(config, b.http_client);
                        if (!same_identity(entries_[i], b, csig) || a.update_interval_ms != b.update_interval_ms) {
                            changed = true;
                            break;
                        }
                    }
                }
                if (changed) {
                    std::vector<Entry> next;
                    next.reserve(specs.size());
                    for (auto const& spec : specs) {
                        auto csig = cli::http_client_signature(config, spec.http_client);
                        auto it = std::ranges::find_if(entries_, [&](auto const& e) {
                            return same_identity(e, spec, csig);
                        });
                        if (it != entries_.end())
                            next.push_back({spec, std::move(it->body), std::move(it->etag), std::move(csig),
                                it->fetched_at, it->fetched_steady, it->next_refresh});
                        else
                            next.push_back({spec, {}, {}, std::move(csig), 0, {}, now});
                    }
                    entries_ = std::move(next);
                    ++generation_;
                }
                current_gen = generation_;
            }
            if (specs.empty()) {
                stop();
                return;
            }
            if (worker_.joinable()) {
                if (source == active_source_ && current_gen == active_generation_) return;
                stop();
            }
            active_source_ = source;
            active_generation_ = current_gen;
            if (!http_pool_) http_pool_ = cli::create_managed_http_pool();
            worker_ = std::jthread([this, cfg = std::move(config), src = std::move(source), &logs](std::stop_token token) {
                while (!token.stop_requested()) {
                    {
                        std::unique_lock wlk(wake_mutex_);
                        wake_cv_.wait_for(wlk, token, std::chrono::milliseconds(100), [] { return false; });
                    }
                    if (token.stop_requested()) break;
                    auto now = std::chrono::steady_clock::now();
                    std::vector<std::tuple<std::size_t, config::BlockRules, std::string>> due;
                    std::uint64_t gen_snap = 0;
                    {
                        std::lock_guard lock(mutex_);
                        gen_snap = generation_;
                        for (std::size_t i = 0; i < entries_.size(); ++i)
                            if (now >= entries_[i].next_refresh)
                                due.emplace_back(i, entries_[i].spec, entries_[i].etag);
                    }
                    bool any_changed = false;
                    for (auto const& [idx, spec, etag] : due) {
                        if (token.stop_requested()) break;
                        auto res = cli::fetch_managed_ruleset(cfg, src, spec, etag, false, token, http_pool_.get());
                        if (token.stop_requested()) break;
                        auto done_steady = std::chrono::steady_clock::now();
                        auto next_at = done_steady + std::chrono::milliseconds(spec.update_interval_ms);
                        std::lock_guard lock(mutex_);
                        if (generation_ != gen_snap || idx >= entries_.size() || entries_[idx].spec.url != spec.url)
                            continue;
                        entries_[idx].next_refresh = next_at;
                        if (!res) {
                            logs.emit(logging::Level::warn, logging::Domain::route, 103, {},
                                "remote rule-set refresh failed: {}", logs.private_text(res.error()));
                            continue;
                        }
                        entries_[idx].fetched_at = res->fetched_at ? res->fetched_at : cli::current_unix_seconds();
                        entries_[idx].fetched_steady = done_steady;
                        if (!res->etag.empty()) entries_[idx].etag = res->etag;
                        if (!res->unchanged && !res->body.empty() && res->body != entries_[idx].body) {
                            if (auto ok = cli::verify_remote_ruleset_sha256(spec, res->body); !ok) {
                                logs.emit(logging::Level::warn, logging::Domain::route, 103, {},
                                    "remote rule-set refresh failed: {}", logs.private_text(ok.error()));
                                continue;
                            }
                            entries_[idx].body = std::move(res->body);
                            any_changed = true;
                        }
                    }
                    if (any_changed) updated_.store(true, std::memory_order_release);
                }
            });
        }
    };

    inline auto is_config_flag(std::string_view arg) noexcept -> bool {
        return arg == "--config" || arg == "-c" || arg == "--config-dir" || arg == "-C";
    }
    inline auto is_config_dir_flag(std::string_view arg) noexcept -> bool {
        return arg == "--config-dir" || arg == "-C";
    }
}
