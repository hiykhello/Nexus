// Private DNS rule file loading, reverse cache creation and remote rule-set lifecycle.
#pragma once
namespace cli::run_detail {
    auto make_reverse_cache() -> std::shared_ptr<dns::ReverseCache> {
        std::random_device rd;
        std::array<std::uint64_t,2> key{
            (std::uint64_t(rd())<<32) | std::uint64_t(rd()),
            (std::uint64_t(rd())<<32) | std::uint64_t(rd())
        };
        return std::make_shared<dns::ReverseCache>(dns::ReverseCache::max_capacity,1,key);
    }

    auto load_dns_rules(config::DnsRouting& routing,RuleFileInput& input) -> std::expected<void,std::string> {
        if (routing.rule_files.empty()) return {};
        routing.cache_rule_fingerprints.clear();
        std::vector<std::string> keys;
        std::size_t total=0,nodes=0;
        for(auto const& reference:routing.rule_files) {
            std::optional<::rules::RuleSet> parsed;
            if (reference.file.inline_rules) {
                parsed=*reference.file.inline_rules;
                if (!routing.unified_cache_root.empty() || !routing.message_cache_directory.empty() ||
                    (routing.fakeip && routing.fakeip->unified)) {
                    auto hash=::state::fingerprint(std::as_bytes(std::span(reference.file.inline_kdl)));
                    routing.cache_rule_fingerprints.append(reinterpret_cast<char const*>(hash.data()),hash.size());
                }
            } else {
                auto const& key=!reference.file.url.empty() ? reference.file.url : reference.file.path;
                auto data=input.read(key);
                if (!data) return std::unexpected("DNS rule-set: "+data.error());
                if (std::ranges::find(keys,key)==keys.end()) {
                    total+=data->size();
                    if (total>8*1024*1024) return std::unexpected("DNS rule sets exceed 8 MiB total");
                    keys.push_back(key);
                }
                if (!routing.unified_cache_root.empty() || !routing.message_cache_directory.empty() ||
                    (routing.fakeip && routing.fakeip->unified)) {
                    auto hash=::state::fingerprint(std::as_bytes(std::span(*data)));
                    routing.cache_rule_fingerprints.append(reinterpret_cast<char const*>(hash.data()),hash.size());
                }
                auto format=reference.file.format==config::RuleFormat::kdl ? ::rules::InputFormat::kdl :
                    reference.file.format==config::RuleFormat::beve ? ::rules::InputFormat::beve : ::rules::InputFormat::srs;
                auto decoded=::rules::parse_rule_input(*data,format,reference.file.ip_cidr_match_source);
                if (!decoded) return std::unexpected("DNS rule-set: "+decoded.error().message);
                parsed=std::move(*decoded);
            }
            auto count=[&](auto&& self,::rules::Rule const& rule) -> bool {
                if(++nodes>::rules::max_rules)return false;
                return std::ranges::all_of(rule.children,[&](auto const& child){return self(self,child);});
            };
            if(!std::ranges::all_of(parsed->rules,[&](auto const& rule){return count(count,rule);})) {
                return std::unexpected("DNS rule-set predicates exceed limit");
            }
            if(!::policy::bind_dns_rule_set(routing.rules[reference.rule],std::move(*parsed))) {
                return std::unexpected("DNS rule-set contains unsupported conditions or exceeds limits");
            }
        }
        return {};
    }

    struct DnsRuleSource {
        std::shared_ptr<proxy::RouteSnapshots> snapshots;
        auto operator()() const -> dns::MessageRuleSnapshot {
            if (!snapshots) return {};
            auto generation=snapshots->load(std::memory_order_acquire);
            if (!generation || generation->empty() || !generation->front().dns) return {};
            auto const& dns=generation->front().dns;
            auto result=dns::MessageRuleSnapshot{{dns,&dns->rules},dns->view};
            result.transports=generation->front().dns_transports;
            return result;
        }
    };

    inline auto dns_rule_source(std::shared_ptr<proxy::RouteSnapshots> snapshots) -> DnsRuleSource {
        return {std::move(snapshots)};
    }

    class RemoteRulesetManager {
        struct Entry {
            config::BlockRules spec;
            std::string body, etag;
            std::chrono::steady_clock::time_point next_refresh{};
        };
        std::mutex mutex_;
        std::vector<Entry> entries_;
        std::atomic<bool> updated_{false};
        std::jthread worker_;

        static auto collect(config::Config const& config) -> std::vector<config::BlockRules> {
            std::vector<config::BlockRules> out;
            auto add=[&](config::BlockRules const& spec) {
                if (spec.url.empty()) return;
                if (std::ranges::any_of(out,[&](auto const& e) { return e.url==spec.url; })) return;
                out.push_back(spec);
            };
            for (auto const& r : config.routes) add(r.file);
            if (config.ordered_tcp) for (auto const& [tag,spec] : config.ordered_tcp->sets) add(spec);
            if (config.dns) for (auto const& ref : config.dns->rule_files) add(ref.file);
            return out;
        }
    public:
        ~RemoteRulesetManager() { stop(); }
        auto stop() noexcept -> void {
            if (worker_.joinable()) {
                worker_.request_stop();
                worker_.join();
            }
        }
        [[nodiscard]] auto has_remote() const noexcept -> bool { return !entries_.empty(); }
        [[nodiscard]] auto consume_updated() noexcept -> bool { return updated_.exchange(false,std::memory_order_acq_rel); }

        auto fetch_initial(config::Config const& config,std::string_view source,RuleFileInput& input)
            -> std::expected<void,std::string> {
            auto specs=collect(config);
            if (specs.empty()) return {};
            auto now=std::chrono::steady_clock::now();
            std::vector<Entry> loaded;
            loaded.reserve(specs.size());
            for (auto const& spec : specs) {
                auto fetched=cli::fetch_managed_ruleset(config,source,spec,{},true);
                if (!fetched) return std::unexpected("remote rule-set "+spec.url+": "+fetched.error());
                input.seed(spec.url,fetched->body);
                loaded.push_back({spec,std::move(fetched->body),std::move(fetched->etag),
                    now+std::chrono::milliseconds(spec.update_interval_ms)});
            }
            std::lock_guard lock(mutex_);
            entries_=std::move(loaded);
            return {};
        }

        auto seed_cached(RuleFileInput& input) -> void {
            std::lock_guard lock(mutex_);
            for (auto const& entry : entries_) input.seed(entry.spec.url,entry.body);
        }

        auto start_background(config::Config config,std::string source,logging::Runtime& logs) -> void {
            if (entries_.empty()) return;
            worker_=std::jthread([this,cfg=std::move(config),src=std::move(source),&logs](std::stop_token token) {
                while (!token.stop_requested()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    if (token.stop_requested()) break;
                    auto now=std::chrono::steady_clock::now();
                    std::vector<std::tuple<std::size_t,config::BlockRules,std::string>> due;
                    {
                        std::lock_guard lock(mutex_);
                        for (std::size_t i=0;i<entries_.size();++i)
                            if (now>=entries_[i].next_refresh)
                                due.emplace_back(i,entries_[i].spec,entries_[i].etag);
                    }
                    bool any_changed=false;
                    for (auto const& [idx,spec,etag] : due) {
                        if (token.stop_requested()) break;
                        auto res=cli::fetch_managed_ruleset(cfg,src,spec,etag,false);
                        auto next_at=std::chrono::steady_clock::now()+std::chrono::milliseconds(spec.update_interval_ms);
                        std::lock_guard lock(mutex_);
                        if (idx>=entries_.size()) continue;
                        entries_[idx].next_refresh=next_at;
                        if (!res) {
                            logs.emit(logging::Level::warn,logging::Domain::route,103,{},
                                "remote rule-set refresh failed: {}",logs.private_text(res.error()));
                            continue;
                        }
                        if (!res->etag.empty()) entries_[idx].etag=res->etag;
                        if (!res->unchanged && !res->body.empty() && res->body!=entries_[idx].body) {
                            entries_[idx].body=std::move(res->body);
                            any_changed=true;
                        }
                    }
                    if (any_changed) updated_.store(true,std::memory_order_release);
                }
            });
        }
    };

    auto is_config_flag(std::string_view arg) noexcept -> bool {
        return arg=="--config" || arg=="-c" || arg=="--config-dir" || arg=="-C";
    }
    auto is_config_dir_flag(std::string_view arg) noexcept -> bool {
        return arg=="--config-dir" || arg=="-C";
    }
}
