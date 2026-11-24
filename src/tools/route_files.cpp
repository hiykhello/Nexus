module;
extern "C" void nexus_register_builtin_http_fetchers() noexcept;
module cli.route_files;
import std;
import config;
import glaze;
import relay;
import rulefile;
import rules;
import rules.rule_input;
import cli.tun_route_sets;

namespace cli {
    namespace {
        std::mutex g_working_directory_mutex;
        std::optional<std::filesystem::path> g_working_directory;
        std::atomic<ManagedRulesetFetcher> g_managed_ruleset_fetcher{nullptr};
        std::atomic<ManagedHttpPoolFactory> g_managed_http_pool_factory{nullptr};
    }

    auto register_managed_ruleset_fetcher(ManagedRulesetFetcher fetcher) noexcept -> void {
        g_managed_ruleset_fetcher.store(fetcher, std::memory_order_release);
    }

    auto register_managed_http_pool_factory(ManagedHttpPoolFactory factory) noexcept -> void {
        g_managed_http_pool_factory.store(factory, std::memory_order_release);
    }

    auto ensure_http_fetchers_registered() noexcept -> void {
        static std::once_flag once;
        std::call_once(once, []() noexcept { ::nexus_register_builtin_http_fetchers(); });
    }

    auto create_managed_http_pool() noexcept -> std::shared_ptr<void> {
        ensure_http_fetchers_registered();
        auto fn = g_managed_http_pool_factory.load(std::memory_order_acquire);
        return fn ? fn() : std::shared_ptr<void>{};
    }

    auto fetch_managed_ruleset(config::Config const& config,std::string_view config_source,
        config::BlockRules const& spec,std::string_view previous_etag,bool offline_fallback,std::stop_token stop,void* client_pool)
        -> std::expected<ManagedRulesetFetchResult,std::string> {
        ensure_http_fetchers_registered();
        auto fn = g_managed_ruleset_fetcher.load(std::memory_order_acquire);
        if (!fn)
            return std::unexpected("remote rule-set requires the http-client build feature");
        return fn(config,config_source,spec,previous_etag,offline_fallback,std::move(stop),client_pool);
    }

    auto set_working_directory(std::filesystem::path directory) -> void {
        std::lock_guard lock(g_working_directory_mutex);
        g_working_directory=std::move(directory);
    }

    auto working_directory() -> std::optional<std::filesystem::path> {
        std::lock_guard lock(g_working_directory_mutex);
        return g_working_directory;
    }

    auto read_config_source(std::string_view path,bool is_directory) -> std::expected<std::string,std::string> {
        std::filesystem::path resolved(path);
        if (resolved.is_relative()) if (auto wd = working_directory()) resolved = *wd / resolved;
        if (!is_directory) return rulefile::read_regular_file(resolved.string());
        std::error_code ec;
        auto root=resolved;
        if (!std::filesystem::is_directory(root,ec) || ec)
            return std::unexpected("config directory is not accessible: "+std::string(path));
        std::vector<std::filesystem::path> files;
        for (auto const& entry : std::filesystem::directory_iterator(root,ec)) {
            if (ec) return std::unexpected("cannot scan config directory: "+ec.message());
            auto name=entry.path().filename().string();
            if (name.empty() || name.starts_with('.') || !name.ends_with(".kdl")) continue;
            if (!entry.is_regular_file(ec) || ec) continue;
            files.push_back(entry.path());
        }
        if (files.empty()) return std::unexpected("config directory contains no .kdl files: "+std::string(path));
        std::ranges::sort(files,[](auto const& a,auto const& b) { return a.filename().string()<b.filename().string(); });
        std::map<std::string,std::string> singletons, inbounds, outbounds;
        std::string merged;
        for (auto const& file : files) {
            auto text=rulefile::read_regular_file(file.string());
            if (!text) return std::unexpected(file.filename().string()+": "+text.error());
            if (merged.size()+text->size()+1>config::max_config_bytes)
                return std::unexpected("merged config directory exceeds maximum size");
            auto doc=glaze::read_kdl<glaze::KdlDocument>(*text);
            if (!doc) return std::unexpected(file.filename().string()+": invalid KDL syntax");
            auto fname=file.filename().string();
            auto check_named=[&](std::map<std::string,std::string>& seen,std::string_view kind,glaze::KdlNode const& n) -> std::expected<void,std::string> {
                if (n.arguments.size()==1) if (auto* s=std::get_if<std::string>(&n.arguments[0].data)) {
                    if (auto [it,ok]=seen.emplace(*s,fname); !ok)
                        return std::unexpected(std::format("duplicate {} \"{}\" in {} (already defined in {})",kind,*s,fname,it->second));
                }
                return {};
            };
            for (auto const& n : *doc) {
                if (n.name=="schema-version" || n.name=="role" || n.name=="dns" || n.name=="routing" ||
                    n.name=="log" || n.name=="state" || n.name=="workers" || n.name=="http-clients") {
                    if (auto [it,ok]=singletons.emplace(n.name,fname); !ok)
                        return std::unexpected(std::format("duplicate {} block in {} (already defined in {})",n.name,fname,it->second));
                } else if (n.name=="inbound") {
                    if (auto ok=check_named(inbounds,"inbound",n); !ok) return std::unexpected(std::move(ok.error()));
                } else if (n.name=="outbound") {
                    if (auto ok=check_named(outbounds,"outbound",n); !ok) return std::unexpected(std::move(ok.error()));
                } else if (n.name=="inbounds" || n.name=="outbounds") {
                    for (auto const& c : n.children)
                        if (auto ok=check_named(n.name=="inbounds" ? inbounds : outbounds,n.name=="inbounds" ? "inbound" : "outbound",c); !ok)
                            return std::unexpected(std::move(ok.error()));
                }
            }
            merged.append(*text);
            if (!merged.empty() && merged.back()!='\n') merged.push_back('\n');
        }
        return merged;
    }
    auto outbound_names(config::Config const& config) -> std::vector<std::string> {
        std::vector<std::string> names;
        names.reserve(2+config.tunnel_count());
        names.push_back(config.direct_outbound_name);
        names.push_back(config.block_outbound_name.value_or("block"));
        auto append=[&](auto const&... groups) {
            auto visit=[&](auto const& entries) {
                for (auto const& entry : entries) names.push_back(entry.name);
            };
            (visit(groups),...);
        };
        append(config.vless_outbounds,config.shadowsocks_outbounds,config.trojan_outbounds,config.anytls_outbounds,
            config.hysteria2_outbounds,config.snell_outbounds,config.shadowtls_outbounds,config.tuic_outbounds,
            config.masque_outbounds,config.wireguard_outbounds,config.ssh_outbounds,config.naive_outbounds,
            config.openvpn_outbounds,config.openconnect_outbounds,config.tailscale_outbounds,config.tcp_proxy_outbounds);
        return names;
    }

    auto relay_rule_format(config::RuleFormat format) noexcept -> relay::RuleFormat {
        using C = config::RuleFormat;
        using R = relay::RuleFormat;
        switch (format) {
        case C::kdl: return R::kdl;
        case C::beve: return R::beve;
        case C::srs: return R::srs;
        case C::nxmm: return R::nxmm;
        case C::json: return R::json;
        case C::domain_list: return R::domain_list;
        case C::ipcidr_list: return R::ipcidr_list;
        case C::classical: return R::classical;
        case C::adguard: return R::adguard;
        }
        std::unreachable();
    }

    auto rule_input_format(config::RuleFormat format) noexcept -> rules::InputFormat {
        using C = config::RuleFormat;
        using I = rules::InputFormat;
        switch (format) {
        case C::kdl: return I::kdl;
        case C::beve: return I::beve;
        case C::srs: return I::srs;
        case C::nxmm: return I::nxmm;
        case C::json: return I::json;
        case C::domain_list: return I::domain_list;
        case C::ipcidr_list: return I::ipcidr_list;
        case C::classical: return I::classical;
        case C::adguard: return I::adguard;
        }
        std::unreachable();
    }

    namespace {
        auto action_for(config::OrderedTcpRule const& rule) noexcept -> rules::ProgramActionKind {
            using Action=config::OrderedTcpAction;
            using Kind=rules::ProgramActionKind;
            switch(rule.action) {
            case Action::sniff: return Kind::sniff;
            case Action::resolve: return Kind::resolve;
            case Action::route: return Kind::route;
            case Action::bypass: return rule.outbound_name ? Kind::route : Kind::bypass;
            case Action::route_options: return Kind::route_options;
            case Action::hijack_dns: return Kind::hijack_dns;
            case Action::reject: return Kind::reject;
            }
            std::unreachable();
        }

        auto domain_source(config::OrderedTcpDomain domain) noexcept -> rules::DomainSource {
            using Domain=config::OrderedTcpDomain;
            switch(domain) {
            case Domain::explicit_target: return rules::DomainSource::explicit_target;
            case Domain::sniffed: return rules::DomainSource::sniffed;
            case Domain::fakeip: return rules::DomainSource::fakeip;
            case Domain::reverse_dns: return rules::DomainSource::reverse_dns;
            }
            std::unreachable();
        }

        auto resolve_rule_path(std::filesystem::path const& config_path, std::string_view path)
            -> std::expected<std::filesystem::path, std::string> {
            std::filesystem::path target(path);
            if (!target.is_absolute()) {
                if (auto wd = working_directory()) return *wd / target;
                std::error_code error;
                auto base = std::filesystem::absolute(config_path, error);
                if (error) return std::unexpected("configuration path: " + error.message());
                if (!std::filesystem::is_directory(base, error)) base = base.parent_path();
                return base / target;
            }
            return target;
        }
    }

    auto RouteFiles::indexed(config::Config const& config) const -> std::vector<relay::IndexedRouteRule> {
        std::vector<relay::IndexedRouteRule> result;
        result.reserve(config.routes.size());
        for(std::size_t index=0;index<config.routes.size();++index) {
            auto const& route=config.routes[index];
            auto idx = indices[index];
            auto mm = idx < data_mmaps.size() ? data_mmaps[idx] : nullptr;
            result.push_back({data[idx], relay_rule_format(route.file.format), route.outbound,
                              route.file.ip_cidr_match_source, std::move(mm)});
        }
        return result;
    }

    auto project_routes(config::Config const& config,RouteFiles const& files) -> ProjectedRoutes {
        auto distribution=config::outbound_distribution(config);
        auto index_of=[&](std::string_view name) {return *config::distributed_outbound_index(config,name);};
        auto indexed=files.indexed(config);
        for (std::size_t index=0;index<indexed.size();++index)
            indexed[index].outbound=index_of(config.routes[index].outbound_name);
        auto ordered_rules=files.ordered;
        if(config.ordered_tcp) {
            auto const& program=*config.ordered_tcp;
            for(std::size_t index=0;index<ordered_rules.size();++index)
                if (auto const& name=program.rules[index].outbound_name)
                    ordered_rules[index].action.outbound=index_of(*name);
        }
        return {std::move(indexed),std::move(ordered_rules),std::move(distribution),index_of(config.default_outbound_name)};
    }

    auto ProjectedRoutes::program(config::Config const& config) const -> std::optional<relay::OrderedRuleInput> {
        if (!config.ordered_tcp) return {};
        auto const& settings=*config.ordered_tcp;
        return relay::OrderedRuleInput{ordered,settings.sniff_timeout_ms,settings.skip_unknown,settings.udp};
    }

    auto ProjectedRoutes::compile(config::Config const& config,std::string_view inbound)
        const -> std::expected<relay::RouteSnapshot,std::string> {
        return relay::compile_routes(indexed,default_outbound,2+config.tunnel_count(),inbound,program(config),distribution);
    }

    auto RuleFileInput::read(std::string const& path) -> std::expected<std::string_view,std::string> {
        if (auto found=files_.find(path);found!=files_.end()) return std::string_view(found->second);
        auto target = resolve_rule_path(config_path_, path);
        if (!target) return std::unexpected(std::move(target.error()));
        auto data=rulefile::read_regular_file(target->string());
        if (!data) return std::unexpected(std::move(data.error()));
        return std::string_view(files_.emplace(path,std::move(*data)).first->second);
    }

    auto RuleFileInput::open_mapped(std::string const& path)
        -> std::expected<std::shared_ptr<rules::MmapMatcher const>,std::string> {
        if (auto found=mmaps_.find(path); found!=mmaps_.end()) return found->second;
        auto target = resolve_rule_path(config_path_, path);
        if (!target) return std::unexpected(std::move(target.error()));
        auto mm = rules::MmapMatcher::open_file(target->string());
        if (!mm) return std::unexpected(std::move(mm.error()));
        auto ptr = std::make_shared<rules::MmapMatcher const>(std::move(*mm));
        return mmaps_.emplace(path, ptr).first->second;
    }

    auto load_route_files(config::Config const& config,RuleFileInput& input) -> std::expected<RouteFiles,std::string> {
        RouteFiles result;
        if(config.routes.empty() && !config.ordered_tcp)return result;

        std::size_t total=0;
        std::vector<std::string> keys;
        auto read=[&](config::BlockRules const& file, bool allow_mmap) -> std::expected<std::size_t,std::string> {
            if (file.inline_rules) {
                if (file.inline_kdl.empty()) return std::unexpected("inline rule-set encoding unavailable");
                result.data.emplace_back(file.inline_kdl);
                result.data_mmaps.emplace_back();
                keys.emplace_back();
                return keys.size()-1;
            }
            auto const& key=!file.url.empty() ? file.url : file.path;
            auto previous=std::ranges::find(keys,key);
            if(previous!=keys.end())return static_cast<std::size_t>(previous-keys.begin());
            std::string content;
            std::shared_ptr<rules::MmapMatcher const> mapped;
            if (!file.url.empty()) {
                auto seeded=input.read(file.url);
                if (seeded) content.assign(*seeded);
                else if (input.allows_unfetched_remote()) {
                    content="schema-version 2\nkind \"predicate\"\ndomain \"remote-placeholder.invalid\"\n";
                } else return std::unexpected("remote rule-set "+file.url+": "+seeded.error());
            } else if (allow_mmap && file.format == config::RuleFormat::nxmm) {
                auto mm = input.open_mapped(file.path);
                if (!mm) return std::unexpected(std::move(mm.error()));
                mapped = std::move(*mm);
            } else {
                auto data=input.read(file.path);
                if(!data)return std::unexpected(std::move(data.error()));
                content.assign(*data);
            }
            total += mapped ? mapped->byte_size() : content.size();
            if(total>8*1024*1024)return std::unexpected("routing rules exceed 8 MiB total");
            keys.push_back(key);
            result.data.emplace_back(std::move(content));
            result.data_mmaps.emplace_back(std::move(mapped));
            return keys.size()-1;
        };

        for(auto const& route:config.routes) {
            auto index=read(route.file, true);
            if(!index)return std::unexpected(std::move(index.error()));
            result.indices.push_back(*index);
        }
        // The parser makes the indexed rules and ordered program mutually exclusive.
        if(config.ordered_tcp) {
            auto load=[&](config::BlockRules const& file) -> std::expected<rules::RuleSet,std::string> {
                if (file.inline_rules) {
                    if (file.inline_rules->rules.empty()) return std::unexpected("tcp-program rule-set must not be empty");
                    return *file.inline_rules;
                }
                if (!file.url.empty() && input.allows_unfetched_remote()) {
                    auto seeded=input.read(file.url);
                    if (!seeded) {
                        rules::RuleSet placeholder{.version=2};
                        placeholder.rules.push_back({"domain","remote-placeholder.invalid",{}});
                        return placeholder;
                    }
                }
                auto index=read(file, false);
                if (!index) return std::unexpected(std::move(index.error()));
                auto set=rules::parse_rule_input(result.data[*index],rule_input_format(file.format),file.ip_cidr_match_source);
                if (!set) return std::unexpected(std::move(set.error().message));
                if (set->rules.empty()) return std::unexpected("tcp-program rule-set must not be empty");
                return std::move(*set);
            };
            std::map<std::string_view,rules::RuleSet> loaded;
            std::set<std::string_view> used;
            std::optional<std::string> load_error;
            std::size_t budget=rules::max_rules;
            auto lookup=[&](std::string_view tag) -> rules::RuleSet const* {
                used.insert(tag);
                auto previous=loaded.find(tag);
                if (previous!=loaded.end()) return &previous->second;
                auto const& sets=config.ordered_tcp->sets;
                auto found=std::ranges::find_if(sets,[&](auto const& item){return item.first==tag;});
                if (found==sets.end()) return nullptr;
                auto parsed=load(found->second);
                if (!parsed) {load_error=std::move(parsed.error());return nullptr;}
                return &loaded.emplace(found->first,std::move(*parsed)).first->second;
            };
            for(auto const& rule:config.ordered_tcp->rules) {
                auto source=&rule.predicates;
                std::optional<rules::RuleSet> mapped;
                if (rule.file) {
                    if (rule.set_tag && !rule.file->ip_cidr_match_source) {
                        source=lookup(*rule.set_tag);
                        if (!source) return std::unexpected(load_error.value_or("unknown ordered rule-set"));
                    } else {
                        if (rule.set_tag) used.insert(*rule.set_tag);
                        auto parsed=load(*rule.file);
                        if (!parsed) return std::unexpected(std::move(parsed.error()));
                        mapped.emplace(std::move(*parsed));
                        source=&*mapped;
                    }
                }
                auto predicates=rules::expand_rule_sets(*source,lookup,budget);
                if (!predicates) return std::unexpected(load_error.value_or(predicates.error().message));
                result.ordered.push_back({std::move(*predicates),
                    {action_for(rule),rule.outbound,rule.connect_timeout_ms,rule.route_only,
                     rule.reject_method,rule.reject_no_drop,rule.tls_record_fragment,
                     rule.tls_fragment_min,rule.tls_fragment_max,rule.tcp_prefix,rule.tcp_prefix_len,
                     rule.udp_timeout_ms,rule.udp_adaptive_timeout,rule.override_address,
                     rule.override_port,rule.tls_fragment_fallback_delay_ms,
                     rule.extra.resolve_strategy,rule.extra.resolve_server,rule.extra.resolve_disable_cache,
                     rule.extra.resolve_rewrite_ttl,rule.extra.resolve_client_subnet,
                     rule.extra.sniff_protocols,rule.extra.sniff_override_destination,
                     rule.extra.sniff_timeout_ms,rule.extra.udp_disable_domain_unmapping},
                    domain_source(rule.domain)});
            }
            for (auto const& in : config.inbounds) {
                if (!in.tun) continue;
                for (auto const* list : {&in.tun->route_address_sets, &in.tun->route_exclude_address_sets}) {
                    for (auto const& tag : *list) {
                        if (std::ranges::contains(result.tun_cidrs, tag, &std::pair<std::string, std::vector<std::string>>::first))
                            continue;
                        auto const* src = lookup(tag);
                        if (!src) return std::unexpected(load_error.value_or("unknown TUN rule-set: " + tag));
                        std::vector<std::string> cidrs;
                        cli::detail::collect_ip_cidrs(*src, cidrs, true, true);
                        result.tun_cidrs.emplace_back(tag, std::move(cidrs));
                    }
                }
            }
            for (auto const& [tag,file]:config.ordered_tcp->sets)
                if (!used.contains(tag)) return std::unexpected("unreferenced rule-set: "+tag);
            result.data.clear();
        }
        return result;
    }

    auto apply_tun_route_sets(config::TunInbound& tun, RouteFiles const& files) -> std::expected<void, std::string> {
        auto add_from = [&](std::vector<std::string> const& tags, std::vector<std::string>& dst, std::size_t cap)
            -> std::expected<void, std::string> {
            for (auto const& tag : tags) {
                auto it = std::ranges::find(files.tun_cidrs, tag, &std::pair<std::string, std::vector<std::string>>::first);
                if (it == files.tun_cidrs.end()) continue;
                for (auto const& cidr : it->second) {
                    if (!(cidr.contains(':') ? tun.inet6_address : tun.inet4_address)) continue;
                    if (!std::ranges::contains(dst, cidr) && dst.size() < cap) dst.push_back(cidr);
                }
            }
            return {};
        };
        if (auto ok = add_from(tun.route_address_sets, tun.route_includes, 64); !ok) return ok;
        if (auto ok = add_from(tun.route_exclude_address_sets, tun.route_excludes, 64); !ok) return ok;
        return {};
    }

    auto load_route_files(config::Config const& config,std::string_view config_path,bool allow_unfetched_remote) -> std::expected<RouteFiles,std::string> {
        RuleFileInput input(config_path,allow_unfetched_remote);
        return load_route_files(config,input);
    }
}
