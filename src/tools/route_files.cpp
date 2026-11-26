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
import cli.route_files_nxmm;

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

    namespace {
        auto resolve_cli_path(std::string_view path) -> std::filesystem::path {
            std::filesystem::path resolved(path);
            if (resolved.is_relative()) if (auto wd = working_directory()) resolved = *wd / resolved;
            return resolved;
        }

        auto apply_host_override(std::string_view base_text, std::string_view override_path)
            -> std::expected<std::string, std::string> {
            if (base_text.size() > config::max_config_bytes) return std::unexpected("configuration exceeds maximum size");
            auto ov_text = rulefile::read_regular_file(resolve_cli_path(override_path).string());
            if (!ov_text) return std::unexpected("host-override: " + ov_text.error());
            if (ov_text->size() > config::max_config_bytes) return std::unexpected("host-override exceeds maximum size");
            auto base_doc = glaze::read_kdl<glaze::KdlDocument>(base_text);
            if (!base_doc) return std::unexpected("invalid KDL syntax in base config");
            auto ov_doc = glaze::read_kdl<glaze::KdlDocument>(*ov_text);
            if (!ov_doc) return std::unexpected("host-override: invalid KDL syntax");
            auto val_str = [](glaze::KdlValue const& v) -> std::string_view {
                auto* s = v.tag ? nullptr : std::get_if<std::string>(&v.data);
                return s ? std::string_view(*s) : std::string_view{};
            };
            auto is_tun = [&](glaze::KdlNode const& n) -> bool {
                return n.name == "tun" || (n.name == "inbound" &&
                    std::ranges::any_of(n.properties, [&](auto const& p) { return p.first == "type" && val_str(p.second) == "tun"; }));
            };
            auto in_name = [&](glaze::KdlNode const& n) -> std::string_view {
                return (!n.tag && n.arguments.size() == 1) ? val_str(n.arguments[0]) : std::string_view{};
            };
            auto canonical_in = [](glaze::KdlNode n) -> glaze::KdlNode {
                if (n.name != "inbound") {
                    if (!std::ranges::any_of(n.properties, [](auto const& p) { return p.first == "type"; }))
                        n.properties.push_back({"type", glaze::KdlValue{n.name, {}}});
                    n.name = "inbound";
                }
                return n;
            };
            auto is_singleton = [](std::string_view name) noexcept -> bool {
                return name == "schema-version" || name == "role" || name == "workers" || name == "state" ||
                       name == "control" || name == "log" || name == "certificate" || name == "memory-watchdog" ||
                       name == "shutdown-grace-ms" || name == "sessions-per-listener" || name == "tcp-splice-pipes" || name == "ntp";
            };
            bool strip_tun = false, ov_has_tun = false, strip_inbounds = false;
            std::vector<glaze::KdlNode> ov_singletons, ov_inbounds, ov_others;
            for (auto& n : *ov_doc) {
                if (n.name == "host-override") {
                    if (n.tag || !n.arguments.empty() || !n.properties.empty())
                        return std::unexpected("host-override block takes only child directives");
                    for (auto const& c : n.children) {
                        auto* b = (!c.tag && c.arguments.size() == 1 && c.properties.empty() && c.children.empty() && !c.arguments[0].tag)
                            ? std::get_if<bool>(&c.arguments[0].data) : nullptr;
                        if (!b) return std::unexpected("invalid host-override directive: " + c.name);
                        if (c.name == "strip-tun") strip_tun = *b;
                        else if (c.name == "strip-inbounds") strip_inbounds = *b;
                        else return std::unexpected("unsupported host-override directive: " + c.name);
                    }
                } else if (n.name == "inbound") { if (is_tun(n)) ov_has_tun = true; ov_inbounds.push_back(std::move(n)); }
                else if (n.name == "inbounds") {
                    if (n.tag || !n.arguments.empty() || !n.properties.empty()) return std::unexpected("host-override: invalid inbounds block");
                    for (auto& c : n.children) { if (is_tun(c)) ov_has_tun = true; ov_inbounds.push_back(std::move(c)); }
                } else if (is_singleton(n.name)) ov_singletons.push_back(std::move(n));
                else ov_others.push_back(std::move(n));
            }
            if (strip_inbounds) std::erase_if(*base_doc, [](auto const& n) { return n.name == "inbound" || n.name == "inbounds"; });
            else if (strip_tun || ov_has_tun) {
                std::erase_if(*base_doc, [&](auto const& n) { return n.name == "inbound" && is_tun(n); });
                for (auto& n : *base_doc) if (n.name == "inbounds") std::erase_if(n.children, is_tun);
            }
            for (auto& s : ov_singletons) {
                auto it = std::ranges::find(*base_doc, s.name, &glaze::KdlNode::name);
                if (it != base_doc->end()) {
                    auto name = s.name; *it = std::move(s);
                    base_doc->erase(std::remove_if(std::next(it), base_doc->end(), [&](auto const& n) { return n.name == name; }), base_doc->end());
                } else if (s.name == "schema-version") base_doc->insert(base_doc->begin(), std::move(s));
                else base_doc->push_back(std::move(s));
            }
            for (auto& in : ov_inbounds) {
                auto name = in_name(in); bool replaced = false;
                if (!name.empty()) for (auto& n : *base_doc) {
                    if (n.name == "inbound" && in_name(n) == name) { n = canonical_in(std::move(in)); replaced = true; break; }
                    if (n.name == "inbounds") {
                        for (auto& c : n.children) if (in_name(c) == name) { c = std::move(in); replaced = true; break; }
                        if (replaced) break;
                    }
                }
                if (!replaced) {
                    auto grp = std::ranges::find(*base_doc, std::string_view("inbounds"), &glaze::KdlNode::name);
                    if (grp != base_doc->end()) grp->children.push_back(std::move(in));
                    else base_doc->push_back(canonical_in(std::move(in)));
                }
            }
            std::erase_if(*base_doc, [](auto const& n) { return n.name == "inbounds" && n.children.empty(); });
            for (auto& o : ov_others) base_doc->push_back(std::move(o));
            auto merged = glaze::write_kdl(*base_doc);
            if (!merged) return std::unexpected("host-override: cannot serialize merged KDL");
            if (merged->size() > config::max_config_bytes) return std::unexpected("merged configuration exceeds maximum size");
            return std::move(*merged);
        }
    }

    auto read_config_source(std::string_view path,bool is_directory,std::string_view host_override_path) -> std::expected<std::string,std::string> {
        auto resolved = resolve_cli_path(path);
        std::string merged;
        if (!is_directory) {
            auto text = rulefile::read_regular_file(resolved.string());
            if (!text) return std::unexpected(std::move(text.error()));
            merged = std::move(*text);
        } else {
            std::error_code ec;
            if (!std::filesystem::is_directory(resolved,ec) || ec)
                return std::unexpected("config directory is not accessible: "+std::string(path));
            std::vector<std::filesystem::path> files;
            for (auto const& entry : std::filesystem::directory_iterator(resolved,ec)) {
                if (ec) return std::unexpected("cannot scan config directory: "+ec.message());
                auto name=entry.path().filename().string();
                if (!name.empty() && !name.starts_with('.') && name.ends_with(".kdl") && entry.is_regular_file(ec) && !ec)
                    files.push_back(entry.path());
            }
            if (files.empty()) return std::unexpected("config directory contains no .kdl files: "+std::string(path));
            std::ranges::sort(files,[](auto const& a,auto const& b) { return a.filename().string()<b.filename().string(); });
            std::map<std::string,std::string> singletons, inbounds, outbounds;
            for (auto const& file : files) {
                auto fname=file.filename().string();
                auto text=rulefile::read_regular_file(file.string());
                if (!text) return std::unexpected(fname+": "+text.error());
                if (merged.size()+text->size()+1>config::max_config_bytes) return std::unexpected("merged config directory exceeds maximum size");
                auto doc=glaze::read_kdl<glaze::KdlDocument>(*text);
                if (!doc) return std::unexpected(fname+": invalid KDL syntax");
                auto check_named=[&](std::map<std::string,std::string>& seen,std::string_view kind,glaze::KdlNode const& n) -> std::expected<void,std::string> {
                    if (n.arguments.size()==1) if (auto* s=std::get_if<std::string>(&n.arguments[0].data))
                        if (auto [it,ok]=seen.emplace(*s,fname); !ok)
                            return std::unexpected(std::format("duplicate {} \"{}\" in {} (already defined in {})",kind,*s,fname,it->second));
                    return {};
                };
                for (auto const& n : *doc) {
                    if (n.name=="schema-version" || n.name=="role" || n.name=="dns" || n.name=="routing" ||
                        n.name=="log" || n.name=="state" || n.name=="workers" || n.name=="http-clients") {
                        if (auto [it,ok]=singletons.emplace(n.name,fname); !ok)
                            return std::unexpected(std::format("duplicate {} block in {} (already defined in {})",n.name,fname,it->second));
                    } else if (n.name=="inbound" || n.name=="outbound") {
                        if (auto ok=check_named(n.name=="inbound" ? inbounds : outbounds,n.name,n); !ok) return std::unexpected(std::move(ok.error()));
                    } else if (n.name=="inbounds" || n.name=="outbounds") {
                        for (auto const& c : n.children)
                            if (auto ok=check_named(n.name=="inbounds" ? inbounds : outbounds,n.name=="inbounds" ? "inbound" : "outbound",c); !ok)
                                return std::unexpected(std::move(ok.error()));
                    }
                }
                merged.append(*text);
                if (!merged.empty() && merged.back()!='\n') merged.push_back('\n');
            }
        }
        return host_override_path.empty() ? std::expected<std::string,std::string>(std::move(merged))
                                          : apply_host_override(merged, host_override_path);
    }
    auto outbound_names(config::Config const& config) -> std::vector<std::string> {
        std::vector<std::string> names{config.direct_outbound_name,config.block_outbound_name.value_or("block")};
        names.reserve(2+config.tunnel_count());
        auto visit=[&](auto const& entries) { for (auto const& entry : entries) names.push_back(entry.name); };
        auto append=[&](auto const&... groups) { (visit(groups),...); };
        append(config.vless_outbounds,config.shadowsocks_outbounds,config.trojan_outbounds,config.anytls_outbounds,
            config.hysteria2_outbounds,config.snell_outbounds,config.shadowtls_outbounds,config.tuic_outbounds,
            config.masque_outbounds,config.wireguard_outbounds,config.ssh_outbounds,config.naive_outbounds,
            config.openvpn_outbounds,config.openconnect_outbounds,config.tailscale_outbounds,config.tcp_proxy_outbounds);
        return names;
    }

    auto relay_rule_format(config::RuleFormat format) noexcept -> relay::RuleFormat {
        using C = config::RuleFormat; using R = relay::RuleFormat;
        switch (format) {
        case C::kdl: return R::kdl; case C::beve: return R::beve; case C::srs: return R::srs;
        case C::nxmm: return R::nxmm; case C::json: return R::json; case C::domain_list: return R::domain_list;
        case C::ipcidr_list: return R::ipcidr_list; case C::classical: return R::classical; case C::adguard: return R::adguard;
        }
        std::unreachable();
    }

    auto rule_input_format(config::RuleFormat format) noexcept -> rules::InputFormat {
        using C = config::RuleFormat; using I = rules::InputFormat;
        switch (format) {
        case C::kdl: return I::kdl; case C::beve: return I::beve; case C::srs: return I::srs;
        case C::nxmm: return I::nxmm; case C::json: return I::json; case C::domain_list: return I::domain_list;
        case C::ipcidr_list: return I::ipcidr_list; case C::classical: return I::classical; case C::adguard: return I::adguard;
        }
        std::unreachable();
    }

    namespace {
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
            auto fmt = mm ? relay::RuleFormat::nxmm : relay_rule_format(route.file.format);
            result.push_back({data[idx], fmt, route.outbound,
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

        std::filesystem::path cache_dir = !input.cache_dir().empty() ? input.cache_dir() :
            (config.state && !config.state->cache_directory.empty() ? std::filesystem::path(config.state->cache_directory) : std::filesystem::path{});
        std::size_t total_inline=0, total_mapped=0;
        std::vector<std::string> keys;
        auto read=[&](config::BlockRules const& file, bool allow_mmap) -> std::expected<std::size_t,std::string> {
            if (file.inline_rules) {
                if (file.inline_kdl.empty()) return std::unexpected("inline rule-set encoding unavailable");
                result.data.emplace_back(file.inline_kdl);
                result.data_mmaps.emplace_back();
                keys.emplace_back();
                return keys.size()-1;
            }
            auto key=!file.url.empty() ? file.url : file.path;
            if ((file.format==config::RuleFormat::srs || file.format==config::RuleFormat::nxmm) && file.ip_cidr_match_source)
                key.append("#src");
            auto previous=std::ranges::find(keys,key);
            if(previous!=keys.end())return static_cast<std::size_t>(previous-keys.begin());
            std::string content;
            std::shared_ptr<rules::MmapMatcher const> mapped;
            if (!file.url.empty()) {
                auto seeded=input.read(file.url);
                if (seeded) {
                    if (allow_mmap && file.format==config::RuleFormat::nxmm) {
                        auto mm=rules::MmapMatcher::open_bytes(std::string(*seeded));
                        if (!mm) return std::unexpected(std::move(mm.error()));
                        mapped=std::make_shared<rules::MmapMatcher const>(std::move(*mm));
                    } else if (allow_mmap && file.format==config::RuleFormat::srs && !cache_dir.empty()) {
                        mapped=nxmm_detail::try_mmap_srs_sidecar(cache_dir,*seeded,file.ip_cidr_match_source);
                        if (!mapped) content.assign(*seeded);
                    } else content.assign(*seeded);
                } else if (input.allows_unfetched_remote()) {
                    content="schema-version 2\nkind \"predicate\"\ndomain \"remote-placeholder.invalid\"\n";
                } else return std::unexpected("remote rule-set "+file.url+": "+seeded.error());
            } else if (allow_mmap && file.format == config::RuleFormat::nxmm) {
                auto mm = input.open_mapped(file.path);
                if (!mm) return std::unexpected(std::move(mm.error()));
                mapped = std::move(*mm);
            } else {
                auto data=input.read(file.path);
                if(!data)return std::unexpected(std::move(data.error()));
                if (allow_mmap && file.format==config::RuleFormat::srs && !cache_dir.empty())
                    mapped=nxmm_detail::try_mmap_srs_sidecar(cache_dir,*data,file.ip_cidr_match_source);
                if (!mapped) content.assign(*data);
            }
            if (mapped) {
                total_mapped += mapped->byte_size();
                if (total_mapped > rules::max_input_bytes) return std::unexpected("mapped routing rules exceed 32 MiB total");
            } else {
                total_inline += content.size();
                if (total_inline > 8*1024*1024) return std::unexpected("routing rules exceed 8 MiB total");
            }
            keys.push_back(std::move(key));
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
            auto has_seed=[&](std::string const& url) -> bool { return input.read(url).has_value(); };
            if (auto ok=nxmm_detail::load_ordered_program(config,input.allows_unfetched_remote(),
                    read,has_seed,result.data,result.data_mmaps,result.ordered,result.tun_cidrs); !ok)
                return std::unexpected(std::move(ok.error()));
        }
        return result;
    }

    auto apply_tun_route_sets(config::TunInbound& tun, RouteFiles const& files) -> std::expected<void, std::string> {
        return nxmm_detail::apply_tun_route_sets_impl(tun, files.tun_cidrs);
    }

    auto load_route_files(config::Config const& config,std::string_view config_path,bool allow_unfetched_remote) -> std::expected<RouteFiles,std::string> {
        RuleFileInput input(config_path,allow_unfetched_remote);
        return load_route_files(config,input);
    }
}
