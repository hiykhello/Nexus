module config;
import std;
import glaze;
import config.kdl_common;
import config.provider_types;
import provider.types;
import rules.regex;

namespace config {
    using namespace config::kdl;
    auto parse_memory_watchdog(g::KdlNode const&) -> std::expected<MemoryWatchdogConfig, std::string>;
    auto parse_services_node(g::KdlNode const&, ServicesConfig&) -> std::expected<void, std::string>;
    auto normalize_groups(g::KdlDocument&) -> std::expected<void, std::string>;
    auto parse_dns(g::KdlNode const&) -> std::expected<DnsRouting, std::string>;
    auto parse_http_clients(g::KdlNode const&) -> std::expected<std::vector<NamedHttpClient>, std::string>;
    auto parse_state_options(g::KdlNode const&) -> std::expected<StateOptions, std::string>;
    auto parse_certificate_block(g::KdlNode const&) -> std::expected<CertificateConfig, std::string>;
    auto apply_state_options(Config&) -> std::expected<void, std::string>;
    auto apply_certificate_defaults(Config&) -> std::expected<void, std::string>;
    auto parse_direct_dial(kdl::Node const&, Config&) -> std::expected<void, std::string>;
    auto parse_outbound_selector(g::KdlNode const&, std::string_view, std::string_view) -> std::expected<OutboundSelector, std::string>;
    auto parse_vless_outbound(kdl::Node const&) -> std::expected<VlessOutbound, std::string>;
    auto shadowsocks_outbound(kdl::Node const&) -> std::expected<ShadowsocksOutbound, std::string>;
    auto parse_trojan_outbound(kdl::Node const&) -> std::expected<TrojanOutbound, std::string>;
    auto parse_anytls_outbound(kdl::Node const&) -> std::expected<AnyTlsOutbound, std::string>;
    auto parse_hysteria2_outbound(kdl::Node const&) -> std::expected<Hysteria2Outbound, std::string>;
    auto parse_snell_outbound(kdl::Node const&) -> std::expected<SnellOutbound, std::string>;
    auto parse_tcp_proxy_outbound(kdl::Node const&, TcpProxyProtocol) -> std::expected<TcpProxyOutbound, std::string>;
    auto parse_shadowtls_outbound(kdl::Node const&) -> std::expected<ShadowTlsOutbound, std::string>;
    auto parse_tuic_outbound(kdl::Node const&) -> std::expected<TuicOutbound, std::string>;
    auto parse_masque_outbound(kdl::Node const&) -> std::expected<MasqueOutbound, std::string>;
    auto parse_wireguard_outbound(kdl::Node const&) -> std::expected<WireGuardOutbound, std::string>;
    auto parse_ssh_outbound(kdl::Node const&) -> std::expected<SshOutbound, std::string>;
    auto parse_naive_outbound(kdl::Node const&) -> std::expected<NaiveOutbound, std::string>;
    auto parse_openvpn_outbound(kdl::Node const&) -> std::expected<OpenVpnOutbound, std::string>;
    auto parse_openconnect_outbound(kdl::Node const&) -> std::expected<OpenConnectOutbound, std::string>;

    namespace {
        auto parse_provider_format(std::string_view s) -> std::optional<provider::ProviderFormat> {
            using F = provider::ProviderFormat;
            if (s == "auto") return F::auto_detect;
            if (s == "uri" || s == "uri-list") return F::uri_list;
            if (s == "base64") return F::base64_uri;
            if (s == "clash" || s == "clash-yaml") return F::clash_yaml;
            if (s == "sing-box" || s == "singbox" || s == "singbox-json") return F::singbox_json;
            if (s == "sip008") return F::sip008_json;
            return std::nullopt;
        }

        auto parse_filter_field(Node const& c, provider::ProviderFilter& f) -> std::expected<bool, std::string> {
            auto v = scalar(c);
            if (c.name == "include") {
                if (!v || v->empty() || v->size() > 4096 || f.include_regexes.size() >= 256)
                    return error("invalid provider filter include regex");
                if (f.include_regex.empty()) f.include_regex = *v;
                f.include_regexes.push_back(*v);
                return true;
            }
            if (c.name == "exclude") {
                if (!v || v->empty() || v->size() > 4096 || f.exclude_regexes.size() >= 256)
                    return error("invalid provider filter exclude regex");
                if (f.exclude_regex.empty()) f.exclude_regex = *v;
                f.exclude_regexes.push_back(*v);
                return true;
            }
            if (c.name == "tag-prefix") {
                if (!f.tag_prefix.empty() || !v || v->size() > 128)
                    return error("invalid provider filter tag-prefix");
                f.tag_prefix = *v;
                return true;
            }
            if (c.name == "detour") {
                if (!f.detour.empty() || !v || !valid_name(*v))
                    return error("invalid provider filter detour");
                f.detour = *v;
                return true;
            }
            if (c.name == "ca-file") {
                if (!f.ca_file.empty() || !v || !absolute_path(*v))
                    return error("provider ca-file must be absolute");
                f.ca_file = *v;
                return true;
            }
            return false;
        }

        auto parse_one_provider(Node const& node, std::string_view forced_type)
            -> std::expected<ProxyProviderConfig, std::string> {
            auto name = argument(node);
            if (!name || !valid_name(*name) || node.tag)
                return error("proxy-provider requires a valid name");
            ProxyProviderConfig cfg;
            cfg.name = *name;
            bool type_seen = !forced_type.empty(), fmt_seen = false, interval_seen = false, filter_block = false;
            if (!forced_type.empty()) {
                if (forced_type == "http") cfg.type = ProxyProviderType::http;
                else if (forced_type == "file") cfg.type = ProxyProviderType::file;
                else return error("unsupported proxy-provider type: " + std::string(forced_type));
            }
            if (auto t = text_property(node, "type")) {
                if (type_seen) return error("duplicate proxy-provider type");
                if (*t == "http") cfg.type = ProxyProviderType::http;
                else if (*t == "file") cfg.type = ProxyProviderType::file;
                else return error("proxy-provider type must be file or http");
                type_seen = true;
            }
            if (node.properties.size() > std::size_t{bool(text_property(node, "type"))})
                return error("unsupported property on proxy-provider");

            for (auto const& c : node.children) {
                if (c.name == "filter") {
                    if (filter_block || c.tag || !c.arguments.empty() || !c.properties.empty())
                        return error("invalid proxy-provider filter block");
                    filter_block = true;
                    for (auto const& fc : c.children) {
                        auto ok = parse_filter_field(fc, cfg.filter);
                        if (!ok) return std::unexpected(ok.error());
                        if (!*ok) return error("unsupported proxy-provider filter field: " + fc.name);
                    }
                    continue;
                }
                if (auto fk = parse_filter_field(c, cfg.filter); !fk) return std::unexpected(fk.error());
                else if (*fk) continue;

                if (c.name == "type") {
                    auto v = scalar(c);
                    if (type_seen || !v) return error("invalid or duplicate proxy-provider type");
                    if (*v == "http") cfg.type = ProxyProviderType::http;
                    else if (*v == "file") cfg.type = ProxyProviderType::file;
                    else return error("proxy-provider type must be file or http");
                    type_seen = true;
                } else if (c.name == "path") {
                    auto v = scalar(c);
                    if (!cfg.path.empty() || !v || v->empty() || v->size() > 1024 || v->contains('\0'))
                        return error("invalid proxy-provider path");
                    cfg.path = *v;
                } else if (c.name == "url") {
                    auto v = scalar(c);
                    if (!cfg.url.empty() || !v || !v->starts_with("https://") || v->size() > 2048 || v->contains('\0'))
                        return error("proxy-provider url must be https://");
                    cfg.url = *v;
                    if (!type_seen) { cfg.type = ProxyProviderType::http; type_seen = true; }
                } else if (c.name == "http-client") {
                    auto v = scalar(c);
                    if (!cfg.http_client.empty() || !v || !valid_name(*v))
                        return error("invalid proxy-provider http-client");
                    cfg.http_client = *v;
                } else if (c.name == "cache-dir") {
                    auto v = scalar(c);
                    if (!cfg.cache_dir.empty() || !v || !absolute_path(*v))
                        return error("proxy-provider cache-dir must be absolute");
                    cfg.cache_dir = *v;
                } else if (c.name == "format") {
                    auto v = scalar(c);
                    auto f = v ? parse_provider_format(*v) : std::nullopt;
                    if (fmt_seen || !f) return error("unsupported proxy-provider format");
                    cfg.format = *f;
                    fmt_seen = true;
                } else if (c.name == "update-interval-ms") {
                    auto iv = integer(c);
                    if (interval_seen || !iv || *iv < 1000 || *iv > 604800000)
                        return error("proxy-provider update-interval-ms must be 1000..604800000");
                    cfg.update_interval_ms = static_cast<std::uint32_t>(*iv);
                    interval_seen = true;
                } else {
                    return error("unsupported proxy-provider field: " + c.name);
                }
            }
            if (cfg.type == ProxyProviderType::file && cfg.path.empty())
                return error("file proxy-provider requires path");
            if (cfg.type == ProxyProviderType::http && cfg.url.empty())
                return error("http proxy-provider requires url");
            return cfg;
        }
    }

    auto is_extra_top_level(std::string_view name) noexcept -> bool {
        return name == "services" || name == "memory-watchdog" ||
               name == "proxy-providers" || name == "proxy-provider";
    }

    auto parse_extra_top_level(Node const& node, Config& result) -> std::expected<void, std::string> {
        if (node.name == "services") return parse_services_node(node, result.services);
        if (node.name == "memory-watchdog") {
            if (result.services.memory_watchdog) return error("duplicate memory-watchdog block");
            auto parsed = parse_memory_watchdog(node);
            if (!parsed) return std::unexpected(parsed.error());
            result.services.memory_watchdog = std::move(*parsed);
            return {};
        }
        if (node.name == "proxy-provider") {
            auto p = parse_one_provider(node, {});
            if (!p) return std::unexpected(p.error());
            result.proxy_providers.push_back(std::move(*p));
            return {};
        }
        if (node.tag || !node.arguments.empty() || !node.properties.empty())
            return error("proxy-providers accepts only child provider nodes");
        for (auto const& c : node.children) {
            std::string_view forced = (c.name == "file" || c.name == "http") ? std::string_view(c.name) :
                (c.name == "provider" ? std::string_view{} : std::string_view{"?"});
            if (forced == "?") return error("proxy-providers accepts provider, file or http nodes");
            auto p = parse_one_provider(c, forced);
            if (!p) return std::unexpected(p.error());
            result.proxy_providers.push_back(std::move(*p));
        }
        return {};
    }

    auto validate_proxy_providers(Config& config) -> std::expected<void, std::string> {
        std::unordered_set<std::string_view> seen_providers, http_names;
        seen_providers.reserve(config.proxy_providers.size());
        http_names.reserve(config.http_clients.size());
        for (auto const& hc : config.http_clients) http_names.insert(hc.name);
        for (auto& p : config.proxy_providers) {
            if (!seen_providers.insert(p.name).second)
                return error("duplicate proxy-provider name: " + p.name);
            if (p.type == ProxyProviderType::http) {
                if (p.http_client.empty()) p.http_client = config.default_http_client;
                if (p.http_client.empty() || !http_names.contains(p.http_client))
                    return error("http proxy-provider requires http-client or routing default-http-client");
            }
            if (!p.filter.include_regex.empty() && p.filter.include_regexes.empty()) {
                if (!provider::compile_filter_regex(p.filter.include_regex))
                    return error("invalid proxy-provider include regex: " + p.name);
            }
            for (auto const& pat : p.filter.include_regexes) {
                if (!provider::compile_filter_regex(pat))
                    return error("invalid proxy-provider include regex: " + p.name);
            }
            if (!p.filter.exclude_regex.empty() && p.filter.exclude_regexes.empty()) {
                if (!provider::compile_filter_regex(p.filter.exclude_regex))
                    return error("invalid proxy-provider exclude regex: " + p.name);
            }
            for (auto const& pat : p.filter.exclude_regexes) {
                if (!provider::compile_filter_regex(pat))
                    return error("invalid proxy-provider exclude regex: " + p.name);
            }
        }
        for (auto const& sel : config.selectors) {
            for (auto const& pname : sel.use_providers) {
                if (!seen_providers.contains(pname))
                    return error("selector '" + sel.name + "' references unknown proxy-provider: " + pname);
            }
        }
        return {};
    }

    auto parse_provider_manifest(std::string_view input) -> std::expected<Config, std::string> {
        auto doc = kdl::read_document(input, max_config_bytes);
        if (!doc) return std::unexpected(std::move(doc.error()));
        if (auto norm = normalize_groups(*doc); !norm) return std::unexpected(std::move(norm.error()));
        Config out;
        std::optional<std::string> direct, block;
        auto parse_manifest_outbound = [&](Node const& ob) -> std::expected<void, std::string> {
            auto t = text_property(ob, "type");
            auto n = argument(ob);
            if (!t || !n || !valid_name(*n)) return {};
            if (*t == "direct" && !direct) {
                if (auto d = parse_direct_dial(ob, out); !d) return std::unexpected(d.error());
                direct = *n;
            } else if (*t == "block" && !block && ob.children.empty()) {
                block = *n;
            } else if ((*t == "selector" || *t == "fallback" || *t == "url-test" || *t == "load-balance") &&
                       out.selectors.size() < max_tunnel_outbounds) {
                auto has_use = std::ranges::any_of(ob.children, [](auto const& c) { return c.name == "use"; });
                if (!has_use) {
                    if (auto s = parse_outbound_selector(ob, *n, *t)) out.selectors.push_back(std::move(*s));
                }
            } else if (*t == "vless" && out.vless_outbounds.size() < max_tunnel_outbounds) {
                auto p = parse_vless_outbound(ob); if (!p) return std::unexpected(p.error());
                out.vless_outbounds.push_back({*n, std::move(*p)});
            } else if (*t == "shadowsocks" && out.shadowsocks_outbounds.size() < max_tunnel_outbounds) {
                auto p = shadowsocks_outbound(ob); if (!p) return std::unexpected(p.error());
                out.shadowsocks_outbounds.push_back({*n, std::move(*p)});
            } else if (*t == "trojan" && out.trojan_outbounds.size() < max_tunnel_outbounds) {
                auto p = parse_trojan_outbound(ob); if (!p) return std::unexpected(p.error());
                out.trojan_outbounds.push_back({*n, std::move(*p)});
            } else if (*t == "anytls" && out.anytls_outbounds.size() < max_tunnel_outbounds) {
                auto p = parse_anytls_outbound(ob); if (!p) return std::unexpected(p.error());
                out.anytls_outbounds.push_back({*n, std::move(*p)});
            } else if (*t == "hysteria2" && out.hysteria2_outbounds.size() < max_tunnel_outbounds) {
                auto p = parse_hysteria2_outbound(ob); if (!p) return std::unexpected(p.error());
                out.hysteria2_outbounds.push_back({*n, std::move(*p)});
            } else if (*t == "snell" && out.snell_outbounds.size() < max_tunnel_outbounds) {
                auto p = parse_snell_outbound(ob); if (!p) return std::unexpected(p.error());
                out.snell_outbounds.push_back({*n, std::move(*p)});
            } else if ((*t == "socks5" || *t == "http-connect" || *t == "socks4" || *t == "socks4a") &&
                       out.tcp_proxy_outbounds.size() < max_tunnel_outbounds) {
                auto proto = *t == "socks5" ? TcpProxyProtocol::socks5 : *t == "socks4" ? TcpProxyProtocol::socks4 :
                    *t == "socks4a" ? TcpProxyProtocol::socks4a : TcpProxyProtocol::http_connect;
                auto p = parse_tcp_proxy_outbound(ob, proto); if (!p) return std::unexpected(p.error());
                out.tcp_proxy_outbounds.push_back({*n, std::move(*p)});
            } else if (*t == "shadowtls" && out.shadowtls_outbounds.size() < max_tunnel_outbounds) {
                auto p = parse_shadowtls_outbound(ob); if (!p) return std::unexpected(p.error());
                out.shadowtls_outbounds.push_back({*n, std::move(*p)});
            } else if (*t == "tuic" && out.tuic_outbounds.size() < max_tunnel_outbounds) {
                auto p = parse_tuic_outbound(ob); if (!p) return std::unexpected(p.error());
                out.tuic_outbounds.push_back({*n, std::move(*p)});
            } else if (*t == "masque" && out.masque_outbounds.size() < max_tunnel_outbounds) {
                auto p = parse_masque_outbound(ob); if (!p) return std::unexpected(p.error());
                out.masque_outbounds.push_back({*n, std::move(*p)});
            } else if (*t == "wireguard" && out.wireguard_outbounds.size() < max_tunnel_outbounds) {
                auto p = parse_wireguard_outbound(ob); if (!p) return std::unexpected(p.error());
                out.wireguard_outbounds.push_back({*n, std::move(*p)});
            } else if (*t == "ssh" && out.ssh_outbounds.size() < max_tunnel_outbounds) {
                auto p = parse_ssh_outbound(ob); if (!p) return std::unexpected(p.error());
                out.ssh_outbounds.push_back({*n, std::move(*p)});
            } else if (*t == "naive" && out.naive_outbounds.size() < max_tunnel_outbounds) {
                auto p = parse_naive_outbound(ob); if (!p) return std::unexpected(p.error());
                out.naive_outbounds.push_back({*n, std::move(*p)});
            } else if (*t == "openvpn" && out.openvpn_outbounds.size() < max_tunnel_outbounds) {
                auto p = parse_openvpn_outbound(ob); if (!p) return std::unexpected(p.error());
                out.openvpn_outbounds.push_back({*n, std::move(*p)});
            } else if (*t == "openconnect" && out.openconnect_outbounds.size() < max_tunnel_outbounds) {
                auto p = parse_openconnect_outbound(ob); if (!p) return std::unexpected(p.error());
                out.openconnect_outbounds.push_back({*n, std::move(*p)});
            } else if (*t == "tailscale" && out.tailscale_outbounds.empty() && ob.children.size() == 1 &&
                       ob.children[0].name == "endpoint-file") {
                if (auto f = scalar(ob.children[0]); f && absolute_path(*f))
                    out.tailscale_outbounds.push_back({*n, std::move(*f)});
            }
            return {};
        };
        for (auto const& node : *doc) {
            if (node.name == "proxy-providers" || node.name == "proxy-provider") {
                if (auto ok = parse_extra_top_level(node, out); !ok) return std::unexpected(ok.error());
            } else if (node.name == "http-clients") {
                if (!out.http_clients.empty()) return error("duplicate http-clients block");
                auto clients = parse_http_clients(node);
                if (!clients) return std::unexpected(clients.error());
                out.http_clients = std::move(*clients);
            } else if (node.name == "dns") {
                if (out.dns) return error("duplicate dns block");
                auto dns = parse_dns(node);
                if (!dns) return std::unexpected(dns.error());
                out.dns = std::move(*dns);
            } else if (node.name == "state") {
                if (out.state) return error("duplicate state block");
                auto st = parse_state_options(node);
                if (!st) return std::unexpected(st.error());
                out.state = std::move(*st);
            } else if (node.name == "certificate") {
                if (out.certificate) return error("duplicate certificate block");
                auto cert = parse_certificate_block(node);
                if (!cert) return std::unexpected(cert.error());
                out.certificate = std::move(*cert);
            } else if (node.name == "outbounds") {
                for (auto const& c : node.children)
                    if (auto ok = parse_manifest_outbound(c); !ok) return std::unexpected(ok.error());
            } else if (node.name == "outbound") {
                if (auto ok = parse_manifest_outbound(node); !ok) return std::unexpected(ok.error());
            } else if (node.name == "routing") {
                for (auto const& child : node.children) {
                    if (child.name == "default-http-client") {
                        auto v = scalar(child);
                        if (!out.default_http_client.empty() || !v || !valid_name(*v))
                            return error("invalid routing default-http-client");
                        out.default_http_client = *v;
                    }
                }
            }
        }
        out.direct_outbound_name = direct.value_or("direct");
        out.block_outbound_name = block;
        if (auto ok = apply_state_options(out); !ok) return std::unexpected(ok.error());
        if (auto ok = apply_certificate_defaults(out); !ok) return std::unexpected(ok.error());
        // Bind only selectors whose members are all statically defined in this manifest.
        std::vector<OutboundSelector> static_selectors;
        for (auto& sel : out.selectors) {
            if (std::ranges::all_of(sel.members, [&](std::string const& m) {
                return outbound_index(out, out.direct_outbound_name, block, m).has_value();
            })) static_selectors.push_back(std::move(sel));
        }
        out.selectors = std::move(static_selectors);
        if (!out.selectors.empty()) {
            if (auto bound = bind_outbound_selectors(out, out.direct_outbound_name, block); !bound)
                return std::unexpected(bound.error());
        }
        if (auto ok = validate_proxy_providers(out); !ok) return std::unexpected(ok.error());
        for (auto& client : out.http_clients) {
            if (!out.dns) return error("HTTP client requires a DNS block");
            auto r = std::ranges::find(out.dns->servers, client.resolver, &DnsServer::name);
            if (r == out.dns->servers.end()) return error("HTTP client domain-resolver not found");
            client.resolver_index = static_cast<std::size_t>(r - out.dns->servers.begin());
            bool used_by_provider = std::ranges::any_of(out.proxy_providers, [&](auto const& p) {
                return p.type == ProxyProviderType::http && p.http_client == client.name;
            });
            auto group = std::ranges::find(out.selectors, client.outbound, &OutboundSelector::name);
            if (group != out.selectors.end() && (group->uses_probe || group->uses_balance)) {
                if (used_by_provider) return error("HTTP client requires a manual outbound group");
                client.outbound_index = 1;
                continue;
            }
            auto ob = outbound_index(out, out.direct_outbound_name, block, client.outbound);
            if (!ob || *ob == 1) {
                if (used_by_provider) return error("HTTP client outbound is not available for proxy-provider");
                client.outbound_index = 1;
                continue;
            }
            client.outbound_index = *ob;
        }
        return out;
    }
}
