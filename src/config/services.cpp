module config;
import std;
import glaze;
import config.kdl_common;

namespace config {
    namespace g = ::glaze;
    using namespace config::kdl;

    namespace {
        auto opt_u64_prop(g::KdlNode const& n, std::string_view key, std::uint64_t& out) -> std::expected<bool, std::string> {
            auto p = property(n, key);
            if (!p) return false;
            auto v = integer(*p);
            if (!v) return error(std::string(key) + " must be an unsigned integer");
            out = *v;
            return true;
        }

        auto opt_str_prop(g::KdlNode const& n, std::string_view key, std::string& out) -> std::expected<bool, std::string> {
            auto p = property(n, key);
            if (!p) return false;
            auto v = string(*p);
            if (!v || v->empty()) return error(std::string(key) + " must be a non-empty string");
            out = *v;
            return true;
        }

        auto opt_bool_prop(g::KdlNode const& n, std::string_view key, bool& out) -> std::expected<bool, std::string> {
            auto p = property(n, key);
            if (!p) return false;
            if (p->tag || !std::holds_alternative<bool>(p->data)) return error(std::string(key) + " must be a boolean");
            out = std::get<bool>(p->data);
            return true;
        }
    }

    auto parse_memory_watchdog(g::KdlNode const& node) -> std::expected<MemoryWatchdogConfig, std::string> {
        MemoryWatchdogConfig cfg{};
        if (node.tag || !node.arguments.empty() || !node.children.empty())
            return error("memory-watchdog takes properties only");
        std::size_t expected = 0;
        for (auto [key, target] : {std::pair{"soft-mb", &cfg.soft_mb}, std::pair{"hard-mb", &cfg.hard_mb},
                 std::pair{"emergency-mb", &cfg.emergency_mb}}) {
            auto seen = opt_u64_prop(node, key, *target);
            if (!seen) return std::unexpected(seen.error());
            if (*seen) { if (*target == 0) return error("watchdog MiB threshold must be > 0"); ++expected; }
        }
        std::uint64_t cd = cfg.cooldown_ms;
        auto cd_seen = opt_u64_prop(node, "cooldown-ms", cd);
        if (!cd_seen) return std::unexpected(cd_seen.error());
        if (*cd_seen) {
            if (cd < 100 || cd > 600000) return error("watchdog cooldown-ms must be 100..600000");
            cfg.cooldown_ms = static_cast<std::uint32_t>(cd);
            ++expected;
        }
        if (node.properties.size() != expected || cfg.soft_mb > cfg.hard_mb || cfg.hard_mb > cfg.emergency_mb)
            return error("invalid memory-watchdog configuration");
        return cfg;
    }

    auto parse_services_node(g::KdlNode const& node, ServicesConfig& out) -> std::expected<void, std::string> {
        if (node.tag || !node.arguments.empty() || !node.properties.empty())
            return error("services node takes no arguments or properties");
        for (auto const& child : node.children) {
            if (child.name == "memory-watchdog") {
                if (out.memory_watchdog) return error("duplicate memory-watchdog service");
                auto parsed = parse_memory_watchdog(child);
                if (!parsed) return std::unexpected(parsed.error());
                out.memory_watchdog = std::move(*parsed);
            } else if (child.name == "ssmapi") {
                if (out.ssmapi || child.tag || !child.arguments.empty() || !child.children.empty())
                    return error("invalid or duplicate ssmapi service");
                SsmApiConfig cfg{.enabled = true};
                std::size_t expected = 0;
                auto en = opt_bool_prop(child, "enabled", cfg.enabled);
                if (!en) return std::unexpected(en.error());
                expected += *en;
                auto pfx = opt_str_prop(child, "prefix", cfg.prefix);
                if (!pfx) return std::unexpected(pfx.error());
                expected += *pfx;
                if (child.properties.size() != expected || !cfg.prefix.starts_with('/'))
                    return error("invalid ssmapi service properties");
                out.ssmapi = std::move(cfg);
            } else if (child.name == "sni-demux") {
                if (out.sni_demux || child.tag || !child.arguments.empty())
                    return error("invalid or duplicate sni-demux service");
                SniDemuxConfig cfg{};
                std::size_t expected = 0;
                auto h = opt_str_prop(child, "listen-host", cfg.listen_host);
                if (!h) return std::unexpected(h.error());
                expected += *h;
                std::uint64_t lp = cfg.listen_port;
                auto p = opt_u64_prop(child, "listen-port", lp);
                if (!p) return std::unexpected(p.error());
                if (*p) { if (!lp || lp > 65535) return error("invalid sni-demux listen-port"); cfg.listen_port = static_cast<std::uint16_t>(lp); ++expected; }
                auto fb = opt_str_prop(child, "fallback-upstream", cfg.fallback_upstream);
                if (!fb) return std::unexpected(fb.error());
                expected += *fb;
                if (child.properties.size() != expected) return error("invalid sni-demux properties");
                for (auto const& r : child.children) {
                    auto pat = argument(r), up = text_property(r, "upstream"), alpn = text_property(r, "alpn"), role = text_property(r, "role");
                    if (r.name != "rule" || r.tag || !r.children.empty() || !pat || pat->empty() || !up || up->empty() ||
                        r.properties.size() != 1u + unsigned(bool(alpn)) + unsigned(bool(role)) || cfg.rules.size() >= 128)
                        return error("invalid sni-demux rule");
                    cfg.rules.push_back({*pat, alpn ? *alpn : "", role ? *role : "proxy", *up});
                }
                out.sni_demux = std::move(cfg);
            } else if (child.name == "acme") {
                if (out.acme || child.tag || !child.arguments.empty()) return error("invalid or duplicate acme service");
                AcmeServiceConfig cfg{};
                std::size_t expected = 0;
                auto dir = opt_str_prop(child, "directory-url", cfg.directory_url);
                auto em = opt_str_prop(child, "email", cfg.email);
                auto ch = opt_str_prop(child, "challenge", cfg.challenge);
                auto sd = opt_str_prop(child, "state-dir", cfg.state_dir);
                auto hlh = opt_str_prop(child, "http-listen-host", cfg.http_listen_host);
                auto alh = opt_str_prop(child, "tls-alpn-listen-host", cfg.tls_alpn_listen_host);
                auto caf = opt_str_prop(child, "ca-file", cfg.ca_file);
                auto dp = opt_str_prop(child, "dns01-provider", cfg.dns01_provider);
                auto dt = opt_str_prop(child, "dns01-api-token-file", cfg.dns01_api_token_file);
                auto dak = opt_str_prop(child, "dns01-access-key-id-file", cfg.dns01_access_key_id_file);
                auto das = opt_str_prop(child, "dns01-access-key-secret-file", cfg.dns01_access_key_secret_file);
                auto ek = opt_str_prop(child, "eab-kid", cfg.eab_kid);
                auto eh = opt_str_prop(child, "eab-hmac-file", cfg.eab_hmac_file);
                std::uint64_t hlp = cfg.http_listen_port, alp = cfg.tls_alpn_listen_port;
                std::uint64_t rbs = static_cast<std::uint64_t>(cfg.renew_before_seconds), cim = cfg.check_interval_ms;
                auto hlp_s = opt_u64_prop(child, "http-listen-port", hlp);
                auto alp_s = opt_u64_prop(child, "tls-alpn-listen-port", alp);
                auto rbs_s = opt_u64_prop(child, "renew-before-seconds", rbs);
                auto cim_s = opt_u64_prop(child, "check-interval-ms", cim);
                if (!dir || !em || !ch || !sd || !hlh || !alh || !caf || !dp || !dt || !dak || !das || !ek || !eh ||
                    !hlp_s || !alp_s || !rbs_s || !cim_s)
                    return error("invalid acme property");
                expected += *dir + *em + *ch + *sd + *hlh + *alh + *caf + *dp + *dt + *dak + *das + *ek + *eh +
                            *hlp_s + *alp_s + *rbs_s + *cim_s;
                if (child.properties.size() != expected || cfg.directory_url.empty() || cfg.state_dir.empty() ||
                    !cfg.state_dir.starts_with('/') || hlp > 65535 || alp > 65535 || !cim)
                    return error("acme requires directory-url and absolute state-dir");
                if (cfg.challenge != "http-01" && cfg.challenge != "tls-alpn-01" && cfg.challenge != "dns-01")
                    return error("invalid acme challenge type");
                cfg.http_listen_port = static_cast<std::uint16_t>(hlp);
                cfg.tls_alpn_listen_port = static_cast<std::uint16_t>(alp);
                cfg.renew_before_seconds = static_cast<std::int64_t>(rbs);
                cfg.check_interval_ms = static_cast<std::uint32_t>(std::min<std::uint64_t>(cim, 86400000));
                for (auto const& d : child.children) {
                    auto val = scalar(d);
                    if (!val || val->empty()) return error("invalid acme child entry: " + d.name);
                    if (d.name == "domain") {
                        if (cfg.domains.size() >= 32) return error("invalid acme domain entry");
                        cfg.domains.push_back(*val);
                    } else if (d.name == "dns01-provider" && cfg.dns01_provider.empty()) {
                        cfg.dns01_provider = *val;
                    } else if (d.name == "dns01-api-token-file" && cfg.dns01_api_token_file.empty()) {
                        cfg.dns01_api_token_file = *val;
                    } else if (d.name == "dns01-access-key-id-file" && cfg.dns01_access_key_id_file.empty()) {
                        cfg.dns01_access_key_id_file = *val;
                    } else if (d.name == "dns01-access-key-secret-file" && cfg.dns01_access_key_secret_file.empty()) {
                        cfg.dns01_access_key_secret_file = *val;
                    } else if (d.name == "eab-kid" && cfg.eab_kid.empty()) {
                        cfg.eab_kid = *val;
                    } else if (d.name == "eab-hmac-file" && cfg.eab_hmac_file.empty()) {
                        cfg.eab_hmac_file = *val;
                    } else {
                        return error("invalid or duplicate acme entry: " + d.name);
                    }
                }
                if (cfg.domains.empty()) return error("acme requires at least one domain");
                if (!cfg.dns01_provider.empty()) {
                    if (cfg.challenge != "dns-01")
                        return error("acme dns01-provider requires challenge=\"dns-01\"");
                    if (cfg.dns01_provider != "file" && cfg.dns01_provider != "cloudflare" && cfg.dns01_provider != "alidns")
                        return error("acme dns01-provider must be file, cloudflare or alidns");
                }
                if (cfg.dns01_provider == "cloudflare") {
                    if (!absolute_path(cfg.dns01_api_token_file) || !cfg.dns01_access_key_id_file.empty() || !cfg.dns01_access_key_secret_file.empty())
                        return error("acme cloudflare dns01-provider requires absolute dns01-api-token-file");
                } else if (cfg.dns01_provider == "alidns") {
                    if (!absolute_path(cfg.dns01_access_key_id_file) || !absolute_path(cfg.dns01_access_key_secret_file) || !cfg.dns01_api_token_file.empty())
                        return error("acme alidns dns01-provider requires absolute dns01-access-key-id-file and dns01-access-key-secret-file");
                } else if (!cfg.dns01_api_token_file.empty() || !cfg.dns01_access_key_id_file.empty() || !cfg.dns01_access_key_secret_file.empty()) {
                    return error("acme dns01 credential files require dns01-provider cloudflare or alidns");
                }
                if (cfg.eab_kid.empty() != cfg.eab_hmac_file.empty())
                    return error("acme eab-kid and eab-hmac-file must be configured together");
                if (!cfg.eab_kid.empty()) {
                    bool ok_kid = cfg.eab_kid.size() <= 256 && std::ranges::none_of(cfg.eab_kid, [](unsigned char c) {
                        return c <= 0x20 || c >= 0x7f || c == '"' || c == '\\';
                    });
                    if (!ok_kid || !absolute_path(cfg.eab_hmac_file))
                        return error("invalid acme eab-kid or eab-hmac-file");
                }
                out.acme = std::move(cfg);
            } else if (child.name == "reverse-tunnel") {
                if (out.reverse_tunnel || child.tag || !child.arguments.empty() || !child.children.empty())
                    return error("invalid or duplicate reverse-tunnel service");
                ReverseTunnelServiceConfig cfg{};
                auto tok = opt_str_prop(child, "token", cfg.token);
                if (!tok || !*tok) return error("reverse-tunnel requires token");
                auto mode_s = opt_str_prop(child, "mode", cfg.mode);
                auto ch_s = opt_str_prop(child, "control-host", cfg.control_host);
                auto eh_s = opt_str_prop(child, "expose-host", cfg.expose_host);
                auto th_s = opt_str_prop(child, "target-host", cfg.target_host);
                std::uint64_t ms = cfg.max_streams, hb = cfg.heartbeat_timeout_ms;
                std::uint64_t cp = cfg.control_port, ep = cfg.expose_port, tp = cfg.target_port;
                auto ms_s = opt_u64_prop(child, "max-streams", ms);
                auto hb_s = opt_u64_prop(child, "heartbeat-timeout-ms", hb);
                auto cp_s = opt_u64_prop(child, "control-port", cp);
                auto ep_s = opt_u64_prop(child, "expose-port", ep);
                auto tp_s = opt_u64_prop(child, "target-port", tp);
                if (!mode_s || !ch_s || !eh_s || !th_s || !ms_s || !hb_s || !cp_s || !ep_s || !tp_s)
                    return error("invalid reverse-tunnel properties");
                std::size_t expected = 1u + *mode_s + *ch_s + *eh_s + *th_s + *ms_s + *hb_s + *cp_s + *ep_s + *tp_s;
                if (child.properties.size() != expected || !ms || ms > 4096 || !hb ||
                    (cfg.mode != "server" && cfg.mode != "client") || cp > 65535 || ep > 65535 || tp > 65535)
                    return error("invalid reverse-tunnel properties");
                cfg.max_streams = static_cast<std::size_t>(ms);
                cfg.heartbeat_timeout_ms = static_cast<std::uint32_t>(hb);
                cfg.control_port = static_cast<std::uint16_t>(cp);
                cfg.expose_port = static_cast<std::uint16_t>(ep);
                cfg.target_port = static_cast<std::uint16_t>(tp);
                out.reverse_tunnel = std::move(cfg);
            } else if (child.name == "bridge") {
                if (out.bridge || child.tag || !child.arguments.empty() || !child.children.empty())
                    return error("invalid or duplicate bridge service");
                BridgeServiceConfig cfg{};
                std::size_t expected = 0;
                auto ti = opt_str_prop(child, "tun-interface", cfg.tun_interface);
                auto pi = opt_str_prop(child, "physical-interface", cfg.physical_interface);
                auto v4 = opt_bool_prop(child, "allow-ipv4", cfg.allow_ipv4);
                auto v6 = opt_bool_prop(child, "allow-ipv6", cfg.allow_ipv6);
                auto ll = opt_bool_prop(child, "drop-link-local", cfg.drop_link_local);
                std::uint64_t mtu = cfg.mtu;
                auto mp = opt_u64_prop(child, "mtu", mtu);
                if (!ti || !pi || !v4 || !v6 || !ll || !mp) return error("invalid bridge property");
                expected += *ti + *pi + *v4 + *v6 + *ll + *mp;
                if (*mp && (mtu < 576 || mtu > 65535)) return error("invalid bridge mtu");
                cfg.mtu = static_cast<std::uint16_t>(mtu);
                if (child.properties.size() != expected) return error("unsupported bridge property");
                out.bridge = std::move(cfg);
            } else if (child.name == "tor") {
                if (out.tor || child.tag || !child.arguments.empty() || !child.children.empty())
                    return error("invalid or duplicate tor service");
                TorServiceConfig cfg{};
                std::size_t expected = 0;
                auto sh = opt_str_prop(child, "socks-host", cfg.socks_host);
                auto ch = opt_str_prop(child, "control-host", cfg.control_host);
                auto pw = opt_str_prop(child, "control-password", cfg.control_password);
                auto ck = opt_str_prop(child, "cookie-hex", cfg.cookie_hex);
                auto iso = opt_bool_prop(child, "isolate-streams", cfg.isolate_streams);
                auto ars = opt_bool_prop(child, "allow-remote-socks", cfg.allow_remote_socks);
                std::uint64_t sp = cfg.socks_port, cp = cfg.control_port;
                auto sp_s = opt_u64_prop(child, "socks-port", sp);
                auto cp_s = opt_u64_prop(child, "control-port", cp);
                if (!sh || !ch || !pw || !ck || !iso || !ars || !sp_s || !cp_s) return error("invalid tor property");
                expected += *sh + *ch + *pw + *ck + *iso + *ars + *sp_s + *cp_s;
                if (!sp || sp > 65535 || !cp || cp > 65535 || child.properties.size() != expected)
                    return error("invalid tor service configuration");
                cfg.socks_port = static_cast<std::uint16_t>(sp);
                cfg.control_port = static_cast<std::uint16_t>(cp);
                out.tor = std::move(cfg);
            } else if (child.name == "derp-server") {
                if (out.derp_server || child.tag || !child.arguments.empty() || !child.children.empty())
                    return error("invalid or duplicate derp-server service");
                DerpServerServiceConfig cfg{};
                std::uint64_t mp = cfg.max_peers, lp = cfg.listen_port;
                auto s = opt_u64_prop(child, "max-peers", mp);
                auto lh = opt_str_prop(child, "listen-host", cfg.listen_host);
                auto lp_s = opt_u64_prop(child, "listen-port", lp);
                auto cf = opt_str_prop(child, "cert-file", cfg.cert_file);
                auto kf = opt_str_prop(child, "key-file", cfg.key_file);
                if (!s || !lh || !lp_s || !cf || !kf) return error("invalid derp-server configuration");
                std::size_t expected = *s + *lh + *lp_s + *cf + *kf;
                if (child.properties.size() != expected || !mp || mp > 8192 || lp > 65535 ||
                    (cfg.cert_file.empty() != cfg.key_file.empty()))
                    return error("invalid derp-server configuration");
                cfg.max_peers = static_cast<std::size_t>(mp);
                cfg.listen_port = static_cast<std::uint16_t>(lp);
                out.derp_server = std::move(cfg);
            } else {
                return error("unsupported service node: " + child.name);
            }
        }
        return {};
    }

    auto parse_alpn_list(g::KdlNode const&, std::vector<std::string>&) -> std::expected<void, std::string>;

    auto parse_shared_inbound_tls_field(g::KdlNode const& field, std::string& provider, std::string& ech_key,
        std::vector<std::string>& alpn, bool& cert_hot_reload, bool& reload_seen) -> std::expected<bool, std::string> {
        if (field.name == "certificate-provider") {
            auto v = scalar(field);
            if (!provider.empty() || !v || !valid_name(*v))
                return error("invalid or duplicate TLS certificate-provider");
            provider = *v;
            return true;
        }
        if (field.name == "ech-key-file") {
            auto v = scalar(field);
            if (!ech_key.empty() || !v || !absolute_path(*v))
                return error("TLS ech-key-file requires one absolute path");
            ech_key = *v;
            return true;
        }
        if (field.name == "alpn") {
            if (auto ok = parse_alpn_list(field, alpn); !ok) return std::unexpected(ok.error());
            return true;
        }
        if (field.name == "cert-hot-reload") {
            auto v = boolean(field);
            if (reload_seen || !v) return error("invalid or duplicate TLS cert-hot-reload");
            cert_hot_reload = *v;
            reload_seen = true;
            return true;
        }
        return false;
    }

    auto extract_delegated_inbound_tls(g::KdlNode const& input, std::string& provider, std::string& ech_key,
        std::vector<std::string>& alpn, bool& cert_hot_reload) -> std::expected<g::KdlNode, std::string> {
        g::KdlNode copy = input;
        bool reload_seen = false;
        for (auto& child : copy.children) {
            if (child.name != "tls" || child.tag || !child.arguments.empty() || !child.properties.empty()) continue;
            std::vector<g::KdlNode> kept;
            bool has_cert = false, has_key = false;
            for (auto const& field : child.children) {
                auto matched = parse_shared_inbound_tls_field(field, provider, ech_key, alpn, cert_hot_reload, reload_seen);
                if (!matched) return std::unexpected(matched.error());
                if (*matched) continue;
                if (field.name == "certificate-file") has_cert = true;
                if (field.name == "private-key-file") has_key = true;
                kept.push_back(field);
            }
            if (!provider.empty()) {
                if (has_cert || has_key)
                    return error("TLS certificate-provider cannot be combined with certificate-file or private-key-file");
                if (cert_hot_reload)
                    return error("TLS cert-hot-reload cannot be combined with certificate-provider");
                g::KdlNode cf{.name = "certificate-file"}; cf.arguments.push_back(g::KdlValue{.data = std::string("/__provider__")});
                g::KdlNode kf{.name = "private-key-file"}; kf.arguments.push_back(g::KdlValue{.data = std::string("/__provider__")});
                kept.push_back(std::move(cf)); kept.push_back(std::move(kf));
            }
            child.children = std::move(kept);
            break;
        }
        return copy;
    }
}
