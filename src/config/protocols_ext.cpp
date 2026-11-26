module config;
import std;
import http.header;
import config.kdl_common;
import glaze;

namespace config {
    auto dns_ipv4(std::string_view) -> std::optional<std::array<std::uint8_t,4>>;
    auto dns_ipv6(std::string_view) -> std::optional<std::array<std::uint8_t,16>>;
    auto dns_hostname(std::string_view) -> bool;
    auto parse_tcp_dial_option(glaze::KdlNode const&,TcpSocketOptions&) -> std::expected<bool,std::string>;
    auto parse_password_tls_outbound(glaze::KdlNode const&,std::string_view,std::string_view) -> std::expected<PasswordTlsOutbound,std::string>;
    auto validate_password_tls_outbound(PasswordTlsOutbound&,Config const&,std::string_view) -> std::expected<void,std::string>;
    auto validate_naive_outbounds(Config&,std::string_view,std::optional<std::string> const&,bool (*)(void const*,std::string_view),void const*) -> std::expected<void,std::string>;
    auto validate_vpn_outbounds(Config&,std::string_view,std::optional<std::string> const&,bool (*)(void const*,std::string_view),void const*) -> std::expected<void,std::string>;
    auto validate_proxy_providers(Config&) -> std::expected<void,std::string>;

    auto parse_quic_ech_field(kdl::Node const& field, QuicEchOptions& options) -> bool {
        if (options.dns || !options.config_file.empty()) return false;
        if (field.name == "ech-dns" && kdl::boolean(field) == true) { options.dns = true; return true; }
        if (field.name != "ech-config-file") return false;
        auto path = kdl::scalar(field);
        if (!path || !kdl::absolute_path(*path)) return false;
        options.config_file = *path;
        return true;
    }

    auto validate_quic_ech(QuicEchOptions const& ech, std::string_view name, bool has_dns)
        -> std::expected<void, std::string> {
        if ((ech.dns || !ech.config_file.empty()) && (!dns_hostname(name) || dns_ipv4(name)))
            return kdl::error("QUIC ECH requires a DNS server-name");
        if (ech.dns) {
#ifdef NEXUS_DNS_RESPONSE
            if (!has_dns) return kdl::error("ech-dns requires configured DNS servers");
#else
            return kdl::error("ech-dns requires the dns-response feature");
#endif
        }
        (void)has_dns;
        return {};
    }

    namespace {
        using namespace config::kdl;

        auto parse_endpoint_node(Node const& child, std::string& host, std::uint16_t& port,
                                 std::string_view label) -> std::expected<void, std::string> {
            auto h = text_property(child, "host");
            auto pval = property(child, "port");
            auto p = pval ? integer(*pval) : std::nullopt;
            if (child.tag || !child.arguments.empty() || !child.children.empty() || child.properties.size() != 2 ||
                !h || !endpoint_name(*h) || !p || !*p || *p > 65535)
                return error("invalid " + std::string(label));
            host = *h;
            port = static_cast<std::uint16_t>(*p);
            return {};
        }

        auto parse_quic_tls_block(Node const& child, std::string& sni, std::string& ca,
                                  TlsKeyExchange& exchange, TlsFingerprint& fp, QuicEchOptions& ech,
                                  std::vector<std::array<std::uint8_t,32>>& pins, std::string_view label)
            -> std::expected<void, std::string> {
            if (child.tag || !child.arguments.empty() || !child.properties.empty())
                return error("invalid " + std::string(label) + " TLS");
            bool verify = false, kx_seen = false, fp_seen = false;
            for (auto const& field : child.children) {
                auto val = scalar(field);
                if (field.name == "server-name" && sni.empty() && val && endpoint_name(*val)) sni = *val;
                else if (field.name == "ca-file" && ca.empty() && val && absolute_path(*val)) ca = *val;
                else if (field.name == "certificate-sha256") {
                    if (auto ok = parse_certificate_sha256(field, pins); !ok) return std::unexpected(ok.error());
                } else if (field.name == "key-exchange" && !kx_seen && val) {
                    if (*val == "x25519") exchange = TlsKeyExchange::x25519;
                    else if (*val == "x25519-mlkem768") exchange = TlsKeyExchange::x25519_mlkem768;
                    else if (*val == "x25519-mlkem768-only") exchange = TlsKeyExchange::x25519_mlkem768_only;
                    else return error("invalid " + std::string(label) + " TLS key-exchange");
                    kx_seen = true;
                } else if (field.name == "fingerprint" && !fp_seen && val) {
                    auto parsed = parse_tls_fingerprint(*val);
                    if (!parsed || *parsed==TlsFingerprint::tls12) return error("invalid " + std::string(label) + " TLS fingerprint");
                    fp = *parsed;
                    fp_seen = true;
                } else if (field.name == "verify" && !verify && boolean(field) == true) verify = true;
                else if (!parse_quic_ech_field(field, ech))
                    return error("unsupported or duplicate " + std::string(label) + " TLS field");
            }
            if (!verify || sni.empty())
                return error(std::string(label) + " requires authenticated TLS");
            return {};
        }

        auto parse_ip_listen(Node const& child, std::array<std::uint8_t, 16>& addr, bool& ipv6,
                             std::string* out_host, std::string_view label) -> std::expected<std::uint16_t, std::string> {
            auto host = text_property(child, "host");
            auto val = property(child, "port");
            auto port = val ? integer(*val) : std::nullopt;
            if (child.tag || !child.arguments.empty() || !child.children.empty() || child.properties.size() != 2 ||
                !host || !port || !*port || *port > 65535)
                return error("invalid " + std::string(label) + " listen");
            if (auto ip4 = dns_ipv4(*host)) { std::ranges::copy(*ip4, addr.begin()); ipv6 = false; }
            else if (auto ip6 = dns_ipv6(*host)) { addr = *ip6; ipv6 = true; }
            else return error(std::string(label) + " listen requires numeric IP without zone");
            if (out_host) *out_host = *host;
            return static_cast<std::uint16_t>(*port);
        }

        auto parse_cc_name(std::string_view v) -> bool {
            return v == "cubic" || v == "reno" || v == "bbr";
        }
    }

    auto parse_shadowtls_inbound(Node const& node) -> std::expected<InboundConfig, std::string> {
        auto tag = argument(node);
        auto type = text_property(node, "type");
        if (!tag || !valid_name(*tag) || node.properties.size() != 1 || !type || *type != "shadowtls")
            return error("invalid ShadowTLS inbound");
        InboundConfig result{*tag, 0, Inbound::shadowtls};
        ShadowTlsInbound cfg;
        bool listen = false, hs = false, tgt = false, auth = false, strict_seen = false;
        for (auto const& child : node.children) {
            if (child.name == "listen") {
                if (listen) return error("duplicate ShadowTLS listen");
                auto p = parse_ip_listen(child, cfg.listen_address, result.listen_ipv6, nullptr, "ShadowTLS");
                if (!p) return std::unexpected(p.error());
                result.port = *p; listen = true;
            } else if (child.name == "handshake") {
                if (hs) return error("duplicate ShadowTLS handshake");
                if (auto ok = parse_endpoint_node(child, cfg.handshake_host, cfg.handshake_port, "ShadowTLS handshake"); !ok)
                    return std::unexpected(ok.error());
                hs = true;
            } else if (child.name == "target") {
                if (tgt) return error("duplicate ShadowTLS target");
                if (auto ok = parse_endpoint_node(child, cfg.target_host, cfg.target_port, "ShadowTLS target"); !ok)
                    return std::unexpected(ok.error());
                tgt = true;
            } else if (child.name == "authentication") {
                if (auth || child.tag || !child.arguments.empty() || !child.properties.empty())
                    return error("invalid ShadowTLS authentication");
                for (auto const& u : child.children) {
                    auto uname = argument(u), pfile = text_property(u, "password-file");
                    if (u.name != "user" || !uname || !valid_name(*uname) || !pfile || !absolute_path(*pfile) ||
                        u.properties.size() != 1 || !u.children.empty() || cfg.users.size() >= 64 ||
                        std::ranges::any_of(cfg.users, [&](auto const& x) { return x.username == *uname; }))
                        return error("invalid or duplicate ShadowTLS user");
                    cfg.users.push_back({*uname, *pfile});
                }
                if (cfg.users.empty()) return error("ShadowTLS requires at least one user");
                auth = true;
            } else if (child.name == "strict-tls13") {
                auto v = boolean(child);
                if (strict_seen || !v) return error("invalid ShadowTLS strict-tls13");
                cfg.strict_tls13 = *v; strict_seen = true;
            } else return error("unsupported ShadowTLS inbound field: " + child.name);
        }
        if (!listen || !hs || !tgt || !auth)
            return error("ShadowTLS inbound requires listen, handshake, target and authentication");
        result.shadowtls = std::move(cfg);
        return result;
    }

    auto parse_shadowtls_outbound(Node const& node) -> std::expected<ShadowTlsOutbound, std::string> {
        auto parsed = parse_password_tls_outbound(node, "Trojan", "strict-tls13");
        if (!parsed) return std::unexpected(parsed.error());
        ShadowTlsOutbound out{std::move(*parsed), true};
        bool strict_seen = false;
        for (auto const& child : node.children) {
            if (child.name != "strict-tls13") continue;
            auto v = boolean(child);
            if (strict_seen || !v) return error("invalid ShadowTLS strict-tls13");
            out.strict_tls13 = *v; strict_seen = true;
        }
        return out;
    }

    auto parse_tuic_inbound(Node const& node) -> std::expected<InboundConfig, std::string> {
        auto tag = argument(node);
        auto type = text_property(node, "type");
        if (!tag || !valid_name(*tag) || node.properties.size() != 1 || !type || *type != "tuic")
            return error("invalid TUIC inbound");
        InboundConfig result{*tag, 0, Inbound::tuic};
        TuicInbound cfg;
        bool listen = false, auth = false, tls = false, cc = false, udp = false, hs_t = false, idle_t = false, mem = false;
        for (auto const& child : node.children) {
            if (child.name == "listen") {
                if (listen) return error("duplicate TUIC listen");
                auto p = parse_ip_listen(child, cfg.listen_address, result.listen_ipv6, &cfg.listen_host, "TUIC");
                if (!p) return std::unexpected(p.error());
                result.port = *p; listen = true;
            } else if (child.name == "authentication") {
                if (auth || child.tag || !child.arguments.empty() || !child.properties.empty())
                    return error("invalid TUIC authentication");
                for (auto const& u : child.children) {
                    auto uname = argument(u), ufile = text_property(u, "uuid-file"), pfile = text_property(u, "password-file");
                    if (u.name != "user" || !uname || !valid_name(*uname) || !ufile || !absolute_path(*ufile) ||
                        !pfile || !absolute_path(*pfile) || u.properties.size() != 2 || !u.children.empty() ||
                        cfg.users.size() >= 64 || std::ranges::any_of(cfg.users, [&](auto const& x) { return x.name == *uname; }))
                        return error("invalid or duplicate TUIC user");
                    cfg.users.push_back({*uname, *ufile, *pfile});
                }
                if (cfg.users.empty()) return error("TUIC requires at least one user");
                auth = true;
            } else if (child.name == "tls") {
                if (tls || child.tag || !child.arguments.empty() || !child.properties.empty()) return error("invalid TUIC TLS");
                for (auto const& f : child.children) {
                    auto v = scalar(f);
                    if (!v || !absolute_path(*v)) return error("TUIC TLS requires absolute paths");
                    if (f.name == "certificate-file" && cfg.certificate_file.empty()) cfg.certificate_file = *v;
                    else if (f.name == "private-key-file" && cfg.private_key_file.empty()) cfg.private_key_file = *v;
                    else return error("unsupported or duplicate TUIC TLS field");
                }
                if (cfg.certificate_file.empty() || cfg.private_key_file.empty()) return error("TUIC TLS requires cert and key");
                tls = true;
            } else if (child.name == "congestion-control") {
                auto v = scalar(child);
                if (cc || !v || !parse_cc_name(*v)) return error("invalid TUIC congestion-control");
                cfg.congestion_control = *v; cc = true;
            } else if (child.name == "udp") {
                auto v = boolean(child); if (udp || !v) return error("invalid TUIC udp flag");
                cfg.udp = *v; udp = true;
            } else if (child.name == "handshake-timeout-ms") {
                auto v = integer(child); if (hs_t || !v || !*v || *v > 3600000) return error("invalid TUIC handshake-timeout-ms");
                cfg.handshake_timeout_ms = static_cast<std::uint32_t>(*v); hs_t = true;
            } else if (child.name == "idle-timeout-ms") {
                auto v = integer(child); if (idle_t || !v || !*v || *v > 86400000) return error("invalid TUIC idle-timeout-ms");
                cfg.idle_timeout_ms = static_cast<std::uint32_t>(*v); idle_t = true;
            } else if (child.name == "native-bytes") {
                auto v = integer(child); if (mem || !v || *v < 65536 || *v > 1024ull * 1024 * 1024) return error("invalid TUIC native-bytes");
                cfg.native_bytes = static_cast<std::size_t>(*v); mem = true;
            } else return error("unsupported TUIC inbound field: " + child.name);
        }
        if (!listen || !auth || !tls) return error("TUIC inbound requires listen, authentication and TLS");
        result.tuic = std::move(cfg);
        return result;
    }

    auto parse_tuic_outbound(Node const& node) -> std::expected<TuicOutbound, std::string> {
        TuicOutbound cfg;
        bool server = false, auth = false, tls = false, cc = false, uos = false, hb = false, hs_t = false, idle_t = false, mem = false, to = false;
        for (auto const& child : node.children) {
            if (child.name == "server") {
                if (server) return error("duplicate TUIC server");
                if (auto ok = parse_endpoint_node(child, cfg.host, cfg.port, "TUIC server"); !ok) return std::unexpected(ok.error());
                server = true;
            } else if (child.name == "authentication") {
                if (auth || child.tag || !child.arguments.empty() || !child.properties.empty()) return error("invalid TUIC auth");
                for (auto const& f : child.children) {
                    auto v = scalar(f);
                    if (!v || !absolute_path(*v)) return error("TUIC auth requires absolute file paths");
                    if (f.name == "uuid-file" && cfg.uuid_file.empty()) cfg.uuid_file = *v;
                    else if (f.name == "password-file" && cfg.password_file.empty()) cfg.password_file = *v;
                    else return error("invalid or duplicate TUIC auth field");
                }
                if (cfg.uuid_file.empty() || cfg.password_file.empty()) return error("TUIC requires uuid-file and password-file");
                auth = true;
            } else if (child.name == "tls") {
                if (tls) return error("duplicate TUIC TLS");
                if (auto ok = parse_quic_tls_block(child, cfg.server_name, cfg.ca_file, cfg.key_exchange, cfg.fingerprint, cfg.ech, cfg.certificate_sha256, "TUIC"); !ok)
                    return std::unexpected(ok.error());
                tls = true;
            } else if (child.name == "congestion-control") {
                auto v = scalar(child); if (cc || !v || !parse_cc_name(*v)) return error("invalid TUIC congestion-control");
                cfg.congestion_control = *v; cc = true;
            } else if (child.name == "udp-over-stream") {
                auto v = boolean(child); if (uos || !v) return error("invalid TUIC udp-over-stream");
                cfg.udp_over_stream = *v; uos = true;
            } else if (child.name == "heartbeat-ms") {
                auto v = integer(child); if (hb || !v || !*v || *v > 3600000) return error("invalid TUIC heartbeat-ms");
                cfg.heartbeat_ms = static_cast<std::uint32_t>(*v); hb = true;
            } else if (child.name == "handshake-timeout-ms") {
                auto v = integer(child); if (hs_t || !v || !*v || *v > 3600000) return error("invalid TUIC handshake-timeout-ms");
                cfg.handshake_timeout_ms = static_cast<std::uint32_t>(*v); hs_t = true;
            } else if (child.name == "idle-timeout-ms") {
                auto v = integer(child); if (idle_t || !v || !*v || *v > 86400000) return error("invalid TUIC idle-timeout-ms");
                cfg.idle_timeout_ms = static_cast<std::uint32_t>(*v); idle_t = true;
            } else if (child.name == "native-bytes") {
                auto v = integer(child); if (mem || !v || *v < 65536 || *v > 1024ull * 1024 * 1024) return error("invalid TUIC native-bytes");
                cfg.native_bytes = static_cast<std::size_t>(*v); mem = true;
            } else if (child.name == "connect-timeout-ms") {
                auto v = connect_timeout(child); if (to || !v) return error("invalid TUIC connect-timeout-ms");
                cfg.connect_timeout_ms = *v; to = true;
            } else if (child.name == "bootstrap-resolver" || child.name=="domain-resolver" || child.name == "detour") {
                auto v = scalar(child); auto& t = child.name == "detour" ? cfg.detour : cfg.bootstrap_resolver;
                if (t || !v || !valid_name(*v)) return error("invalid TUIC outbound dependency");
                t = *v;
            } else {
                auto opt = parse_tcp_dial_option(child, cfg.tcp_options);
                if (!opt) return std::unexpected(opt.error());
                if (!*opt) return error("unsupported TUIC outbound field: " + child.name);
            }
        }
        if (!server || !auth || !tls) return error("TUIC requires server, authentication and TLS");
        if (cfg.tcp_options.tcp_configured()) return error("TCP-only dial options are not valid for TUIC");
        return cfg;
    }

    auto parse_masque_outbound(Node const& node) -> std::expected<MasqueOutbound, std::string> {
        MasqueOutbound cfg;
        bool server = false, authority = false, auth = false, tls = false, hs_t = false, idle_t = false, mem = false, to = false;
        bool protocol_seen=false, path_seen=false, mtu_seen=false, mode_seen=false;
        for (auto const& child : node.children) {
            if (child.name == "server") {
                if (server) return error("duplicate MASQUE server");
                if (auto ok = parse_endpoint_node(child, cfg.host, cfg.port, "MASQUE server"); !ok) return std::unexpected(ok.error());
                server = true;
            } else if (child.name == "authority") {
                auto v = scalar(child);
                if (authority || !v || !endpoint_name(*v) || std::ranges::any_of(*v, [](unsigned char c) {
                    return c == '/' || c == '?' || c == '#' || c == '@' || c == '\\'; }))
                    return error("invalid MASQUE authority");
                cfg.authority = *v; authority = true;
            } else if (child.name == "authentication") {
                if (auth || child.tag || !child.arguments.empty() || !child.properties.empty() ||
                    child.children.size() != 1 || child.children[0].name != "bearer-file")
                    return error("MASQUE requires one bearer-file");
                auto f = scalar(child.children[0]);
                if (!f || !absolute_path(*f)) return error("MASQUE bearer-file must be absolute");
                cfg.bearer_file = *f; auth = true;
            } else if (child.name == "tls") {
                if (tls) return error("duplicate MASQUE TLS");
                if (auto ok = parse_quic_tls_block(child, cfg.server_name, cfg.ca_file, cfg.key_exchange, cfg.fingerprint, cfg.ech, cfg.certificate_sha256, "MASQUE"); !ok)
                    return std::unexpected(ok.error());
                tls = true;
            } else if (child.name == "handshake-timeout-ms") {
                auto v = integer(child); if (hs_t || !v || !*v || *v > 3600000) return error("invalid MASQUE handshake-timeout-ms");
                cfg.handshake_timeout_ms = static_cast<std::uint32_t>(*v); hs_t = true;
            } else if (child.name == "idle-timeout-ms") {
                auto v = integer(child); if (idle_t || !v || !*v || *v > 86400000) return error("invalid MASQUE idle-timeout-ms");
                cfg.idle_timeout_ms = static_cast<std::uint32_t>(*v); idle_t = true;
            } else if (child.name == "native-bytes") {
                auto v = integer(child); if (mem || !v || *v < 65536 || *v > 1024ull * 1024 * 1024) return error("invalid MASQUE native-bytes");
                cfg.native_bytes = static_cast<std::size_t>(*v); mem = true;
            } else if (child.name == "connect-timeout-ms") {
                auto v = connect_timeout(child); if (to || !v) return error("invalid MASQUE connect-timeout-ms");
                cfg.connect_timeout_ms = *v; to = true;
            } else if (child.name == "bootstrap-resolver" || child.name=="domain-resolver" || child.name == "detour") {
                auto v = scalar(child);
                auto& setting = child.name == "detour" ? cfg.detour : cfg.bootstrap_resolver;
                if (setting || !v || !valid_name(*v)) return error("invalid MASQUE " + child.name);
                setting = *v;
            } else if (child.name == "mode") {
                auto v = scalar(child);
                if (std::exchange(mode_seen,true) || !v || (*v != "connect-udp" && *v != "connect-ip")) return error("invalid MASQUE mode");
                cfg.connect_ip = (*v == "connect-ip");
            } else if (child.name=="protocol") {
                auto value=scalar(child);
                if (std::exchange(protocol_seen,true) || !value || value->empty() || value->size()>64 ||
                    !std::ranges::all_of(*value,http::header_token)) return error("invalid MASQUE protocol");
                cfg.protocol=*value;
            } else if (child.name=="header") {
                if (child.tag || !child.properties.empty() || !child.children.empty() || child.arguments.size()!=2 ||
                    cfg.connect_headers.size()==16) return error("invalid MASQUE CONNECT header");
                auto name=child.arguments[0].tag ? nullptr : std::get_if<std::string>(&child.arguments[0].data);
                auto value=child.arguments[1].tag ? nullptr : std::get_if<std::string>(&child.arguments[1].data);
                if (!name || name->empty() || name->size()>64 || !std::ranges::all_of(*name,http::header_token) ||
                    !value || value->size()>4096 || !http::valid_header_field_value(*value))
                    return error("invalid MASQUE CONNECT header");
                auto lower=*name;
                for (auto& c:lower) if (c>='A' && c<='Z') c=static_cast<char>(c-'A'+'a');
                if (lower=="host" || lower=="capsule-protocol" || lower=="proxy-authorization" ||
                    lower=="connection" || lower=="content-length" || lower=="transfer-encoding" ||
                    std::ranges::any_of(cfg.connect_headers,[&](auto const& h){return h.first==lower;}))
                    return error("reserved or duplicate MASQUE CONNECT header");
                cfg.connect_headers.emplace_back(std::move(lower),*value);
            } else if (child.name == "path") {
                auto v = scalar(child);
                if (std::exchange(path_seen,true) || !v || v->empty() || v->size()>2048 || v->front()!='/' ||
                    std::ranges::any_of(*v,[](unsigned char c){return c<=32 || c>=127 || c=='#';})) return error("invalid MASQUE path");
                cfg.path = *v;
            } else if (child.name == "mtu") {
                auto v = integer(child);
                if (std::exchange(mtu_seen,true) || !v || *v < 68 || *v > 1500) return error("MASQUE mtu must be 68..1500");
                cfg.mtu = static_cast<std::uint16_t>(*v);
            } else if (child.name == "local-address") {
                auto v = scalar(child);
                if (!v) return error("invalid MASQUE local-address");
                auto s = std::string_view(*v);
                if (auto sl = s.find('/'); sl != std::string_view::npos) s = s.substr(0, sl);
                if (auto a4 = dns_ipv4(s)) cfg.local_v4 = *a4;
                else if (auto a6 = dns_ipv6(s)) cfg.local_v6 = *a6;
                else return error("invalid MASQUE local-address");
            } else {
                auto opt = parse_tcp_dial_option(child, cfg.tcp_options);
                if (!opt) return std::unexpected(opt.error());
                if (!*opt) return error("unsupported MASQUE outbound field: " + child.name);
            }
        }
        if (!server || !authority || !auth || !tls)
            return error("MASQUE outbound requires server, authority, authentication and TLS");
        if (!cfg.connect_ip && (protocol_seen || path_seen || mtu_seen || !cfg.connect_headers.empty() || cfg.local_v4 || cfg.local_v6))
            return error("MASQUE CONNECT-IP settings require mode connect-ip");
        if (cfg.connect_ip && cfg.mtu<1280 && (!cfg.local_v4 || cfg.local_v6))
            return error("MASQUE IPv6 or dynamically assigned addresses require MTU at least 1280");
        if (cfg.protocol!="connect-ip" && !cfg.local_v4 && !cfg.local_v6)
            return error("alternate MASQUE protocol requires a static local-address");
        if (cfg.tcp_options.tcp_configured()) return error("TCP-only dial options are not valid for MASQUE");
        return cfg;
    }

    auto validate_extra_outbounds(Config& config, std::string_view direct, std::optional<std::string> const& block,
                                  bool (*check_ref)(void const*, std::string_view), void const* ref_ctx)
        -> std::expected<void, std::string> {
        auto check_boot = [&](auto& cfg, std::string_view kind) -> std::expected<void, std::string> {
            if (!cfg.bootstrap_resolver) return {};
            if (!config.dns || !dns_hostname(cfg.host) || dns_ipv4(cfg.host))
                return error(std::string(kind) + " bootstrap-resolver requires DNS and domain host");
            cfg.bootstrap_index=config.dns->resolver_index(*cfg.bootstrap_resolver);
            if (!cfg.bootstrap_index) return error(std::string(kind) + " domain-resolver references unknown DNS server or view: "+*cfg.bootstrap_resolver);
            return {};
        };
        auto name_exists = [&](std::string_view name, auto const& self_vec, std::size_t self_idx) -> bool {
            if (name == direct || (block && name == *block)) return true;
            auto any = [&](auto const& vec) {
                for (std::size_t j = 0; j < vec.size(); ++j) {
                    if constexpr (std::same_as<decltype(vec), decltype(self_vec)>) {
                        if (&vec == &self_vec && j >= self_idx) break;
                    }
                    if (vec[j].name == name) return true;
                }
                return false;
            };
            return any(config.vless_outbounds) || any(config.shadowsocks_outbounds) ||
                   any(config.trojan_outbounds) || any(config.anytls_outbounds) ||
                   any(config.hysteria2_outbounds) || any(config.snell_outbounds) ||
                   any(config.tcp_proxy_outbounds) ||
                   any(config.shadowtls_outbounds) || any(config.tuic_outbounds) ||
                   any(config.masque_outbounds) || any(config.wireguard_outbounds) ||
                   any(config.ssh_outbounds) || any(config.naive_outbounds) ||
                   any(config.openvpn_outbounds) || any(config.openconnect_outbounds) ||
                   any(config.tailscale_outbounds);
        };
        for (std::size_t index=0;index<config.tcp_proxy_outbounds.size();++index) {
            auto& entry=config.tcp_proxy_outbounds[index];
            if (name_exists(entry.name,config.tcp_proxy_outbounds,index)) return error("outbound names must be unique");
            if (!check_ref(ref_ctx,entry.name)) return error("TCP proxy must be referenced by routing or a detour");
            if (auto checked=check_boot(entry.config,"TCP proxy");!checked) return checked;
            if (entry.config.tls)
                if (auto ok = validate_quic_ech(entry.config.tls->ech, entry.config.tls->server_name, config.dns.has_value()); !ok) return ok;
        }
        for (std::size_t i = 0; i < config.shadowtls_outbounds.size(); ++i) {
            auto const& name = config.shadowtls_outbounds[i].name;
            if (name_exists(name, config.shadowtls_outbounds, i)) return error("outbound names must be unique");
            if (!check_ref(ref_ctx, name)) return error("ShadowTLS must be referenced by routing or a detour");
            if (auto ok = check_boot(config.shadowtls_outbounds[i].config.connection, "ShadowTLS"); !ok) return ok;
        }
        for (std::size_t i = 0; i < config.tuic_outbounds.size(); ++i) {
            auto const& name = config.tuic_outbounds[i].name;
            if (name_exists(name, config.tuic_outbounds, i)) return error("outbound names must be unique");
            if (!check_ref(ref_ctx, name)) return error("TUIC must be referenced by routing or a detour");
            if (auto ok = check_boot(config.tuic_outbounds[i].config, "TUIC"); !ok) return ok;
            auto const& value = config.tuic_outbounds[i].config;
            if (auto ok = validate_quic_ech(value.ech, value.server_name, config.dns.has_value()); !ok) return ok;
        }
        for (auto const& entry : config.inbounds) {
            if (!entry.tun || !entry.tun->connect_ip_outbound) continue;
            auto found = std::ranges::find(config.masque_outbounds, *entry.tun->connect_ip_outbound, &NamedMasqueOutbound::name);
            if (found == config.masque_outbounds.end() || !found->config.connect_ip)
                return error("TUN connect-ip-outbound must name a MASQUE CONNECT-IP outbound");
            if (found->config.ech.dns) return error("CONNECT-IP TUN uses ech-config-file for ECH");
        }
        for (std::size_t i = 0; i < config.masque_outbounds.size(); ++i) {
            auto const& name = config.masque_outbounds[i].name;
            if (name_exists(name, config.masque_outbounds, i)) return error("outbound names must be unique");
            auto const& value = config.masque_outbounds[i].config;
            if (auto ok = validate_quic_ech(value.ech, value.server_name, config.dns.has_value()); !ok) return ok;
            bool tun_ref = std::ranges::any_of(config.inbounds, [&](auto const& entry) {
                return entry.tun && entry.tun->connect_ip_outbound == name;
            });
            if (!tun_ref && !check_ref(ref_ctx, name)) return error("MASQUE outbound must be referenced by routing, a detour or CONNECT-IP TUN");
            if (auto ok = check_boot(config.masque_outbounds[i].config, "MASQUE"); !ok) return ok;
        }
        for (std::size_t i = 0; i < config.tailscale_outbounds.size(); ++i) {
            auto const& name = config.tailscale_outbounds[i].name;
            if (name_exists(name, config.tailscale_outbounds, i)) return error("outbound names must be unique");
            if (!check_ref(ref_ctx, name)) return error("Tailscale must be referenced by routing or a detour");
        }
        for (std::size_t i = 0; i < config.wireguard_outbounds.size(); ++i) {
            auto const& name = config.wireguard_outbounds[i].name;
            if (name_exists(name, config.wireguard_outbounds, i)) return error("outbound names must be unique");
            if (!check_ref(ref_ctx, name)) return error("WireGuard outbound must be referenced by routing or a detour");
            if (auto ok = check_boot(config.wireguard_outbounds[i].config, "WireGuard"); !ok) return ok;
        }
        for (std::size_t i = 0; i < config.ssh_outbounds.size(); ++i) {
            auto const& name = config.ssh_outbounds[i].name;
            if (name_exists(name, config.ssh_outbounds, i)) return error("outbound names must be unique");
            if (!check_ref(ref_ctx, name)) return error("SSH outbound must be referenced by routing or a detour");
            if (auto ok = check_boot(config.ssh_outbounds[i].config, "SSH"); !ok) return ok;
        }
        if (auto ok = validate_naive_outbounds(config, direct, block, check_ref, ref_ctx); !ok) return ok;
        if (auto ok = validate_proxy_providers(config); !ok) return ok;
        return validate_vpn_outbounds(config, direct, block, check_ref, ref_ctx);
    }
}
