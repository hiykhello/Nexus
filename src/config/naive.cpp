module config;
import std;
import http.header;
import config.kdl_common;
import platform.ip_address;
import glaze;

namespace config {
    auto dns_ipv4(std::string_view) -> std::optional<std::array<std::uint8_t, 4>>;
    auto dns_hostname(std::string_view) -> bool;
    auto parse_tcp_dial_option(glaze::KdlNode const&, TcpSocketOptions&) -> std::expected<bool, std::string>;
    auto parse_quic_ech_field(glaze::KdlNode const&, QuicEchOptions&) -> bool;
    auto parse_outbound_tls_fragment(glaze::KdlNode const&, OutboundTlsFragment&) -> std::expected<void, std::string>;
    auto parse_alpn_list(glaze::KdlNode const&, std::vector<std::string>&) -> std::expected<void, std::string>;
    auto validate_quic_ech(QuicEchOptions const&, std::string_view, bool) -> std::expected<void, std::string>;

    namespace {
        using namespace config::kdl;

        auto lower_ascii(std::string_view s) -> std::string {
            std::string out(s);
            for (char& c : out)
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            return out;
        }

        auto valid_naive_user(std::string_view v) noexcept -> bool {
            return !v.empty() && v.size() <= 255 && !v.contains(':') &&
                   std::ranges::all_of(v, [](unsigned char c) { return c >= 32 && c <= 126; });
        }

        auto parse_naive_tls_block(Node const& child, NaiveOutbound& cfg) -> std::expected<void, std::string> {
            if (child.tag || !child.arguments.empty() || !child.properties.empty() || child.children.empty())
                return error("invalid NaiveProxy TLS block");
            bool verify = false, kx_seen = false, fp_seen = false, frag_seen = false;
            for (auto const& field : child.children) {
                auto val = scalar(field);
                if (field.name == "server-name" && cfg.server_name.empty() && val && endpoint_name(*val))
                    cfg.server_name = *val;
                else if (field.name == "ca-file" && cfg.ca_file.empty() && val && absolute_path(*val))
                    cfg.ca_file = *val;
                else if (field.name == "certificate-sha256") {
                    if (auto ok = parse_certificate_sha256(field, cfg.certificate_sha256); !ok)
                        return std::unexpected(ok.error());
                } else if (field.name == "key-exchange" && !kx_seen && val) {
                    if (*val == "x25519") cfg.key_exchange = TlsKeyExchange::x25519;
                    else if (*val == "x25519-mlkem768") cfg.key_exchange = TlsKeyExchange::x25519_mlkem768;
                    else if (*val == "x25519-mlkem768-only") cfg.key_exchange = TlsKeyExchange::x25519_mlkem768_only;
                    else return error("invalid NaiveProxy TLS key-exchange");
                    kx_seen = true;
                } else if (field.name == "fingerprint" && !fp_seen && val) {
                    auto parsed = parse_tls_fingerprint(*val);
                    if (!parsed) return error("invalid NaiveProxy TLS fingerprint");
                    cfg.fingerprint = *parsed;
                    fp_seen = true;
                } else if (field.name == "tls-fragment") {
                    if (std::exchange(frag_seen, true)) return error("duplicate NaiveProxy TLS tls-fragment");
                    if (auto ok = parse_outbound_tls_fragment(field, cfg.tls_fragment); !ok) return ok;
                } else if (field.name == "alpn") {
                    if (auto ok = parse_alpn_list(field, cfg.alpn); !ok) return ok;
                } else if (field.name == "verify" && !verify && boolean(field) == true) {
                    verify = true;
                } else if (!parse_quic_ech_field(field, cfg.ech)) {
                    return error("unsupported or duplicate NaiveProxy TLS field");
                }
            }
            if (!verify || cfg.server_name.empty())
                return error("NaiveProxy requires authenticated TLS with server-name and verify #true");
            if ((cfg.ech.dns || !cfg.ech.config_file.empty()) && cfg.fingerprint == TlsFingerprint::tls12)
                return error("NaiveProxy ECH requires TLS 1.3");
            return {};
        }

        auto forbidden_naive_header(std::string_view lower_name) noexcept -> bool {
            return lower_name.starts_with(':') || lower_name == "host" ||
                   lower_name == "connection" || lower_name == "proxy-connection" ||
                   lower_name == "keep-alive" || lower_name == "transfer-encoding" ||
                   lower_name == "upgrade" || lower_name == "te" ||
                   lower_name == "proxy-authorization" || lower_name == "padding" ||
                   lower_name == "padding-type-request" || lower_name == "content-length";
        }
    }

    auto parse_naive_outbound(Node const& node) -> std::expected<NaiveOutbound, std::string> {
        NaiveOutbound cfg;
        bool proto_seen = false, server_seen = false, auth_seen = false, tls_seen = false;
        bool pad_seen = false, max_seen = false, ct_seen = false, hs_seen = false, idle_seen = false, mem_seen = false;
        for (auto const& child : node.children) {
            if (child.name == "protocol") {
                auto v = scalar(child);
                if (std::exchange(proto_seen, true) || !v) return error("duplicate or invalid NaiveProxy protocol");
                if (*v == "https" || *v == "h2") cfg.protocol = NaiveProtocol::h2;
                else if (*v == "quic" || *v == "h3") cfg.protocol = NaiveProtocol::h3;
                else return error("NaiveProxy outbound protocol must be https/h2 or quic/h3");
            } else if (child.name == "server") {
                auto h = text_property(child, "host");
                auto pval = property(child, "port");
                auto p = pval ? integer(*pval) : std::nullopt;
                if (std::exchange(server_seen, true) || child.tag || !child.arguments.empty() ||
                    !child.children.empty() || child.properties.size() != 2 ||
                    !h || !endpoint_name(*h) || !p || !*p || *p > 65535)
                    return error("invalid NaiveProxy server");
                cfg.host = *h;
                cfg.port = static_cast<std::uint16_t>(*p);
            } else if (child.name == "authentication") {
                auto u = text_property(child, "username");
                auto pf = text_property(child, "password-file");
                if (std::exchange(auth_seen, true) || child.tag || !child.arguments.empty() ||
                    !child.children.empty() || child.properties.size() != 2 ||
                    !u || !valid_naive_user(*u) || !pf || !absolute_path(*pf))
                    return error("NaiveProxy authentication requires username and absolute password-file");
                cfg.username = *u;
                cfg.password_file = *pf;
            } else if (child.name == "tls") {
                if (std::exchange(tls_seen, true)) return error("duplicate NaiveProxy TLS");
                if (auto ok = parse_naive_tls_block(child, cfg); !ok) return std::unexpected(ok.error());
            } else if (child.name == "padding") {
                auto v = boolean(child);
                if (std::exchange(pad_seen, true) || !v) return error("invalid NaiveProxy padding flag");
                cfg.padding = *v;
            } else if (child.name == "extra-header") {
                if (child.tag || !child.properties.empty() || !child.children.empty() ||
                    child.arguments.size() != 2 || cfg.extra_headers.size() >= 16)
                    return error("invalid NaiveProxy extra-header");
                auto name = child.arguments[0].tag ? nullptr : std::get_if<std::string>(&child.arguments[0].data);
                auto val = child.arguments[1].tag ? nullptr : std::get_if<std::string>(&child.arguments[1].data);
                if (!name || name->empty() || name->size() > 64 || !std::ranges::all_of(*name, http::header_token) ||
                    !val || val->size() > 4096 || !http::valid_header_field_value(*val))
                    return error("invalid NaiveProxy extra-header field");
                auto lowered = lower_ascii(*name);
                if (forbidden_naive_header(lowered) ||
                    std::ranges::any_of(cfg.extra_headers, [&](auto const& h) { return h.first == lowered; }))
                    return error("forbidden or duplicate NaiveProxy extra-header");
                cfg.extra_headers.emplace_back(std::move(lowered), *val);
            } else if (child.name == "max-sessions") {
                auto v = integer(child);
                if (std::exchange(max_seen, true) || !v || *v < 1 || *v > 64)
                    return error("NaiveProxy max-sessions must be 1..64");
                cfg.max_sessions = static_cast<std::size_t>(*v);
            } else if (child.name == "connect-timeout-ms") {
                auto v = connect_timeout(child);
                if (std::exchange(ct_seen, true) || !v) return error("invalid NaiveProxy connect-timeout-ms");
                cfg.connect_timeout_ms = *v;
            } else if (child.name == "handshake-timeout-ms") {
                auto v = integer(child);
                if (std::exchange(hs_seen, true) || !v || !*v || *v > 3600000)
                    return error("invalid NaiveProxy handshake-timeout-ms");
                cfg.handshake_timeout_ms = static_cast<std::uint32_t>(*v);
            } else if (child.name == "idle-timeout-ms") {
                auto v = integer(child);
                if (std::exchange(idle_seen, true) || !v || !*v || *v > 86400000)
                    return error("invalid NaiveProxy idle-timeout-ms");
                cfg.idle_timeout_ms = static_cast<std::uint32_t>(*v);
            } else if (child.name == "native-bytes") {
                auto v = integer(child);
                if (std::exchange(mem_seen, true) || !v || *v < 65536 || *v > 1024ull * 1024 * 1024)
                    return error("invalid NaiveProxy native-bytes");
                cfg.native_bytes = static_cast<std::size_t>(*v);
            } else if (child.name == "bootstrap-resolver" || child.name == "domain-resolver" || child.name == "detour") {
                auto v = scalar(child);
                auto& dst = child.name == "detour" ? cfg.detour : cfg.bootstrap_resolver;
                if (dst || !v || !valid_name(*v)) return error("invalid NaiveProxy dependency");
                dst = *v;
            } else if (child.name == "tcp-fast-open") {
                auto v = boolean(child);
                if (cfg.tcp_fast_open || !v) return error("invalid NaiveProxy tcp-fast-open");
                cfg.tcp_fast_open = *v;
            } else {
                auto opt = parse_tcp_dial_option(child, cfg.tcp_options);
                if (!opt) return std::unexpected(opt.error());
                if (!*opt) return error("unsupported NaiveProxy outbound field: " + child.name);
            }
        }
        if (!server_seen || !auth_seen || !tls_seen)
            return error("NaiveProxy outbound requires server, authentication and tls");
        if (cfg.protocol == NaiveProtocol::h3) {
            if (cfg.fingerprint == TlsFingerprint::tls12)
                return error("NaiveProxy H3/QUIC cannot use tls12 fingerprint");
            if (cfg.tls_fragment.enabled || cfg.tls_fragment.record_fragment)
                return error("NaiveProxy H3/QUIC cannot use TCP TLS fragmentation");
            if (cfg.tcp_fast_open.value_or(false) || cfg.tcp_options.tcp_configured())
                return error("TCP-only dial options are not valid for NaiveProxy H3/QUIC");
        }
        return cfg;
    }

    auto parse_naive_inbound(Node const& node) -> std::expected<InboundConfig, std::string> {
        auto tag = argument(node);
        auto type = text_property(node, "type");
        if (!tag || !valid_name(*tag) || node.properties.size() != 1 || !type || *type != "naive")
            return error("invalid NaiveProxy inbound");
        InboundConfig result{*tag, 0, Inbound::naive};
        NaiveInbound cfg;
        bool listen_seen = false, tls_seen = false, auth_seen = false, proto_seen = false;
        bool pad_seen = false, fb_seen = false, hs_seen = false, idle_seen = false, mem_seen = false;
        for (auto const& child : node.children) {
            if (child.name == "listen") {
                auto host = text_property(child, "host");
                auto pval = property(child, "port");
                auto p = pval ? integer(*pval) : std::nullopt;
                auto ip = host ? platform::parse_ip_address(*host) : std::nullopt;
                if (std::exchange(listen_seen, true) || child.tag || !child.arguments.empty() ||
                    !child.children.empty() || child.properties.size() != 2 || !ip || !p || !*p || *p > 65535)
                    return error("invalid NaiveProxy listen");
                result.port = static_cast<std::uint16_t>(*p);
                result.listen_ipv6 = ip->size == 16;
                cfg.listen_address = ip->bytes;
                cfg.listen_host = *host;
            } else if (child.name == "protocol") {
                auto v = scalar(child);
                if (std::exchange(proto_seen, true) || !v) return error("invalid NaiveProxy inbound protocol");
                if (*v == "h2" || *v == "https") cfg.protocol = NaiveProtocol::h2;
                else if (*v == "h3" || *v == "quic") cfg.protocol = NaiveProtocol::h3;
                else if (*v == "both") cfg.protocol = NaiveProtocol::both;
                else return error("NaiveProxy inbound protocol must be h2/https, h3/quic or both");
            } else if (child.name == "tls") {
                if (std::exchange(tls_seen, true) || child.tag || !child.arguments.empty() || !child.properties.empty())
                    return error("invalid NaiveProxy TLS");
                for (auto const& f : child.children) {
                    auto v = scalar(f);
                    if (!v || !absolute_path(*v)) return error("NaiveProxy TLS requires absolute file paths");
                    if (f.name == "certificate-file" && cfg.certificate_file.empty()) cfg.certificate_file = *v;
                    else if (f.name == "private-key-file" && cfg.private_key_file.empty()) cfg.private_key_file = *v;
                    else return error("unsupported or duplicate NaiveProxy TLS field");
                }
                if (cfg.certificate_file.empty() || cfg.private_key_file.empty())
                    return error("NaiveProxy TLS requires certificate-file and private-key-file");
            } else if (child.name == "authentication") {
                if (std::exchange(auth_seen, true) || child.tag || !child.arguments.empty() || !child.properties.empty())
                    return error("invalid NaiveProxy authentication");
                for (auto const& u : child.children) {
                    auto uname = argument(u);
                    auto login = text_property(u, "username");
                    auto pfile = text_property(u, "password-file");
                    std::string effective = login ? *login : (uname ? *uname : std::string{});
                    std::size_t expected_props = 1 + static_cast<std::size_t>(login != nullptr);
                    if (u.name != "user" || !uname || !valid_name(*uname) || !valid_naive_user(effective) ||
                        !pfile || !absolute_path(*pfile) || u.properties.size() != expected_props ||
                        !u.children.empty() || cfg.users.size() >= 64 ||
                        std::ranges::any_of(cfg.users, [&](auto const& x) {
                            return x.name == *uname || x.username == effective;
                        }))
                        return error("invalid or duplicate NaiveProxy user");
                    cfg.users.push_back({*uname, std::move(effective), *pfile});
                }
                if (cfg.users.empty()) return error("NaiveProxy inbound requires at least one user");
            } else if (child.name == "padding") {
                auto v = boolean(child);
                if (std::exchange(pad_seen, true) || !v) return error("invalid NaiveProxy padding");
                cfg.padding = *v;
            } else if (child.name == "fallback-status") {
                auto v = integer(child);
                if (std::exchange(fb_seen, true) || !v || (*v != 200 && *v != 404))
                    return error("NaiveProxy fallback-status must be 200 or 404");
                cfg.fallback_status = static_cast<std::uint16_t>(*v);
            } else if (child.name == "handshake-timeout-ms") {
                auto v = integer(child);
                if (std::exchange(hs_seen, true) || !v || !*v || *v > 3600000)
                    return error("invalid NaiveProxy handshake-timeout-ms");
                cfg.handshake_timeout_ms = static_cast<std::uint32_t>(*v);
            } else if (child.name == "idle-timeout-ms") {
                auto v = integer(child);
                if (std::exchange(idle_seen, true) || !v || !*v || *v > 86400000)
                    return error("invalid NaiveProxy idle-timeout-ms");
                cfg.idle_timeout_ms = static_cast<std::uint32_t>(*v);
            } else if (child.name == "native-bytes") {
                auto v = integer(child);
                if (std::exchange(mem_seen, true) || !v || *v < 65536 || *v > 1024ull * 1024 * 1024)
                    return error("invalid NaiveProxy native-bytes");
                cfg.native_bytes = static_cast<std::size_t>(*v);
            } else {
                return error("unsupported NaiveProxy inbound field: " + child.name);
            }
        }
        if (!listen_seen || !tls_seen || !auth_seen)
            return error("NaiveProxy inbound requires listen, tls and authentication");
        result.naive = std::move(cfg);
        return result;
    }

    auto validate_naive_outbounds(Config& config, std::string_view direct, std::optional<std::string> const& block,
                                  bool (*check_ref)(void const*, std::string_view), void const* ref_ctx)
        -> std::expected<void, std::string> {
        auto name_exists = [&](std::string_view name, std::size_t self_idx) -> bool {
            if (name == direct || (block && name == *block)) return true;
            auto any = [&](auto const& vec) {
                return std::ranges::any_of(vec, [&](auto const& item) { return item.name == name; });
            };
            for (std::size_t j = 0; j < self_idx; ++j)
                if (config.naive_outbounds[j].name == name) return true;
            return any(config.vless_outbounds) || any(config.shadowsocks_outbounds) ||
                   any(config.trojan_outbounds) || any(config.anytls_outbounds) ||
                   any(config.hysteria2_outbounds) || any(config.snell_outbounds) ||
                   any(config.shadowtls_outbounds) || any(config.tuic_outbounds) ||
                   any(config.masque_outbounds) || any(config.wireguard_outbounds) ||
                   any(config.ssh_outbounds) || any(config.openvpn_outbounds) ||
                   any(config.openconnect_outbounds) || any(config.tailscale_outbounds) ||
                   any(config.tcp_proxy_outbounds);
        };
        for (std::size_t i = 0; i < config.naive_outbounds.size(); ++i) {
            auto& entry = config.naive_outbounds[i];
            if (name_exists(entry.name, i)) return error("outbound names must be unique");
            if (!check_ref(ref_ctx, entry.name)) return error("NaiveProxy must be referenced by routing or a detour");
            if (entry.config.bootstrap_resolver) {
                if (!config.dns || !dns_hostname(entry.config.host) || dns_ipv4(entry.config.host))
                    return error("NaiveProxy bootstrap-resolver requires DNS and domain host");
                entry.config.bootstrap_index = config.dns->resolver_index(*entry.config.bootstrap_resolver);
                if (!entry.config.bootstrap_index)
                    return error("NaiveProxy domain-resolver references unknown DNS server or view: " +
                                 *entry.config.bootstrap_resolver);
            }
            if (auto ok = validate_quic_ech(entry.config.ech, entry.config.server_name, config.dns.has_value()); !ok)
                return ok;
        }
        return {};
    }
}
