module config;
import std;
import glaze;
import config.kdl_common;

namespace config {
    namespace g = ::glaze;
    auto dns_ipv4(std::string_view) -> std::optional<std::array<std::uint8_t, 4>>;
    auto dns_ipv6(std::string_view) -> std::optional<std::array<std::uint8_t, 16>>;
    auto dns_hostname(std::string_view) -> bool;
    auto parse_tcp_dial_option(g::KdlNode const&, TcpSocketOptions&) -> std::expected<bool, std::string>;

    namespace {
        using namespace config::kdl;

        auto parse_endpoint(Node const& child, std::string& host, std::uint16_t& port, std::string_view label)
            -> std::expected<void, std::string> {
            auto h = text_property(child, "host");
            auto p = property(child, "port");
            auto pv = p ? integer(*p) : std::nullopt;
            if (child.tag || !child.arguments.empty() || !child.children.empty() ||
                child.properties.size() != 2 || !h || !endpoint_name(*h) || !pv || !*pv || *pv > 65535)
                return error(std::string(label) + " server requires host and port 1..65535");
            host = *h;
            port = static_cast<std::uint16_t>(*pv);
            return {};
        }

        auto strip_cidr(std::string_view text) -> std::optional<std::string_view> {
            auto slash = text.find('/');
            if (slash == std::string_view::npos) return text;
            auto ps = text.substr(slash + 1);
            unsigned pfx = 0;
            auto [end, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), pfx);
            if (ec != std::errc{} || end != ps.data() + ps.size()) return std::nullopt;
            auto ip = text.substr(0, slash);
            if (pfx > (ip.find(':') != std::string_view::npos ? 128u : 32u)) return std::nullopt;
            return ip;
        }

        template<class T>
        auto parse_vpn_tls(Node const& child, T& cfg, std::string_view label) -> std::expected<void, std::string> {
            if (child.tag || !child.arguments.empty() || !child.properties.empty() || child.children.empty())
                return error(std::string("invalid ") + std::string(label) + " TLS block");
            bool verify_seen = false, kx_seen = false, fp_seen = false;
            for (auto const& field : child.children) {
                auto val = scalar(field);
                if (field.name == "server-name" && cfg.server_name.empty() && val && endpoint_name(*val)) {
                    cfg.server_name = *val;
                } else if (field.name == "ca-file" && cfg.ca_file.empty() && val && absolute_path(*val)) {
                    cfg.ca_file = *val;
                } else if (field.name == "client-cert-file" || field.name == "client-key-file") {
                    return error(std::string(label) + " outbound TLS client-cert-file/client-key-file requires client TLS mTLS handshake support (not yet supported)");
                } else if (field.name == "certificate-sha256") {
                    if (auto ok = parse_certificate_sha256(field, cfg.certificate_sha256); !ok)
                        return std::unexpected(ok.error());
                } else if (field.name == "key-exchange" && !kx_seen && val) {
                    if (*val == "x25519") cfg.key_exchange = TlsKeyExchange::x25519;
                    else if (*val == "x25519-mlkem768") cfg.key_exchange = TlsKeyExchange::x25519_mlkem768;
                    else if (*val == "x25519-mlkem768-only") cfg.key_exchange = TlsKeyExchange::x25519_mlkem768_only;
                    else return error("invalid VPN TLS key-exchange");
                    kx_seen = true;
                } else if (field.name == "fingerprint" && !fp_seen && val) {
                    auto parsed = parse_tls_fingerprint(*val);
                    if (!parsed) return error("invalid VPN TLS fingerprint");
                    cfg.fingerprint = *parsed;
                    fp_seen = true;
                } else if (field.name == "verify" && !verify_seen) {
                    auto v = boolean(field);
                    if (!v || !*v) return error(std::string(label) + " requires verified TLS");
                    verify_seen = true;
                } else {
                    return error("unsupported or duplicate VPN TLS field: " + field.name);
                }
            }
            if (cfg.server_name.empty()) return error(std::string(label) + " TLS requires server-name");
            return {};
        }

        template<class T>
        auto parse_local_ip(Node const& child, T& cfg, bool& v4_seen, bool& v6_seen) -> std::expected<void, std::string> {
            auto v = scalar(child);
            auto ip = v ? strip_cidr(*v) : std::nullopt;
            if (!ip) return error("invalid VPN local-address");
            if (auto a4 = dns_ipv4(*ip)) {
                if (std::exchange(v4_seen, true)) return error("duplicate VPN IPv4 local-address");
                cfg.local_v4 = *a4; cfg.has_v4 = true;
                return {};
            }
            if (auto a6 = dns_ipv6(*ip)) {
                if (std::exchange(v6_seen, true)) return error("duplicate VPN IPv6 local-address");
                cfg.local_v6 = *a6; cfg.has_v6 = true;
                return {};
            }
            return error("invalid VPN local-address");
        }
    }

    auto parse_openvpn_outbound(Node const& node) -> std::expected<OpenVpnOutbound, std::string> {
        OpenVpnOutbound cfg;
        bool server = false, tls_seen = false, tr_seen = false, ci_seen = false, auth_seen = false;
        bool sk_seen = false, tam_seen = false, kd_seen = false, sha1_seen = false;
        bool v4_seen = false, v6_seen = false, mtu_seen = false, ka_seen = false, to_seen = false;
        for (auto const& child : node.children) {
            if (child.name == "server") {
                if (std::exchange(server, true)) return error("duplicate OpenVPN server");
                if (auto ok = parse_endpoint(child, cfg.host, cfg.port, "OpenVPN"); !ok) return std::unexpected(ok.error());
            } else if (child.name == "transport") {
                auto v = scalar(child);
                if (std::exchange(tr_seen, true) || !v) return error("invalid OpenVPN transport");
                if (*v == "udp") cfg.transport = OpenVpnTransport::udp;
                else if (*v == "tcp") cfg.transport = OpenVpnTransport::tcp;
                else return error("OpenVPN transport must be udp or tcp");
            } else if (child.name == "cipher") {
                auto v = scalar(child);
                if (std::exchange(ci_seen, true) || !v) return error("invalid OpenVPN cipher");
                if (*v == "aes-256-gcm" || *v == "AES-256-GCM") cfg.cipher = OpenVpnCipher::aes_256_gcm;
                else if (*v == "chacha20-poly1305" || *v == "CHACHA20-POLY1305") cfg.cipher = OpenVpnCipher::chacha20_poly1305;
                else return error("unsupported OpenVPN cipher: " + *v);
            } else if (child.name == "tls") {
                if (std::exchange(tls_seen, true)) return error("duplicate OpenVPN TLS");
                if (auto ok = parse_vpn_tls(child, cfg, "OpenVPN"); !ok) return std::unexpected(ok.error());
            } else if (child.name == "authentication") {
                if (std::exchange(auth_seen, true) || child.tag || !child.arguments.empty())
                    return error("invalid OpenVPN authentication block");
                auto pu = text_property(child, "username"), pp = text_property(child, "password-file");
                if (pu && pp && child.children.empty() && child.properties.size() == 2 && !pu->empty() && absolute_path(*pp)) {
                    cfg.username = *pu; cfg.password_file = *pp;
                } else if (!child.children.empty() && child.properties.empty()) {
                    bool u_s = false, p_s = false;
                    for (auto const& f : child.children) {
                        auto sv = scalar(f);
                        if (f.name == "username" && !std::exchange(u_s, true) && sv && !sv->empty()) cfg.username = *sv;
                        else if (f.name == "password-file" && !std::exchange(p_s, true) && sv && absolute_path(*sv)) cfg.password_file = *sv;
                        else return error("invalid OpenVPN authentication field: " + f.name);
                    }
                    if (!u_s || !p_s) return error("OpenVPN authentication requires username and password-file");
                } else return error("OpenVPN authentication requires username and absolute password-file");
            } else if (child.name == "username") {
                auto v = scalar(child);
                if (!cfg.username.empty() || !v || v->empty()) return error("invalid OpenVPN username");
                cfg.username = *v;
            } else if (child.name == "password-file") {
                auto v = scalar(child);
                if (cfg.password_file || !v || !absolute_path(*v)) return error("OpenVPN password-file must be absolute");
                cfg.password_file = *v;
            } else if (child.name == "static-key-file") {
                auto v = scalar(child);
                if (std::exchange(sk_seen, true) || !v || !absolute_path(*v)) return error("OpenVPN static-key-file must be absolute");
                cfg.static_key_file = *v;
            } else if (child.name == "tls-auth-mode") {
                auto v = scalar(child);
                if (std::exchange(tam_seen, true) || !v) return error("invalid OpenVPN tls-auth-mode");
                if (*v == "tls-auth") cfg.tls_auth_mode = OpenVpnTlsAuthMode::tls_auth;
                else if (*v == "tls-crypt") cfg.tls_auth_mode = OpenVpnTlsAuthMode::tls_crypt;
                else return error("OpenVPN tls-auth-mode must be tls-auth or tls-crypt");
            } else if (child.name == "key-direction") {
                if (std::exchange(kd_seen, true) || child.tag || !child.properties.empty() || !child.children.empty() || child.arguments.size() != 1)
                    return error("invalid OpenVPN key-direction");
                if (auto v = integer(child); v && (*v == 0 || *v == 1)) {
                    cfg.key_direction = static_cast<std::int8_t>(*v);
                } else if (auto sv = scalar(child); sv && (*sv == "bidirectional" || *sv == "none")) {
                    cfg.key_direction = -1;
                } else return error("OpenVPN key-direction must be 0, 1, or bidirectional");
            } else if (child.name == "tls-auth-sha1") {
                auto v = boolean(child);
                if (std::exchange(sha1_seen, true) || !v) return error("invalid OpenVPN tls-auth-sha1");
                cfg.tls_auth_sha1 = *v;
            } else if (child.name == "local-address") {
                if (auto ok = parse_local_ip(child, cfg, v4_seen, v6_seen); !ok) return std::unexpected(ok.error());
            } else if (child.name == "mtu") {
                auto v = integer(child);
                if (std::exchange(mtu_seen, true) || !v || *v < 576 || *v > 1500) return error("OpenVPN mtu must be 576..1500");
                cfg.mtu = static_cast<std::uint16_t>(*v);
            } else if (child.name == "keepalive") {
                auto v = integer(child);
                if (std::exchange(ka_seen, true) || !v || *v > 3600) return error("OpenVPN keepalive must be 0..3600");
                cfg.keepalive_s = static_cast<std::uint16_t>(*v);
            } else if (child.name == "connect-timeout-ms") {
                auto v = connect_timeout(child);
                if (std::exchange(to_seen, true) || !v) return error("invalid OpenVPN connect-timeout-ms");
                cfg.connect_timeout_ms = *v;
            } else if (child.name == "bootstrap-resolver" || child.name == "domain-resolver") {
                auto v = scalar(child);
                if (cfg.bootstrap_resolver || !v || !valid_name(*v)) return error("invalid OpenVPN bootstrap-resolver");
                cfg.bootstrap_resolver = *v;
            } else if (child.name == "detour") {
                auto v = scalar(child);
                if (cfg.detour || !v || !valid_name(*v)) return error("invalid OpenVPN detour");
                cfg.detour = *v;
            } else {
                auto opt = parse_tcp_dial_option(child, cfg.tcp_options);
                if (!opt) return std::unexpected(opt.error());
                if (!*opt) return error("unsupported OpenVPN outbound field: " + child.name);
            }
        }
        if (!server || !tls_seen) return error("OpenVPN outbound requires server and tls");
        if (cfg.username.empty() != !cfg.password_file.has_value())
            return error("OpenVPN username and password-file must be configured together");
        if (cfg.static_key_file && !tam_seen) cfg.tls_auth_mode = OpenVpnTlsAuthMode::tls_auth;
        if (!cfg.static_key_file && (tam_seen || kd_seen || sha1_seen))
            return error("OpenVPN tls-auth options require static-key-file");
        if (cfg.tls_auth_mode == OpenVpnTlsAuthMode::tls_crypt && (kd_seen || cfg.tls_auth_sha1))
            return error("OpenVPN tls-crypt does not use key-direction or tls-auth-sha1");
        if (cfg.transport == OpenVpnTransport::udp && cfg.tcp_options.tcp_configured())
            return error("TCP-only dial options are not valid for OpenVPN UDP");
        if (!v4_seen && v6_seen) cfg.has_v4 = false;
        return cfg;
    }

    auto parse_openconnect_outbound(Node const& node) -> std::expected<OpenConnectOutbound, std::string> {
        OpenConnectOutbound cfg;
        bool server = false, tls_seen = false, auth_seen = false, ua_seen = false;
        bool dtls_seen = false, dtls_fb_seen = false;
        bool v4_seen = false, v6_seen = false, mtu_seen = false, dpd_seen = false, ka_seen = false, to_seen = false;
        for (auto const& child : node.children) {
            if (child.name == "server") {
                if (std::exchange(server, true)) return error("duplicate OpenConnect server");
                if (auto ok = parse_endpoint(child, cfg.host, cfg.port, "OpenConnect"); !ok) return std::unexpected(ok.error());
            } else if (child.name == "tls") {
                if (std::exchange(tls_seen, true)) return error("duplicate OpenConnect TLS");
                if (auto ok = parse_vpn_tls(child, cfg, "OpenConnect"); !ok) return std::unexpected(ok.error());
            } else if (child.name == "authentication") {
                if (std::exchange(auth_seen, true) || child.tag || !child.arguments.empty())
                    return error("invalid OpenConnect authentication");
                if (!child.properties.empty() && child.children.empty()) {
                    auto u = text_property(child, "username"), pf = text_property(child, "password-file");
                    auto grp = text_property(child, "group"), cf = text_property(child, "cookie-file");
                    std::size_t expected = std::size_t{bool(u)} + bool(pf) + bool(grp) + bool(cf);
                    if (child.properties.size() != expected) return error("unsupported OpenConnect authentication property");
                    if (u) cfg.username = *u;
                    if (pf) { if (!absolute_path(*pf)) return error("OpenConnect password-file must be absolute"); cfg.password_file = *pf; }
                    if (grp) cfg.group = *grp;
                    if (cf) { if (!absolute_path(*cf)) return error("OpenConnect cookie-file must be absolute"); cfg.cookie_file = *cf; }
                } else if (!child.children.empty() && child.properties.empty()) {
                    bool u_s = false, p_s = false, g_s = false, c_s = false;
                    for (auto const& f : child.children) {
                        auto sv = scalar(f);
                        if (f.name == "username" && !std::exchange(u_s, true) && sv && !sv->empty()) cfg.username = *sv;
                        else if (f.name == "password-file" && !std::exchange(p_s, true) && sv && absolute_path(*sv)) cfg.password_file = *sv;
                        else if (f.name == "group" && !std::exchange(g_s, true) && sv) cfg.group = *sv;
                        else if (f.name == "cookie-file" && !std::exchange(c_s, true) && sv && absolute_path(*sv)) cfg.cookie_file = *sv;
                        else return error("invalid OpenConnect authentication field: " + f.name);
                    }
                } else return error("invalid OpenConnect authentication syntax");
            } else if (child.name == "dtls") {
                auto v = boolean(child);
                if (std::exchange(dtls_seen, true) || !v) return error("invalid OpenConnect dtls");
                cfg.dtls = *v;
            } else if (child.name == "dtls-fallback") {
                auto v = boolean(child);
                if (std::exchange(dtls_fb_seen, true) || !v) return error("invalid OpenConnect dtls-fallback");
                cfg.dtls_fallback = *v;
            } else if (child.name == "user-agent") {
                auto v = scalar(child);
                if (std::exchange(ua_seen, true) || !v || v->empty()) return error("invalid OpenConnect user-agent");
                cfg.user_agent = *v;
            } else if (child.name == "local-address") {
                if (auto ok = parse_local_ip(child, cfg, v4_seen, v6_seen); !ok) return std::unexpected(ok.error());
            } else if (child.name == "mtu") {
                auto v = integer(child);
                if (std::exchange(mtu_seen, true) || !v || *v < 576 || *v > 9000) return error("OpenConnect mtu must be 576..9000");
                cfg.mtu = static_cast<std::uint16_t>(*v);
            } else if (child.name == "dpd") {
                auto v = integer(child);
                if (std::exchange(dpd_seen, true) || !v || *v > 3600) return error("OpenConnect dpd must be 0..3600");
                cfg.dpd_s = static_cast<std::uint16_t>(*v);
            } else if (child.name == "keepalive") {
                auto v = integer(child);
                if (std::exchange(ka_seen, true) || !v || *v > 3600) return error("OpenConnect keepalive must be 0..3600");
                cfg.keepalive_s = static_cast<std::uint16_t>(*v);
            } else if (child.name == "connect-timeout-ms") {
                auto v = connect_timeout(child);
                if (std::exchange(to_seen, true) || !v) return error("invalid OpenConnect connect-timeout-ms");
                cfg.connect_timeout_ms = *v;
            } else if (child.name == "bootstrap-resolver" || child.name == "domain-resolver") {
                auto v = scalar(child);
                if (cfg.bootstrap_resolver || !v || !valid_name(*v)) return error("invalid OpenConnect bootstrap-resolver");
                cfg.bootstrap_resolver = *v;
            } else if (child.name == "detour") {
                auto v = scalar(child);
                if (cfg.detour || !v || !valid_name(*v)) return error("invalid OpenConnect detour");
                cfg.detour = *v;
            } else {
                auto opt = parse_tcp_dial_option(child, cfg.tcp_options);
                if (!opt) return std::unexpected(opt.error());
                if (!*opt) return error("unsupported OpenConnect outbound field: " + child.name);
            }
        }
        bool has_user_pw = !cfg.username.empty() && cfg.password_file.has_value();
        bool has_cookie = cfg.cookie_file.has_value();
        if (!server || !tls_seen || !auth_seen)
            return error("OpenConnect outbound requires server, tls and authentication");
        if (!has_user_pw && !has_cookie)
            return error("OpenConnect authentication requires cookie-file or username+password-file");
        if (cfg.detour && cfg.dtls && !cfg.dtls_fallback)
            return error("OpenConnect dtls without dtls-fallback cannot be used over a TCP detour");
        if (!v4_seen && v6_seen) cfg.has_v4 = false;
        return cfg;
    }

    auto validate_vpn_outbounds(Config& config, std::string_view direct, std::optional<std::string> const& block,
                                bool (*check_ref)(void const*, std::string_view), void const* ref_ctx)
        -> std::expected<void, std::string> {
        auto name_exists = [&](std::string_view name, auto const& self_vec, std::size_t self_idx) -> bool {
            if (name == direct || (block && name == *block)) return true;
            auto any = [&](auto const& vec) {
                for (std::size_t j = 0; j < vec.size(); ++j) {
                    if constexpr (std::same_as<decltype(vec), decltype(self_vec)>)
                        if (&vec == &self_vec && j >= self_idx) break;
                    if (vec[j].name == name) return true;
                }
                return false;
            };
            return any(config.vless_outbounds) || any(config.shadowsocks_outbounds) || any(config.trojan_outbounds) ||
                   any(config.anytls_outbounds) || any(config.hysteria2_outbounds) || any(config.snell_outbounds) ||
                   any(config.shadowtls_outbounds) || any(config.tuic_outbounds) || any(config.masque_outbounds) ||
                   any(config.wireguard_outbounds) || any(config.ssh_outbounds) || any(config.naive_outbounds) ||
                   any(config.openvpn_outbounds) || any(config.openconnect_outbounds) ||
                   any(config.tailscale_outbounds) || any(config.tcp_proxy_outbounds);
        };
        auto check_list = [&](auto& list, std::string_view label) -> std::expected<void, std::string> {
            for (std::size_t i = 0; i < list.size(); ++i) {
                auto& e = list[i];
                if (name_exists(e.name, list, i)) return error("outbound names must be unique");
                if (!check_ref(ref_ctx, e.name)) return error(std::string(label) + " must be referenced by routing or a detour");
                if (e.config.bootstrap_resolver) {
                    if (!config.dns || !dns_hostname(e.config.host) || dns_ipv4(e.config.host))
                        return error(std::string(label) + " bootstrap-resolver requires DNS and domain host");
                    e.config.bootstrap_index = config.dns->resolver_index(*e.config.bootstrap_resolver);
                    if (!e.config.bootstrap_index)
                        return error(std::string(label) + " domain-resolver not found: " + *e.config.bootstrap_resolver);
                }
            }
            return {};
        };
        if (auto ok = check_list(config.openvpn_outbounds, "OpenVPN outbound"); !ok) return ok;
        return check_list(config.openconnect_outbounds, "OpenConnect outbound");
    }
}
