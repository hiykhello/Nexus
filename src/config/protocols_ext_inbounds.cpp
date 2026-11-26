// ShadowTLS and TUIC inbound/outbound KDL configuration parsers.
module config;
import std;
import config.kdl_common;
import platform.ip_address;
import glaze;

namespace config {
    auto dns_ipv4(std::string_view) -> std::optional<std::array<std::uint8_t, 4>>;
    auto dns_ipv6(std::string_view) -> std::optional<std::array<std::uint8_t, 16>>;
    auto dns_hostname(std::string_view) -> bool;
    auto parse_password_tls_outbound(glaze::KdlNode const&, std::string_view, std::string_view)
        -> std::expected<PasswordTlsOutbound, std::string>;

    namespace {
        using namespace config::kdl;

        auto lower_ascii(std::string_view text) -> std::string {
            std::string out;
            out.reserve(text.size());
            for (unsigned char c : text)
                out.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : static_cast<char>(c));
            return out;
        }

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

        auto parse_host_port_spec(std::string_view spec) -> std::optional<FallbackTarget> {
            if (spec.empty() || spec.size() > 260) return {};
            for (unsigned char c : spec)
                if (c < 33 || c > 126) return {};
            auto parsed = platform::split_host_port(spec, true);
            if (!parsed || !endpoint_name(parsed->host) || !parsed->port) return {};
            return FallbackTarget{std::string(parsed->host), parsed->port};
        }

        auto parse_sni_target(Node const& node, std::string_view sni_raw, std::size_t target_arg_idx,
                              std::vector<std::pair<std::string, FallbackTarget>>& out)
            -> std::expected<void, std::string> {
            if (node.tag || !node.children.empty() || out.size() >= 64)
                return error("invalid or excessive ShadowTLS handshake-for-server-name entry");
            auto sni = lower_ascii(sni_raw);
            if (!dns_hostname(sni) || dns_ipv4(sni))
                return error("ShadowTLS handshake-for-server-name requires a valid DNS hostname");
            if (std::ranges::any_of(out, [&](auto const& kv) { return kv.first == sni; }))
                return error("duplicate ShadowTLS handshake-for-server-name: " + sni);
            FallbackTarget target{};
            if (node.properties.empty() && node.arguments.size() == target_arg_idx + 1) {
                auto raw = string(node.arguments[target_arg_idx]);
                auto parsed = raw ? parse_host_port_spec(*raw) : std::nullopt;
                if (!parsed) return error("invalid ShadowTLS handshake-for-server-name endpoint");
                target = std::move(*parsed);
            } else if (node.arguments.size() == target_arg_idx && node.properties.size() == 2) {
                auto h = text_property(node, "host");
                auto pv = property(node, "port");
                auto p = pv ? integer(*pv) : std::nullopt;
                if (!h || !endpoint_name(*h) || !p || !*p || *p > 65535)
                    return error("invalid ShadowTLS handshake-for-server-name endpoint");
                target = {*h, static_cast<std::uint16_t>(*p)};
            } else {
                return error("invalid ShadowTLS handshake-for-server-name syntax");
            }
            out.emplace_back(std::move(sni), std::move(target));
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

        auto parse_alpn_node(Node const& field, std::vector<std::string>& out, std::string_view label)
            -> std::expected<void, std::string> {
            if (field.tag || !field.properties.empty() || !field.children.empty() || field.arguments.empty())
                return error("invalid " + std::string(label) + " alpn");
            for (auto const& arg : field.arguments) {
                auto tok = string(arg);
                if (!tok || tok->empty() || tok->size() > 255 ||
                    !std::ranges::all_of(*tok, [](unsigned char c) { return c >= 33 && c <= 126; }) ||
                    out.size() >= 16 || std::ranges::contains(out, *tok))
                    return error("invalid or duplicate " + std::string(label) + " alpn");
                out.push_back(*tok);
            }
            return {};
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
        bool listen = false, hs = false, tgt = false, auth = false, strict_seen = false, wildcard_seen = false;
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
            } else if (child.name == "handshake-for-server-name") {
                if (!child.children.empty()) {
                    if (child.tag || !child.arguments.empty() || !child.properties.empty())
                        return error("invalid ShadowTLS handshake-for-server-name block");
                    for (auto const& entry : child.children) {
                        if (entry.name == "server" || entry.name == "entry") {
                            auto sni = entry.arguments.empty() ? nullptr : string(entry.arguments.front());
                            if (!sni) return error("invalid ShadowTLS handshake-for-server-name entry");
                            if (auto ok = parse_sni_target(entry, *sni, 1, cfg.handshake_for_server_name); !ok) return std::unexpected(ok.error());
                        } else {
                            if (auto ok = parse_sni_target(entry, entry.name, 0, cfg.handshake_for_server_name); !ok) return std::unexpected(ok.error());
                        }
                    }
                } else {
                    auto sni = child.arguments.empty() ? nullptr : string(child.arguments.front());
                    if (!sni) return error("invalid ShadowTLS handshake-for-server-name entry");
                    if (auto ok = parse_sni_target(child, *sni, 1, cfg.handshake_for_server_name); !ok) return std::unexpected(ok.error());
                }
            } else if (child.name == "wildcard-sni") {
                auto v = scalar(child);
                if (wildcard_seen || !v || (*v != "off" && *v != "authed" && *v != "all"))
                    return error("ShadowTLS wildcard-sni must be off, authed or all");
                cfg.wildcard_sni = *v; wildcard_seen = true;
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
        bool listen = false, auth = false, tls = false, cc = false, udp = false, hs_t = false, idle_t = false, mem = false, zrt = false;
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
                bool reload_seen = false;
                for (auto const& f : child.children) {
                    if (f.name == "alpn") {
                        if (auto ok = parse_alpn_node(f, cfg.alpn, "TUIC TLS"); !ok) return std::unexpected(ok.error());
                    } else if (f.name == "cert-hot-reload") {
                        auto v = boolean(f);
                        if (reload_seen || !v) return error("invalid TUIC TLS cert-hot-reload");
                        cfg.cert_hot_reload = *v; reload_seen = true;
                    } else if (f.name == "certificate-provider") {
                        auto v = scalar(f);
                        if (!cfg.certificate_provider.empty() || !v || !valid_name(*v))
                            return error("invalid or duplicate TUIC TLS certificate-provider");
                        cfg.certificate_provider = *v;
                    } else {
                        auto v = scalar(f);
                        if (!v || !absolute_path(*v)) return error("TUIC TLS requires absolute paths");
                        if (f.name == "certificate-file" && cfg.certificate_file.empty()) cfg.certificate_file = *v;
                        else if (f.name == "private-key-file" && cfg.private_key_file.empty()) cfg.private_key_file = *v;
                        else if (f.name == "ech-key-file" && cfg.ech_key_file.empty()) cfg.ech_key_file = *v;
                        else return error("unsupported or duplicate TUIC TLS field");
                    }
                }
                bool const has_files = !cfg.certificate_file.empty() || !cfg.private_key_file.empty();
                bool const has_prov = !cfg.certificate_provider.empty();
                if ((has_files && has_prov) || (!has_prov && (cfg.certificate_file.empty() || cfg.private_key_file.empty())))
                    return error("TUIC TLS requires cert and key or certificate-provider");
                if (has_prov && cfg.cert_hot_reload)
                    return error("TUIC TLS cert-hot-reload cannot be combined with certificate-provider");
                tls = true;
            } else if (child.name == "congestion-control") {
                auto v = scalar(child);
                if (cc || !v || !parse_cc_name(*v)) return error("invalid TUIC congestion-control");
                cfg.congestion_control = *v; cc = true;
            } else if (child.name == "udp") {
                auto v = boolean(child); if (udp || !v) return error("invalid TUIC udp flag");
                cfg.udp = *v; udp = true;
            } else if (child.name == "zero-rtt-handshake") {
                auto v = boolean(child); if (zrt || !v) return error("invalid TUIC zero-rtt-handshake");
                cfg.zero_rtt_handshake = *v; zrt = true;
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
}
