module provider;
import std;
import glaze;
import :detail;

namespace provider {
    using namespace detail;

    namespace {
        auto normalize_fingerprint(std::string_view raw) -> std::string_view {
            auto l = lower_ascii(raw);
            if (l == "chrome" || l == "chrome-133") return "chrome";
            if (l == "firefox" || l == "firefox-135") return "firefox";
            if (l == "safari" || l == "safari-18") return "safari";
            if (l == "ios" || l == "android" || l == "edge" || l == "random" ||
                l == "native" || l == "tls13-grease" || l == "tls13-randomized" || l == "tls12")
                return raw;
            return {};
        }

        auto is_ss2022_method(std::string_view m) noexcept -> bool {
            return m == "2022-blake3-aes-128-gcm" || m == "2022-blake3-aes-256-gcm" ||
                   m == "2022-blake3-chacha20-poly1305";
        }

        auto normalize_sha256_pin(std::string_view pin) -> std::optional<std::string> {
            auto s = trim(pin);
            if (s.size() == 64 && std::ranges::all_of(s, [](char c) { return hex_val(c) >= 0; }))
                return lower_ascii(s);
            if (s.size() == 95) {
                for (std::size_t i = 0; i < 32; ++i) {
                    if (hex_val(s[i * 3]) < 0 || hex_val(s[i * 3 + 1]) < 0) return std::nullopt;
                    if (i < 31 && s[i * 3 + 2] != ':') return std::nullopt;
                }
                return std::string(s);
            }
            return std::nullopt;
        }

        auto normalize_ssh_host_key(std::string_view raw) -> std::optional<std::string> {
            auto s = trim(raw);
            if (s.starts_with("SHA256:") || s.starts_with("sha256:")) {
                auto rest = std::string(s.substr(7));
                if (auto dec = base64_decode(rest); dec && dec->size() == 32)
                    return "SHA256:" + rest;
            }
            return normalize_sha256_pin(s);
        }

        auto normalize_path_leading(std::string_view p) -> std::string {
            if (p.empty()) return {};
            return p.front() == '/' ? std::string(p) : "/" + std::string(p);
        }

        auto emit_tls_block(std::ostringstream& os, ParsedProxy const& p, std::string_view fallback_ca,
                            bool allow_reality, bool allow_tls12) -> std::expected<void, std::string> {
            os << "    tls {\n";
            os << "      server-name " << kdl_escape(p.sni.empty() ? p.host : p.sni) << '\n';
            if (allow_reality && !p.reality_public_key.empty()) {
                auto pbk = normalize_reality_pbk(p.reality_public_key);
                if (!pbk) return std::unexpected("invalid Reality public-key on " + p.tag);
                os << "      reality {\n        public-key " << kdl_escape(*pbk) << '\n';
                if (!p.reality_short_id.empty()) {
                    auto sid = lower_ascii(p.reality_short_id);
                    if (sid.size() > 16 || sid.size() % 2 != 0 ||
                        !std::ranges::all_of(sid, [](char c) { return hex_val(c) >= 0; }))
                        return std::unexpected("invalid Reality short-id on " + p.tag);
                    os << "        short-id " << kdl_escape(sid) << '\n';
                }
                os << "      }\n";
            } else {
                os << "      verify #true\n";
                if (!fallback_ca.empty()) os << "      ca-file " << kdl_escape(fallback_ca) << '\n';
                if (auto pin = normalize_sha256_pin(p.certificate_sha256))
                    os << "      certificate-sha256 " << kdl_escape(*pin) << '\n';
            }
            if (!p.fingerprint.empty()) {
                auto fp = lower_ascii(p.fingerprint);
                auto norm = normalize_fingerprint(fp);
                if (!norm.empty() && (allow_tls12 || norm != "tls12"))
                    os << "      fingerprint " << kdl_escape(norm) << '\n';
            }
            os << "    }\n";
            return {};
        }

        auto emit_transport_block(std::ostringstream& os, ParsedProxy const& p, bool allow_xhttp) -> void {
            if (p.transport == "websocket" || p.transport == "httpupgrade") {
                os << "    transport " << kdl_escape(p.transport) << " {\n";
                if (!p.host_header.empty()) os << "      host " << kdl_escape(p.host_header) << '\n';
                if (!p.path.empty()) os << "      path " << kdl_escape(normalize_path_leading(p.path)) << '\n';
                os << "    }\n";
            } else if (p.transport == "grpc") {
                os << "    transport \"grpc\" {\n";
                auto sn = !p.service_name.empty() ? p.service_name : p.path;
                if (!sn.empty() && sn.front() == '/') sn.erase(sn.begin());
                if (!sn.empty()) os << "      service-name " << kdl_escape(sn) << '\n';
                if (!p.host_header.empty()) os << "      authority " << kdl_escape(p.host_header) << '\n';
                os << "    }\n";
            } else if (p.transport == "xhttp" && allow_xhttp) {
                os << "    transport \"xhttp\" {\n";
                if (!p.host_header.empty()) os << "      host " << kdl_escape(p.host_header) << '\n';
                if (!p.path.empty()) os << "      path " << kdl_escape(normalize_path_leading(p.path)) << '\n';
                if (p.xhttp_mode == "auto" || p.xhttp_mode == "stream-one" ||
                    p.xhttp_mode == "packet-up" || p.xhttp_mode == "stream-up")
                    os << "      mode " << kdl_escape(p.xhttp_mode) << '\n';
                os << "    }\n";
            }
        }

        auto emit_multiplex_block(std::ostringstream& os, ParsedProxy const& p) -> void {
            if (!p.mux_enabled) return;
            auto mp = lower_ascii(p.mux_protocol);
            std::string_view proto = (mp == "smux-v1") ? "smux-v1" : (mp == "h2mux") ? "h2mux" : "smux-v2";
            os << "    multiplex {\n      enabled #true\n      protocol " << kdl_escape(proto) << "\n    }\n";
        }

        auto parse_listen_ep(std::string_view s) -> std::pair<std::string, std::uint16_t> {
            auto hp = split_host_port(s);
            if (hp) return *hp;
            return {"127.0.0.1", 7890};
        }

        auto system_ca_exists() -> bool {
            for (std::string_view p : {"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"}) {
                std::error_code ec;
                if (std::filesystem::is_regular_file(p, ec) && !ec) return true;
            }
            return false;
        }
    }

    auto emit_outbound_kdl(ParsedProxy const& p, SecretWriter write_secret, std::string_view fallback_ca)
        -> std::expected<std::string, std::string> {
        if (p.host.empty() || p.port == 0) return std::unexpected("outbound missing server host or port: " + p.tag);
        std::ostringstream os;
        auto proto_str = protocol_kdl_name(p.protocol);
        os << "  outbound " << kdl_escape(p.tag) << " type=" << kdl_escape(proto_str) << " {\n";
        os << "    server host=" << kdl_escape(p.host) << " port=" << p.port << '\n';

        if (p.protocol == ProxyProtocol::vless) {
            if (p.secret.empty()) return std::unexpected("VLESS missing uuid: " + p.tag);
            auto uf = write_secret(p.tag + "-uuid", p.secret);
            if (!uf) return std::unexpected(uf.error());
            os << "    authentication {\n      uuid-file " << kdl_escape(*uf) << "\n    }\n";
            bool is_vision = (p.flow == "xtls-rprx-vision" && p.transport.empty());
            bool is_xhttp = (p.transport == "xhttp");
            if (is_vision) os << "    flow \"xtls-rprx-vision\"\n";
            if (p.tls_enabled || !is_xhttp || !p.reality_public_key.empty()) {
                if (auto ok = emit_tls_block(os, p, fallback_ca, p.transport.empty() || is_xhttp,
                        !is_vision && p.reality_public_key.empty() && !is_xhttp); !ok) return std::unexpected(ok.error());
            }
            emit_transport_block(os, p, !is_vision);
            if (!is_vision && !is_xhttp) emit_multiplex_block(os, p);
        } else if (p.protocol == ProxyProtocol::trojan || p.protocol == ProxyProtocol::anytls) {
            if (p.secret.empty()) return std::unexpected("missing password on " + p.tag);
            auto pf = write_secret(p.tag + "-pass", p.secret);
            if (!pf) return std::unexpected(pf.error());
            os << "    authentication {\n      password-file " << kdl_escape(*pf) << "\n    }\n";
            if (auto ok = emit_tls_block(os, p, fallback_ca, false, true); !ok) return std::unexpected(ok.error());
            emit_transport_block(os, p, false);
            if (p.protocol == ProxyProtocol::trojan) emit_multiplex_block(os, p);
        } else if (p.protocol == ProxyProtocol::shadowsocks) {
            if (!is_ss2022_method(p.method))
                return std::unexpected("skipped legacy Shadowsocks cipher '" + p.method + "' on " + p.tag + " (Nexus supports SS-2022 only)");
            auto kf = write_secret(p.tag + "-sskey", p.secret);
            if (!kf) return std::unexpected(kf.error());
            os << "    method " << kdl_escape(p.method) << '\n';
            os << "    key-file " << kdl_escape(*kf) << '\n';
            if (p.uot) os << "    udp-over-tcp \"v2\"\n";
            emit_multiplex_block(os, p);
        } else if (p.protocol == ProxyProtocol::hysteria2) {
            if (p.secret.empty()) return std::unexpected("Hysteria2 missing password: " + p.tag);
            auto pf = write_secret(p.tag + "-pass", p.secret);
            if (!pf) return std::unexpected(pf.error());
            os << "    authentication {\n      password-file " << kdl_escape(*pf) << "\n    }\n";
            if (auto ok = emit_tls_block(os, p, fallback_ca, false, false); !ok) return std::unexpected(ok.error());
            bool has_sal = lower_ascii(p.obfs) == "salamander" && !p.obfs_password.empty();
            if (has_sal || !p.hy2_ports.empty() || p.hy2_up_mbps > 0 || p.hy2_down_mbps > 0) {
                os << "    quic {\n";
                if (has_sal) {
                    auto sf = write_secret(p.tag + "-salamander", p.obfs_password);
                    if (!sf) return std::unexpected(sf.error());
                    os << "      salamander-password-file " << kdl_escape(*sf) << '\n';
                }
                if (!p.hy2_ports.empty()) {
                    os << "      ports " << kdl_escape(p.hy2_ports) << '\n';
                    if (p.hy2_hop_interval_ms >= 500 && p.hy2_hop_interval_ms <= 86400000)
                        os << "      hop-interval-ms " << p.hy2_hop_interval_ms << '\n';
                }
                if (p.hy2_up_mbps > 0)
                    os << "      send-bps " << std::min<std::uint64_t>(std::uint64_t(p.hy2_up_mbps) * 125000ull, 1000000000000ull) << '\n';
                if (p.hy2_down_mbps > 0)
                    os << "      receive-bps " << std::min<std::uint64_t>(std::uint64_t(p.hy2_down_mbps) * 125000ull, 1000000000000ull) << '\n';
                os << "    }\n";
            }
        } else if (p.protocol == ProxyProtocol::tuic) {
            if (p.username.empty() || p.secret.empty())
                return std::unexpected("TUIC requires both UUID and password: " + p.tag);
            auto uf = write_secret(p.tag + "-uuid", p.username);
            if (!uf) return std::unexpected(uf.error());
            auto pf = write_secret(p.tag + "-pass", p.secret);
            if (!pf) return std::unexpected(pf.error());
            os << "    authentication {\n      uuid-file " << kdl_escape(*uf)
               << "\n      password-file " << kdl_escape(*pf) << "\n    }\n";
            if (auto ok = emit_tls_block(os, p, fallback_ca, false, false); !ok) return std::unexpected(ok.error());
            auto cc = lower_ascii(p.congestion_control);
            if (cc == "bbr" || cc == "cubic" || cc == "reno")
                os << "    congestion-control " << kdl_escape(cc) << '\n';
            auto urm = lower_ascii(p.udp_relay_mode);
            if (urm == "quic") os << "    udp-over-stream #true\n";
            else if (urm == "native") os << "    udp-over-stream #false\n";
        } else if (p.protocol == ProxyProtocol::snell) {
            if (p.secret.empty()) return std::unexpected("Snell missing PSK: " + p.tag);
            auto kf = write_secret(p.tag + "-psk", p.secret);
            if (!kf) return std::unexpected(kf.error());
            os << "    version " << (p.snell_version == 4 ? 4 : 5) << '\n';
            os << "    psk-file " << kdl_escape(*kf) << '\n';
            if (lower_ascii(p.obfs) == "http") {
                os << "    obfs \"http\"\n";
                if (!p.host_header.empty()) os << "    obfs-host " << kdl_escape(p.host_header) << '\n';
            }
            emit_multiplex_block(os, p);
        } else if (p.protocol == ProxyProtocol::naive) {
            if (p.username.empty() || p.secret.empty())
                return std::unexpected("NaiveProxy requires username and password: " + p.tag);
            auto pf = write_secret(p.tag + "-pass", p.secret);
            if (!pf) return std::unexpected(pf.error());
            os << "    protocol " << kdl_escape(p.naive_protocol == "h3" ? "h3" : "h2") << '\n';
            os << "    authentication username=" << kdl_escape(p.username) << " password-file=" << kdl_escape(*pf) << '\n';
            if (auto ok = emit_tls_block(os, p, fallback_ca, false, false); !ok) return std::unexpected(ok.error());
            os << "    padding " << (p.padding ? "#true" : "#false") << '\n';
        } else if (p.protocol == ProxyProtocol::ssh) {
            auto fp = normalize_ssh_host_key(p.certificate_sha256);
            if (!fp) return std::unexpected("SSH requires host-key-sha256 pin (skipped " + p.tag + ")");
            if (p.username.empty() || (p.secret.empty() && p.path.empty()))
                return std::unexpected("SSH missing user or credential: " + p.tag);
            os << "    user " << kdl_escape(p.username) << '\n';
            os << "    host-key-sha256 " << kdl_escape(*fp) << '\n';
            if (!p.path.empty()) {
                if (!p.path.contains("-----BEGIN ") || !p.path.contains('\n'))
                    return std::unexpected("rejected local private-key-file path from subscription on " + p.tag);
                auto kf = write_secret(p.tag + "-sshkey", p.path);
                if (!kf) return std::unexpected(kf.error());
                os << "    private-key-file " << kdl_escape(*kf) << '\n';
            } else {
                auto pf = write_secret(p.tag + "-pass", p.secret);
                if (!pf) return std::unexpected(pf.error());
                os << "    password-file " << kdl_escape(*pf) << '\n';
            }
            if (p.method == "chacha20-poly1305@openssh.com" || p.method == "aes256-gcm@openssh.com" ||
                p.method == "aes128-gcm@openssh.com")
                os << "    cipher " << kdl_escape(p.method) << '\n';
        } else if (p.protocol == ProxyProtocol::socks5 || p.protocol == ProxyProtocol::http_connect) {
            if (!p.username.empty() && !p.secret.empty()) {
                auto pf = write_secret(p.tag + "-pass", p.secret);
                if (!pf) return std::unexpected(pf.error());
                os << "    authentication username=" << kdl_escape(p.username) << " password-file=" << kdl_escape(*pf) << '\n';
            }
            if (p.protocol == ProxyProtocol::socks5 && p.udp) os << "    udp #true\n";
            if (p.protocol == ProxyProtocol::http_connect && p.tls_enabled) {
                if (auto ok = emit_tls_block(os, p, fallback_ca, false, false); !ok) return std::unexpected(ok.error());
            }
        } else if (p.protocol == ProxyProtocol::wireguard) {
            if (p.wg_private_key.empty() || p.wg_peer_public_key.empty() ||
                (p.wg_local_ipv4.empty() && p.wg_local_ipv6.empty()))
                return std::unexpected("WireGuard requires keys and local-address: " + p.tag);
            auto privf = write_secret(p.tag + "-wgpriv", p.wg_private_key);
            if (!privf) return std::unexpected(privf.error());
            auto pubf = write_secret(p.tag + "-wgpub", p.wg_peer_public_key);
            if (!pubf) return std::unexpected(pubf.error());
            os << "    private-key-file " << kdl_escape(*privf) << '\n';
            os << "    peer-public-key-file " << kdl_escape(*pubf) << '\n';
            if (!p.wg_preshared_key.empty()) {
                auto pskf = write_secret(p.tag + "-wgpsk", p.wg_preshared_key);
                if (!pskf) return std::unexpected(pskf.error());
                os << "    preshared-key-file " << kdl_escape(*pskf) << '\n';
            }
            if (!p.wg_local_ipv4.empty()) os << "    local-address " << kdl_escape(p.wg_local_ipv4) << '\n';
            if (!p.wg_local_ipv6.empty()) os << "    local-address " << kdl_escape(p.wg_local_ipv6) << '\n';
            auto mtu = std::clamp<std::uint16_t>(p.wg_mtu ? p.wg_mtu : 1420, 68, 1500);
            os << "    mtu " << mtu << '\n';
            if (p.wg_reserved != std::array<std::uint8_t, 3>{})
                os << "    reserved " << unsigned(p.wg_reserved[0]) << ' ' << unsigned(p.wg_reserved[1]) << ' ' << unsigned(p.wg_reserved[2]) << '\n';
        }
        if (!p.detour.empty() && p.detour != p.tag) os << "    detour " << kdl_escape(p.detour) << '\n';
        os << "  }\n";
        return os.str();
    }

    auto convert_config_to_kdl(std::string_view input, ConvertOptions const& opts)
        -> std::expected<std::pair<std::string, std::vector<std::string>>, std::string> {
        auto parsed = parse_subscription(input, opts.format);
        if (!parsed) return std::unexpected(parsed.error());
        auto doc = std::move(*parsed);
        if (auto ok = apply_filter(doc.proxies, opts.filter); !ok) return std::unexpected(ok.error());
        if (doc.proxies.empty() && doc.groups.empty())
            return std::unexpected("no matching proxies after filtering");

        std::set<std::string> used_secrets;
        std::string fallback_ca = !opts.ca_file.empty() ? opts.ca_file : opts.filter.ca_file;
        std::vector<std::pair<std::string, std::string>> emitted;
        std::set<std::string> valid_tags{"direct", "block"};
        bool any_insecure = false;
        for (auto const& p : doc.proxies) {
            if (p.skip_cert_verify) any_insecure = true;
            std::set<std::string> pending_secrets;
            std::vector<StagedSecret> staged_secrets;
            SecretWriter writer = [&](std::string_view hint, std::string_view content) -> std::expected<std::string, std::string> {
                return stage_provider_secret(opts, used_secrets, pending_secrets, staged_secrets, hint, content);
            };
            auto kdl = emit_outbound_kdl(p, writer, fallback_ca);
            if (!kdl) {
                doc.warnings.push_back(kdl.error());
                continue;
            }
            if (auto committed = commit_provider_secrets(opts, used_secrets, staged_secrets); !committed) {
                doc.warnings.push_back(committed.error());
                continue;
            }
            valid_tags.insert(p.tag);
            emitted.emplace_back(p.tag, std::move(*kdl));
        }
        if (any_insecure)
            doc.warnings.push_back("upstream skip-cert-verify/insecure was upgraded to verified TLS (specify --ca-file or trust system CAs)");

        std::ostringstream out;
        out << "schema-version 1\nrole \"client\"\n";
        if (!fallback_ca.empty()) out << "certificate {\n  ca-file " << kdl_escape(fallback_ca) << "\n}\n";
        else if (system_ca_exists()) out << "certificate {\n  store \"system\"\n}\n";

        auto [in_host, in_port] = parse_listen_ep(opts.inbound_listen);
        if (doc.inbound_port && opts.inbound_listen == "127.0.0.1:7890") in_port = doc.inbound_port;
        auto in_type = opts.inbound_type.empty() ? doc.inbound_type : opts.inbound_type;
        if (in_type != "socks5" && in_type != "http") in_type = "mixed";
        out << "inbounds {\n  inbound \"local-in\" type=" << kdl_escape(in_type) << " {\n    listen host="
            << kdl_escape(in_host) << " port=" << in_port << "\n    authentication \"none\"\n  }\n}\n";

        out << "outbounds {\n  direct \"direct\"\n  block \"block\"\n";
        for (auto const& [tag, node_kdl] : emitted) out << node_kdl;

        struct ResolvedGroup {
            ParsedGroup const* group = nullptr;
            std::vector<std::string> members;
            bool alive = true;
        };
        std::vector<ResolvedGroup> group_candidates;
        std::set<std::string> declared_groups;
        for (auto const& g : doc.groups) {
            if (g.name.empty() || valid_tags.contains(g.name) || !declared_groups.insert(g.name).second) continue;
            group_candidates.push_back({&g, {}, true});
        }
        for (;;) {
            bool changed = false;
            for (auto& rg : group_candidates) {
                if (!rg.alive) continue;
                auto const& g = *rg.group;
                rg.members.clear();
                for (auto const& m : g.members) {
                    if (m == g.name) continue;
                    if ((valid_tags.contains(m) || declared_groups.contains(m)) &&
                        !std::ranges::contains(rg.members, m))
                        rg.members.push_back(m);
                }
                if (rg.members.empty() && g.use_providers.empty()) {
                    for (auto const& [t, _] : emitted) rg.members.push_back(t);
                }
                if (rg.members.empty() && g.use_providers.empty()) {
                    rg.alive = false;
                    declared_groups.erase(g.name);
                    changed = true;
                }
            }
            if (!changed) break;
        }

        std::vector<std::string> group_kdl;
        std::set<std::string> group_names, referenced_outbounds;
        for (auto const& rg : group_candidates) {
            if (!rg.alive) continue;
            auto const& g = *rg.group;
            auto const& mems = rg.members;
            for (auto const& m : mems) referenced_outbounds.insert(m);
            group_names.insert(g.name);
            valid_tags.insert(g.name);
            std::ostringstream go;
            go << "  outbound " << kdl_escape(g.name) << " type=" << kdl_escape(g.type) << " {\n";
            if (!mems.empty()) {
                go << "    members";
                for (auto const& m : mems) go << ' ' << kdl_escape(m);
                go << '\n';
            }
            for (auto const& u : g.use_providers) go << "    use " << kdl_escape(u) << '\n';
            if (g.type == "url-test" || g.type == "fallback") {
                go << "    probe-url " << kdl_escape(g.probe_url) << '\n';
                go << "    probe-interval-ms " << g.interval_ms << '\n';
                if (g.type == "url-test") go << "    tolerance-ms " << g.tolerance_ms << '\n';
            }
            go << "  }\n";
            group_kdl.push_back(go.str());
        }
        bool need_fallback_group = !emitted.empty() && (group_names.empty() || !opts.default_group.empty() ||
            std::ranges::any_of(emitted, [&](auto const& e) { return !referenced_outbounds.contains(e.first); }));
        std::string def_group = !opts.default_group.empty() ? sanitize_tag(opts.default_group, "proxy") : "proxy";
        if (need_fallback_group && !group_names.contains(def_group)) {
            std::ostringstream go;
            go << "  outbound " << kdl_escape(def_group) << " type=\"selector\" {\n    members";
            for (auto const& [t, _] : emitted) go << ' ' << kdl_escape(t);
            go << "\n  }\n";
            group_kdl.push_back(go.str());
            group_names.insert(def_group);
            valid_tags.insert(def_group);
        }
        for (auto const& gk : group_kdl) out << gk;
        out << "}\n";

        std::string def_out = valid_tags.contains(doc.default_outbound) ? doc.default_outbound :
            (group_names.contains(def_group) ? def_group : (emitted.empty() ? "direct" : emitted.front().first));
        if (def_out == "block") def_out = group_names.contains(def_group) ? def_group : "direct";
        out << "routing {\n  default " << kdl_escape(def_out) << '\n';
        bool has_rules = std::ranges::any_of(doc.rules, [&](auto const& r) {
            return r.kind != "rule-set" && valid_tags.contains(r.target);
        });
        if (has_rules) {
            out << "  rules {\n";
            for (auto const& r : doc.rules) {
                if (!valid_tags.contains(r.target)) continue;
                if (r.kind == "rule-set") {
                    doc.warnings.push_back("skipped rule-set routing rule '" + r.value + "' (no local rule-set block emitted)");
                    continue;
                }
                if ((r.kind == "port" || r.kind == "source-port") && !r.value.empty() &&
                    std::ranges::all_of(r.value, [](unsigned char c) { return std::isdigit(c); })) {
                    out << "    - " << kdl_escape(r.kind) << ' ' << r.value;
                } else {
                    auto val = r.kind == "network" ? lower_ascii(r.value) : r.value;
                    out << "    - " << kdl_escape(r.kind) << ' ' << kdl_escape(val);
                }
                if (r.invert) out << " invert=#true";
                out << " to=" << kdl_escape(r.target) << '\n';
            }
            out << "  }\n";
        }
        out << "}\n";
        return std::pair{out.str(), std::move(doc.warnings)};
    }
}
