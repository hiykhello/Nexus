// Stage 2 & Stage 3: Secure outbound, group, and chain KDL emission for workspace compiler.
module provider.workspace_compose;
import std;
import encoding.base64;
import encoding.hex;
import glaze;
import platform.ip_address;
import :detail;

namespace provider::ws_detail {
    namespace {
        auto normalize_fp(std::string_view raw) -> std::string {
            auto l = lower_ascii(raw);
            if (l == "chrome" || l == "chrome-133") return "chrome";
            if (l == "firefox" || l == "firefox-135") return "firefox";
            if (l == "safari" || l == "safari-18") return "safari";
            if (l == "ios" || l == "android" || l == "edge" || l == "random" ||
                l == "native" || l == "tls13-grease" || l == "tls13-randomized" || l == "tls12") return l;
            return {};
        }

        auto normalize_kx(std::string_view raw) -> std::string_view {
            auto l = lower_ascii(raw);
            if (l == "x25519") return "x25519";
            if (l == "x25519-mlkem768" || l == "mlkem768") return "x25519-mlkem768";
            if (l == "x25519-mlkem768-only") return "x25519-mlkem768-only";
            return {};
        }

        auto normalize_sha256(std::string_view raw) -> std::optional<std::string> {
            auto s = trim(raw);
            if (s.starts_with("sha256:") || s.starts_with("SHA256:")) s.remove_prefix(7);
            if (s.size() == 64 && std::ranges::all_of(s, [](char c) { return encoding::hex_value(c) >= 0; }))
                return lower_ascii(s);
            if (s.size() == 95) {
                for (std::size_t i = 0; i < 32; ++i) {
                    if (encoding::hex_value(s[i * 3]) < 0 || encoding::hex_value(s[i * 3 + 1]) < 0) return std::nullopt;
                    if (i < 31 && s[i * 3 + 2] != ':') return std::nullopt;
                }
                return std::string(s);
            }
            return std::nullopt;
        }

        auto normalize_ssh_pin(std::string_view raw) -> std::optional<std::string> {
            auto s = trim(raw);
            if (s.starts_with("SHA256:") || s.starts_with("sha256:")) {
                auto rest = std::string(s.substr(7));
                if (auto dec = encoding::decode_base64_flexible(rest); dec && dec->size() == 32)
                    return "SHA256:" + rest;
            }
            return normalize_sha256(s);
        }

        auto parse_wg_reserved(std::string_view raw) -> std::optional<std::array<std::uint8_t, 3>> {
            auto s = trim(raw);
            if (s.empty()) return std::nullopt;
            if (s.contains(',')) {
                std::array<std::uint8_t, 3> out{};
                std::size_t idx = 0;
                bool done = false;
                while (!s.empty() && idx < 3) {
                    auto comma = s.find(',');
                    auto tok = trim(s.substr(0, comma));
                    unsigned v = 0;
                    auto [e, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), v);
                    if (tok.empty() || ec != std::errc{} || e != tok.data() + tok.size() || v > 255) return std::nullopt;
                    out[idx++] = static_cast<std::uint8_t>(v);
                    if (comma == std::string_view::npos) { done = true; break; }
                    s.remove_prefix(comma + 1);
                }
                if (idx == 3 && done) return out;
                return std::nullopt;
            }
            if (auto dec = encoding::decode_base64_flexible(s); dec && dec->size() == 3) {
                return std::array<std::uint8_t, 3>{
                    static_cast<std::uint8_t>((*dec)[0]),
                    static_cast<std::uint8_t>((*dec)[1]),
                    static_cast<std::uint8_t>((*dec)[2])};
            }
            return std::nullopt;
        }

        auto leading_slash(std::string_view p) -> std::string {
            if (p.empty()) return "/";
            return p.front() == '/' ? std::string(p) : "/" + std::string(p);
        }

        auto is_ss2022(std::string_view m) noexcept -> bool {
            return m == "2022-blake3-aes-128-gcm" || m == "2022-blake3-aes-256-gcm" || m == "2022-blake3-chacha20-poly1305";
        }

        auto emit_physical_socket_opts(ComposeContext const& ctx, std::ostringstream& os,
                                       std::string_view server, std::string_view detour) -> void {
            if (!detour.empty() || is_loopback_host(server)) return;
            if (ctx.host.platform == "android") {
                if (!ctx.host.android.protect_socket_path.empty())
                    os << "    protect-path " << kdl_quote(ctx.host.android.protect_socket_path) << '\n';
            } else if (ctx.host.platform.starts_with("desktop-")) {
                if (!ctx.host.desktop.bind_interface.empty())
                    os << "    bind-interface " << kdl_quote(ctx.host.desktop.bind_interface) << '\n';
                if (!ctx.host.desktop.inet4_bind_address.empty())
                    os << "    inet4-bind-address " << kdl_quote(ctx.host.desktop.inet4_bind_address) << '\n';
                if (!ctx.host.desktop.inet6_bind_address.empty())
                    os << "    inet6-bind-address " << kdl_quote(ctx.host.desktop.inet6_bind_address) << '\n';
            }
        }

        auto emit_tls(ComposeContext& ctx, std::ostringstream& os, WorkspaceNode const& n, std::string_view tag,
                      bool allow_reality, bool allow_tls12, bool allow_kx, bool allow_ech) -> std::expected<void, std::string> {
            auto const& t = n.tls;
            std::string sni = t.sni.empty() ? n.server : t.sni;
            os << "    tls {\n";
            os << "      server-name " << kdl_quote(sni) << '\n';
            if (allow_reality && !t.reality_public_key.empty()) {
                auto pbk = normalize_reality_pbk(t.reality_public_key);
                if (!pbk) return std::unexpected("invalid Reality public_key on " + std::string(tag));
                os << "      reality {\n        public-key " << kdl_quote(*pbk) << '\n';
                if (!t.reality_short_id.empty()) {
                    auto sid = lower_ascii(t.reality_short_id);
                    if (sid.size() > 16 || sid.size() % 2 != 0 ||
                        !std::ranges::all_of(sid, [](char c) { return encoding::hex_value(c) >= 0; }))
                        return std::unexpected("invalid Reality short_id on " + std::string(tag));
                    os << "        short-id " << kdl_quote(sid) << '\n';
                }
                os << "      }\n";
            } else {
                os << "      verify #true\n";
                if (!t.ca_pem.empty()) {
                    auto ca_path = ctx.write_hashed_secret("ca", t.ca_pem, ".pem");
                    if (!ca_path) return std::unexpected(ca_path.error());
                    os << "      ca-file " << kdl_quote(*ca_path) << '\n';
                } else if (!ctx.resolved_ca_file.empty()) {
                    os << "      ca-file " << kdl_quote(ctx.resolved_ca_file) << '\n';
                }
                std::vector<std::string> pins;
                for (auto const& raw_pin : t.cert_sha256) {
                    if (auto pin = normalize_sha256(raw_pin)) pins.push_back(std::move(*pin));
                    else return std::unexpected("invalid cert_sha256 pin on " + std::string(tag));
                }
                if (!pins.empty()) {
                    os << "      certificate-sha256";
                    for (auto const& pin : pins) os << ' ' << kdl_quote(pin);
                    os << '\n';
                }
            }
            if (allow_kx && !t.key_exchange.empty()) {
                if (auto kx = normalize_kx(t.key_exchange); !kx.empty())
                    os << "      key-exchange " << kdl_quote(kx) << '\n';
            }
            if (!t.fingerprint.empty()) {
                auto fp = lower_ascii(t.fingerprint);
                auto norm = normalize_fp(fp);
                if (!norm.empty() && (allow_tls12 || norm != "tls12"))
                    os << "      fingerprint " << kdl_quote(norm) << '\n';
            }
            if (allow_ech && is_valid_hostname(sni) && !platform::parse_ip_address(sni)) {
                auto em = lower_ascii(t.ech_mode);
                if (em == "dns") os << "      ech-dns #true\n";
                else if (!t.ech_config.empty() && (em.empty() || em == "config")) {
                    auto ef = ctx.write_hashed_secret("ech", t.ech_config, ".ech");
                    if (!ef) return std::unexpected(ef.error());
                    os << "      ech-config-file " << kdl_quote(*ef) << '\n';
                }
            }
            os << "    }\n";
            return {};
        }

        auto emit_transport(std::ostringstream& os, WorkspaceTransport const& tr, bool allow_xhttp) -> void {
            auto kind = lower_ascii(tr.type);
            if (kind == "ws") kind = "websocket";
            if (kind == "splithttp") kind = "xhttp";
            if (kind == "websocket" || kind == "httpupgrade") {
                os << "    transport " << kdl_quote(kind) << " {\n";
                if (!tr.host.empty()) os << "      host " << kdl_quote(tr.host) << '\n';
                if (!tr.path.empty()) os << "      path " << kdl_quote(leading_slash(tr.path)) << '\n';
                for (auto const& [k, v] : tr.headers)
                    if (!k.empty()) os << "      header " << kdl_quote(k) << ' ' << kdl_quote(v) << '\n';
                os << "    }\n";
            } else if (kind == "grpc") {
                os << "    transport \"grpc\" {\n";
                auto sn = !tr.service_name.empty() ? tr.service_name : tr.path;
                if (!sn.empty() && sn.front() == '/') sn.erase(sn.begin());
                if (!sn.empty()) os << "      service-name " << kdl_quote(sn) << '\n';
                auto auth = !tr.authority.empty() ? tr.authority : tr.host;
                if (!auth.empty()) os << "      authority " << kdl_quote(auth) << '\n';
                os << "    }\n";
            } else if (kind == "xhttp" && allow_xhttp) {
                os << "    transport \"xhttp\" {\n";
                if (!tr.host.empty()) os << "      host " << kdl_quote(tr.host) << '\n';
                if (!tr.path.empty()) os << "      path " << kdl_quote(leading_slash(tr.path)) << '\n';
                auto xm = lower_ascii(tr.xhttp_mode);
                if (xm == "auto" || xm == "stream-one" || xm == "packet-up" || xm == "stream-up")
                    os << "      mode " << kdl_quote(xm) << '\n';
                auto xp = lower_ascii(tr.xhttp_protocol);
                if (xp == "h1" || xp == "h2" || xp == "h3")
                    os << "      protocol " << kdl_quote(xp) << '\n';
                for (auto const& [k, v] : tr.headers) {
                    auto lk = lower_ascii(k);
                    if (!lk.empty() && lk != "content-type")
                        os << "      header " << kdl_quote(lk) << ' ' << kdl_quote(v) << '\n';
                }
                os << "    }\n";
            }
        }

        auto emit_multiplex(std::ostringstream& os, WorkspaceMultiplex const& mux) -> void {
            if (!mux.enabled) return;
            auto mp = lower_ascii(mux.protocol);
            std::string_view proto = (mp == "smux-v1") ? "smux-v1" : "smux-v2";
            os << "    multiplex {\n      enabled #true\n      protocol " << kdl_quote(proto) << '\n';
            if (mux.max_connections >= 1 && mux.max_connections <= 64)
                os << "      max-connections " << mux.max_connections << '\n';
            if (mux.padding) os << "      padding #true\n";
            os << "    }\n";
        }
    }

    auto node_is_xhttp_vless(WorkspaceProfile const& p) noexcept -> bool {
        if (p.kind != "node") return false;
        auto pr = lower_ascii(p.node.protocol);
        auto tr = lower_ascii(p.node.transport.type);
        return pr == "vless" && (tr == "xhttp" || tr == "splithttp");
    }

    auto node_is_datagram_capable(WorkspaceNode const& n) noexcept -> bool {
        auto pr = lower_ascii(n.protocol);
        if (pr == "ssh" || pr == "naive" || pr == "shadowtls" || pr == "http" || pr == "https" || pr == "http-connect")
            return false;
        if (pr == "shadowsocks" || pr == "ss") {
            auto pe = lower_ascii(n.packet_encoding);
            return pe == "uot" || pe == "v2" || pe == "native";
        }
        return true;
    }

    auto emit_node_outbound(ComposeContext& ctx, WorkspaceNode const& n, std::string_view tag,
                            std::string_view detour, bool note_datagram) -> std::expected<std::string, std::string> {
        auto proto = lower_ascii(n.protocol);
        if (proto == "ss") proto = "shadowsocks";
        if (proto == "hy2") proto = "hysteria2";
        if (proto == "wg") proto = "wireguard";
        if (proto == "socks") proto = "socks5";
        if (proto == "http" || proto == "https") proto = "http-connect";
        if (proto == "vmess" || proto == "ssr" || proto == "shadowsocksr" || proto == "hysteria")
            return std::unexpected("unsupported legacy protocol '" + proto + "' on " + std::string(tag));
        if (n.server.empty() || n.port == 0)
            return std::unexpected("outbound missing server or port: " + std::string(tag));
        struct RollbackGuard {
            ComposeContext& c;
            ComposeContext::Checkpoint cp;
            bool ok = false;
            ~RollbackGuard() { if (!ok) c.rollback_to(cp); }
        } guard{ctx, ctx.checkpoint()};
        if (note_datagram && !node_is_datagram_capable(n)) ctx.proxy_datagram_capable = false;
        ctx.note_protect_host(n.server);

        std::ostringstream os;
        os << "  outbound " << kdl_quote(tag) << " type=" << kdl_quote(proto) << " {\n";
        os << "    server host=" << kdl_quote(n.server) << " port=" << n.port << '\n';

        if (proto == "vless") {
            auto uuid = !n.password.empty() ? n.password : n.username;
            if (uuid.empty()) return std::unexpected("VLESS missing uuid on " + std::string(tag));
            auto uf = ctx.write_hashed_secret("vless-uuid", uuid);
            if (!uf) return std::unexpected(uf.error());
            os << "    authentication {\n      uuid-file " << kdl_quote(*uf) << "\n    }\n";
            auto tr = lower_ascii(n.transport.type);
            if (tr == "tcp" || tr == "raw" || tr == "none") tr.clear();
            bool is_xhttp = (tr == "xhttp" || tr == "splithttp");
            bool is_h3 = is_xhttp && lower_ascii(n.transport.xhttp_protocol) == "h3";
            bool is_vision = (n.flow == "xtls-rprx-vision" && tr.empty());
            if (is_vision) os << "    flow \"xtls-rprx-vision\"\n";
            auto pe = lower_ascii(n.packet_encoding);
            if (!is_vision && !is_xhttp && tr != "grpc" && (pe == "xudp" || pe == "packetaddr" || pe == "fixed"))
                os << "    packet-encoding " << kdl_quote(pe) << '\n';
            bool allow_reality = tr.empty() || (is_xhttp && !is_h3);
            if (n.tls.enabled || !is_xhttp || !n.tls.reality_public_key.empty() || is_h3) {
                if (auto ok = emit_tls(ctx, os, n, tag, allow_reality,
                        !is_vision && n.tls.reality_public_key.empty() && !is_xhttp, true, false); !ok)
                    return std::unexpected(ok.error());
            }
            emit_transport(os, n.transport, !is_vision);
            if (!is_vision && !is_xhttp) emit_multiplex(os, n.multiplex);
        } else if (proto == "trojan" || proto == "anytls") {
            if (n.password.empty()) return std::unexpected("missing password on " + std::string(tag));
            auto pf = ctx.write_hashed_secret("pass", n.password);
            if (!pf) return std::unexpected(pf.error());
            os << "    authentication {\n      password-file " << kdl_quote(*pf) << "\n    }\n";
            if (auto ok = emit_tls(ctx, os, n, tag, false, true, true, false); !ok) return std::unexpected(ok.error());
            emit_transport(os, n.transport, false);
            if (proto == "trojan") emit_multiplex(os, n.multiplex);
        } else if (proto == "shadowsocks") {
            if (!is_ss2022(n.method))
                return std::unexpected("unsupported legacy Shadowsocks cipher '" + n.method + "' on " + std::string(tag));
            if (n.password.empty()) return std::unexpected("Shadowsocks missing key on " + std::string(tag));
            auto kf = ctx.write_hashed_secret("sskey", n.password);
            if (!kf) return std::unexpected(kf.error());
            os << "    method " << kdl_quote(n.method) << '\n';
            os << "    key-file " << kdl_quote(*kf) << '\n';
            auto pe = lower_ascii(n.packet_encoding);
            if (pe == "uot" || pe == "v2") os << "    udp-over-tcp \"v2\"\n";
            else if (pe == "native") os << "    udp-mode \"native\"\n";
            emit_multiplex(os, n.multiplex);
        } else if (proto == "hysteria2") {
            if (n.password.empty()) return std::unexpected("Hysteria2 missing password on " + std::string(tag));
            auto pf = ctx.write_hashed_secret("hy2-pass", n.password);
            if (!pf) return std::unexpected(pf.error());
            os << "    authentication {\n      password-file " << kdl_quote(*pf) << "\n    }\n";
            if (auto ok = emit_tls(ctx, os, n, tag, false, false, true, true); !ok) return std::unexpected(ok.error());
            auto const& ex = n.extra;
            bool need_quic = !ex.hy2_salamander_password.empty() || !ex.hy2_ports.empty() || ex.hy2_up_mbps > 0 || ex.hy2_down_mbps > 0;
            if (need_quic) {
                os << "    quic {\n";
                if (!ex.hy2_salamander_password.empty()) {
                    auto sf = ctx.write_hashed_secret("hy2-sal", ex.hy2_salamander_password);
                    if (!sf) return std::unexpected(sf.error());
                    os << "      salamander-password-file " << kdl_quote(*sf) << '\n';
                }
                if (!ex.hy2_ports.empty()) {
                    os << "      ports " << kdl_quote(ex.hy2_ports) << '\n';
                    if (ex.hy2_hop_interval_ms >= 500 && ex.hy2_hop_interval_ms <= 86400000)
                        os << "      hop-interval-ms " << ex.hy2_hop_interval_ms << '\n';
                }
                if (ex.hy2_up_mbps > 0)
                    os << "      send-bps " << std::min<std::uint64_t>(std::uint64_t(ex.hy2_up_mbps) * 125000ull, 1000000000000ull) << '\n';
                if (ex.hy2_down_mbps > 0)
                    os << "      receive-bps " << std::min<std::uint64_t>(std::uint64_t(ex.hy2_down_mbps) * 125000ull, 1000000000000ull) << '\n';
                os << "    }\n";
            }
        } else if (proto == "tuic") {
            if (n.username.empty() || n.password.empty())
                return std::unexpected("TUIC requires uuid and password on " + std::string(tag));
            auto uf = ctx.write_hashed_secret("tuic-uuid", n.username);
            if (!uf) return std::unexpected(uf.error());
            auto pf = ctx.write_hashed_secret("tuic-pass", n.password);
            if (!pf) return std::unexpected(pf.error());
            os << "    authentication {\n      uuid-file " << kdl_quote(*uf) << "\n      password-file " << kdl_quote(*pf) << "\n    }\n";
            if (auto ok = emit_tls(ctx, os, n, tag, false, false, true, true); !ok) return std::unexpected(ok.error());
            auto cc = lower_ascii(n.extra.tuic_congestion_control);
            if (cc == "bbr" || cc == "cubic" || cc == "reno") os << "    congestion-control " << kdl_quote(cc) << '\n';
            os << "    udp-over-stream " << (n.extra.tuic_udp_over_stream ? "#true" : "#false") << '\n';
        } else if (proto == "snell") {
            if (n.password.empty()) return std::unexpected("Snell missing PSK on " + std::string(tag));
            auto kf = ctx.write_hashed_secret("snell-psk", n.password);
            if (!kf) return std::unexpected(kf.error());
            os << "    version " << (n.extra.snell_version == 4 ? 4 : 5) << '\n';
            os << "    psk-file " << kdl_quote(*kf) << '\n';
            if (lower_ascii(n.extra.snell_obfs) == "http") {
                os << "    obfs \"http\"\n";
                if (!n.extra.snell_obfs_host.empty()) os << "    obfs-host " << kdl_quote(n.extra.snell_obfs_host) << '\n';
            }
            emit_multiplex(os, n.multiplex);
        } else if (proto == "naive") {
            if (n.username.empty() || n.password.empty())
                return std::unexpected("NaiveProxy requires username and password on " + std::string(tag));
            auto pf = ctx.write_hashed_secret("naive-pass", n.password);
            if (!pf) return std::unexpected(pf.error());
            auto np = lower_ascii(n.extra.naive_protocol);
            bool h3 = (np == "h3" || np == "quic");
            os << "    protocol " << kdl_quote(h3 ? "h3" : "h2") << '\n';
            os << "    authentication username=" << kdl_quote(n.username) << " password-file=" << kdl_quote(*pf) << '\n';
            if (auto ok = emit_tls(ctx, os, n, tag, false, !h3, true, false); !ok) return std::unexpected(ok.error());
            os << "    padding #true\n";
        } else if (proto == "ssh") {
            std::vector<std::string> pins;
            for (auto const& raw : n.extra.ssh_host_key_sha256)
                if (auto p = normalize_ssh_pin(raw)) pins.push_back(std::move(*p));
            for (auto const& raw : n.tls.cert_sha256)
                if (auto p = normalize_ssh_pin(raw)) pins.push_back(std::move(*p));
            if (pins.empty() || n.username.empty() || n.password.empty())
                return std::unexpected("SSH requires user, credential and host_key_sha256 on " + std::string(tag));
            os << "    user " << kdl_quote(n.username) << '\n';
            os << "    host-key-sha256";
            for (auto const& p : pins) os << ' ' << kdl_quote(p);
            os << '\n';
            if (n.password.contains("-----BEGIN ")) {
                auto kf = ctx.write_hashed_secret("ssh-key", n.password);
                if (!kf) return std::unexpected(kf.error());
                os << "    private-key-file " << kdl_quote(*kf) << '\n';
            } else {
                auto pf = ctx.write_hashed_secret("ssh-pass", n.password);
                if (!pf) return std::unexpected(pf.error());
                os << "    password-file " << kdl_quote(*pf) << '\n';
            }
            if (n.method == "chacha20-poly1305@openssh.com" || n.method == "aes256-gcm@openssh.com" ||
                n.method == "aes128-gcm@openssh.com") os << "    cipher " << kdl_quote(n.method) << '\n';
        } else if (proto == "wireguard") {
            if (n.password.empty() || n.extra.wg_peer_public_key.empty() || n.extra.wg_local_addresses.empty())
                return std::unexpected("WireGuard requires private key, peer public key and local_addresses on " + std::string(tag));
            auto priv = ctx.write_hashed_secret("wg-priv", n.password);
            if (!priv) return std::unexpected(priv.error());
            auto pub = ctx.write_hashed_secret("wg-pub", n.extra.wg_peer_public_key);
            if (!pub) return std::unexpected(pub.error());
            os << "    private-key-file " << kdl_quote(*priv) << '\n';
            os << "    peer-public-key-file " << kdl_quote(*pub) << '\n';
            if (!n.extra.wg_preshared_key.empty()) {
                auto psk = ctx.write_hashed_secret("wg-psk", n.extra.wg_preshared_key);
                if (!psk) return std::unexpected(psk.error());
                os << "    preshared-key-file " << kdl_quote(*psk) << '\n';
            }
            for (auto const& addr : n.extra.wg_local_addresses)
                if (!addr.empty()) os << "    local-address " << kdl_quote(addr) << '\n';
            auto mtu = std::clamp<std::uint16_t>(n.extra.wg_mtu ? n.extra.wg_mtu : 1420, 68, 1500);
            os << "    mtu " << mtu << '\n';
            if (!n.extra.wg_reserved.empty()) {
                auto res = parse_wg_reserved(n.extra.wg_reserved);
                if (!res) return std::unexpected("invalid WireGuard reserved bytes on " + std::string(tag));
                os << "    reserved " << unsigned((*res)[0]) << ' ' << unsigned((*res)[1]) << ' ' << unsigned((*res)[2]) << '\n';
            }
        } else if (proto == "masque") {
            if (n.password.empty()) return std::unexpected("MASQUE requires bearer token on " + std::string(tag));
            auto bf = ctx.write_hashed_secret("masque-bearer", n.password);
            if (!bf) return std::unexpected(bf.error());
            std::string auth_host = !n.tls.sni.empty() ? n.tls.sni : n.server;
            os << "    authority " << kdl_quote(auth_host) << '\n';
            os << "    authentication {\n      bearer-file " << kdl_quote(*bf) << "\n    }\n";
            if (auto ok = emit_tls(ctx, os, n, tag, false, false, true, true); !ok) return std::unexpected(ok.error());
            auto mode = lower_ascii(n.extra.masque_mode);
            if (mode == "connect-ip") {
                os << "    mode \"connect-ip\"\n";
                if (!n.extra.masque_path.empty()) os << "    path " << kdl_quote(leading_slash(n.extra.masque_path)) << '\n';
                for (auto const& la : n.extra.masque_local_addresses)
                    if (!la.empty()) os << "    local-address " << kdl_quote(la) << '\n';
            }
        } else if (proto == "socks5" || proto == "http-connect") {
            if (!n.username.empty() && !n.password.empty()) {
                auto pf = ctx.write_hashed_secret("proxy-pass", n.password);
                if (!pf) return std::unexpected(pf.error());
                os << "    authentication username=" << kdl_quote(n.username) << " password-file=" << kdl_quote(*pf) << '\n';
            }
            if (proto == "socks5" && detour.empty()) os << "    udp #true\n";
            if (proto == "http-connect" && n.tls.enabled) {
                if (auto ok = emit_tls(ctx, os, n, tag, false, true, false, false); !ok) return std::unexpected(ok.error());
            }
        } else if (proto == "shadowtls") {
            if (n.password.empty()) return std::unexpected("ShadowTLS missing password on " + std::string(tag));
            auto pf = ctx.write_hashed_secret("stls-pass", n.password);
            if (!pf) return std::unexpected(pf.error());
            os << "    authentication {\n      password-file " << kdl_quote(*pf) << "\n    }\n";
            if (auto ok = emit_tls(ctx, os, n, tag, false, false, true, false); !ok) return std::unexpected(ok.error());
            os << "    strict-tls13 #true\n";
        } else {
            return std::unexpected("unsupported outbound protocol '" + proto + "' on " + std::string(tag));
        }

        if (!detour.empty()) os << "    detour " << kdl_quote(detour) << '\n';
        else emit_physical_socket_opts(ctx, os, n.server, detour);
        os << "  }\n";
        guard.ok = true;
        return os.str();
    }
}
