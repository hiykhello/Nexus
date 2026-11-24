module provider;
import std;
import :detail;

namespace provider::detail {
    namespace {
        auto convert_clash_proxy(YamlVal const& item) -> std::expected<ParsedProxy, std::string> {
            auto type_v = item.get("type");
            if (!type_v) return std::unexpected("proxy missing type");
            auto kind = lower_ascii(type_v->as_str());
            auto srv = item.get("server");
            auto port_v = item.get("port");
            auto port = port_v ? port_v->as_int() : std::nullopt;
            if (!srv || srv->as_str().empty() || !port || *port <= 0 || *port > 65535)
                return std::unexpected("proxy missing server or port");
            ParsedProxy p{};
            p.host = srv->as_str();
            p.port = static_cast<std::uint16_t>(*port);
            p.tag = sanitize_tag(item.get("name") ? item.get("name")->as_str() : std::string{}, kind + "-" + p.host);
            if (auto* v = item.get("udp")) p.udp = v->as_bool(true);
            if (auto* v = item.get("udp-over-tcp")) p.uot = v->as_bool(false);
            if (auto* v = item.get("dialer-proxy")) p.detour = sanitize_tag(v->as_str(), {});
            if (auto* v = item.get("skip-cert-verify")) p.skip_cert_verify = v->as_bool(false);
            if (auto* v = item.get("client-fingerprint")) p.fingerprint = v->as_str();
            else if (auto* v2 = item.get("fingerprint")) p.fingerprint = v2->as_str();
            if (auto* v = item.get("servername")) p.sni = v->as_str();
            else if (auto* v2 = item.get("sni")) p.sni = v2->as_str();
            if (auto* v = item.get("ca")) p.ca_file = v->as_str();
            if (auto* smux = item.get("smux"); smux && smux->kind == YamlVal::Kind::map_v) {
                if (auto* en = smux->get("enabled"); en && en->as_bool()) {
                    p.mux_enabled = true;
                    if (auto* pr = smux->get("protocol")) p.mux_protocol = pr->as_str();
                }
            }
            if (kind == "vless") {
                p.protocol = ProxyProtocol::vless;
                p.secret = item.get("uuid") ? item.get("uuid")->as_str() : std::string{};
                p.flow = item.get("flow") ? item.get("flow")->as_str() : std::string{};
                p.tls_enabled = item.get("tls") ? item.get("tls")->as_bool(true) : true;
            } else if (kind == "trojan") {
                p.protocol = ProxyProtocol::trojan;
                p.secret = item.get("password") ? item.get("password")->as_str() : std::string{};
            } else if (kind == "ss" || kind == "shadowsocks") {
                p.protocol = ProxyProtocol::shadowsocks;
                p.tls_enabled = false;
                p.method = item.get("cipher") ? item.get("cipher")->as_str() : std::string{};
                p.secret = item.get("password") ? item.get("password")->as_str() : std::string{};
                return p;
            } else if (kind == "hysteria2" || kind == "hy2") {
                p.protocol = ProxyProtocol::hysteria2;
                p.secret = item.get("password") ? item.get("password")->as_str() : std::string{};
                if (auto* v = item.get("obfs")) p.obfs = v->as_str();
                if (auto* v = item.get("obfs-password")) p.obfs_password = v->as_str();
            } else if (kind == "tuic") {
                p.protocol = ProxyProtocol::tuic;
                p.username = item.get("uuid") ? item.get("uuid")->as_str() : std::string{};
                p.secret = item.get("password") ? item.get("password")->as_str() : std::string{};
                if (auto* v = item.get("congestion-controller")) p.congestion_control = v->as_str();
                if (auto* v = item.get("udp-relay-mode")) p.udp_relay_mode = v->as_str();
            } else if (kind == "anytls") {
                p.protocol = ProxyProtocol::anytls;
                p.secret = item.get("password") ? item.get("password")->as_str() : std::string{};
            } else if (kind == "snell") {
                p.protocol = ProxyProtocol::snell;
                p.tls_enabled = false;
                p.secret = item.get("psk") ? item.get("psk")->as_str() : std::string{};
                if (auto* v = item.get("version"); v && v->as_int()) p.snell_version = static_cast<int>(*v->as_int());
                if (auto* ob = item.get("obfs-opts")) {
                    if (auto* m = ob->get("mode")) p.obfs = m->as_str();
                    if (auto* h = ob->get("host")) p.host_header = h->as_str();
                }
                return p;
            } else if (kind == "naive") {
                p.protocol = ProxyProtocol::naive;
                p.username = item.get("username") ? item.get("username")->as_str() : std::string{};
                p.secret = item.get("password") ? item.get("password")->as_str() : std::string{};
                if (auto* v = item.get("network"); v && lower_ascii(v->as_str()) == "quic") p.naive_protocol = "h3";
            } else if (kind == "ssh") {
                p.protocol = ProxyProtocol::ssh;
                p.tls_enabled = false;
                p.username = item.get("username") ? item.get("username")->as_str() :
                    (item.get("user") ? item.get("user")->as_str() : std::string{});
                p.secret = item.get("password") ? item.get("password")->as_str() : std::string{};
                if (auto* pk = item.get("private-key")) p.path = pk->as_str();
                if (auto* fp = item.get("host-key-sha256")) {
                    if (fp->kind == YamlVal::Kind::arr_v && !fp->arr.empty()) p.certificate_sha256 = fp->arr.front().as_str();
                    else p.certificate_sha256 = fp->as_str();
                }
                if (auto* ci = item.get("cipher")) p.method = ci->as_str();
                return p;
            } else if (kind == "socks5") {
                p.protocol = ProxyProtocol::socks5;
                p.tls_enabled = false;
                p.username = item.get("username") ? item.get("username")->as_str() : std::string{};
                p.secret = item.get("password") ? item.get("password")->as_str() : std::string{};
                return p;
            } else if (kind == "http") {
                p.protocol = ProxyProtocol::http_connect;
                p.tls_enabled = item.get("tls") ? item.get("tls")->as_bool(false) : false;
                p.username = item.get("username") ? item.get("username")->as_str() : std::string{};
                p.secret = item.get("password") ? item.get("password")->as_str() : std::string{};
            } else if (kind == "wireguard") {
                p.protocol = ProxyProtocol::wireguard;
                p.tls_enabled = false;
                p.wg_private_key = item.get("private-key") ? item.get("private-key")->as_str() : std::string{};
                p.wg_peer_public_key = item.get("public-key") ? item.get("public-key")->as_str() : std::string{};
                if (auto* v = item.get("pre-shared-key")) p.wg_preshared_key = v->as_str();
                else if (auto* v2 = item.get("preshared-key")) p.wg_preshared_key = v2->as_str();
                if (auto* v = item.get("ip")) p.wg_local_ipv4 = v->as_str();
                if (auto* v = item.get("ipv6")) p.wg_local_ipv6 = v->as_str();
                if (auto* v = item.get("mtu"); v && v->as_int() && *v->as_int() >= 68 && *v->as_int() <= 65535)
                    p.wg_mtu = static_cast<std::uint16_t>(*v->as_int());
                if (auto* r = item.get("reserved"); r && r->kind == YamlVal::Kind::arr_v && r->arr.size() == 3) {
                    for (std::size_t i = 0; i < 3; ++i)
                        p.wg_reserved[i] = static_cast<std::uint8_t>(r->arr[i].as_int().value_or(0));
                }
                return p;
            } else {
                return std::unexpected("unsupported Clash proxy type: " + kind);
            }
            if (p.sni.empty() && p.tls_enabled) p.sni = p.host;
            if (auto* ro = item.get("reality-opts")) {
                if (auto* pk = ro->get("public-key")) p.reality_public_key = pk->as_str();
                if (auto* sid = ro->get("short-id")) p.reality_short_id = sid->as_str();
            }
            if (auto* net = item.get("network")) {
                auto nt = lower_ascii(net->as_str());
                if (nt == "ws") p.transport = "websocket";
                else if (nt == "grpc" || nt == "httpupgrade" || nt == "xhttp") p.transport = nt;
            }
            if (auto* ws = item.get("ws-opts")) {
                if (auto* pa = ws->get("path")) p.path = pa->as_str();
                if (auto* hd = ws->get("headers")) if (auto* h = hd->get("Host")) p.host_header = h->as_str();
            }
            if (auto* gr = item.get("grpc-opts")) {
                if (auto* sn = gr->get("grpc-service-name")) p.service_name = sn->as_str();
            }
            if (auto* xh = item.get("xhttp-opts")) {
                if (auto* pa = xh->get("path")) p.path = pa->as_str();
                if (auto* h = xh->get("host")) p.host_header = h->as_str();
                if (auto* m = xh->get("mode")) p.xhttp_mode = m->as_str();
            }
            return p;
        }
    }

    auto parse_clash_yaml(std::string_view body) -> std::expected<ParsedDocument, std::string> {
        auto root = parse_yaml_dom(body);
        if (!root) return std::unexpected(root.error());
        if (root->kind != YamlVal::Kind::map_v) return std::unexpected("Clash YAML root must be a mapping");
        ParsedDocument doc{};
        doc.detected_format = ProviderFormat::clash_yaml;
        if (auto* mp = root->get("mixed-port"); mp && mp->as_int() && *mp->as_int() > 0 && *mp->as_int() <= 65535) {
            doc.inbound_port = static_cast<std::uint16_t>(*mp->as_int());
            doc.inbound_type = "mixed";
        } else if (auto* sp = root->get("socks-port"); sp && sp->as_int() && *sp->as_int() > 0 && *sp->as_int() <= 65535) {
            doc.inbound_port = static_cast<std::uint16_t>(*sp->as_int());
            doc.inbound_type = "socks5";
        } else if (auto* hp = root->get("port"); hp && hp->as_int() && *hp->as_int() > 0 && *hp->as_int() <= 65535) {
            doc.inbound_port = static_cast<std::uint16_t>(*hp->as_int());
            doc.inbound_type = "http";
        }
        if (auto* px = root->get("proxies"); px && px->kind == YamlVal::Kind::arr_v) {
            for (auto const& item : px->arr) {
                auto p = convert_clash_proxy(item);
                if (!p) doc.warnings.push_back(p.error());
                else doc.proxies.push_back(std::move(*p));
            }
        }
        if (auto* pgs = root->get("proxy-groups"); pgs && pgs->kind == YamlVal::Kind::arr_v) {
            for (auto const& item : pgs->arr) {
                auto* nv = item.get("name");
                if (!nv || nv->as_str().empty()) continue;
                ParsedGroup g{};
                g.name = sanitize_tag(nv->as_str(), "group");
                auto t = lower_ascii(item.get("type") ? item.get("type")->as_str() : std::string("select"));
                g.type = (t == "select") ? "selector" : (t == "url-test" || t == "fallback" || t == "load-balance") ? t : "selector";
                if (auto* pr = item.get("proxies"); pr && pr->kind == YamlVal::Kind::arr_v) {
                    for (auto const& m : pr->arr) {
                        auto s = m.as_str();
                        auto l = lower_ascii(s);
                        if (l == "direct") g.members.push_back("direct");
                        else if (l == "reject") g.members.push_back("block");
                        else if (!s.empty()) g.members.push_back(sanitize_tag(s, {}));
                    }
                }
                if (auto* us = item.get("use"); us && us->kind == YamlVal::Kind::arr_v) {
                    for (auto const& u : us->arr)
                        if (auto s = sanitize_tag(u.as_str(), {}); !s.empty()) g.use_providers.push_back(std::move(s));
                }
                if (auto* u = item.get("url"); u && !u->as_str().empty()) g.probe_url = u->as_str();
                if (auto* iv = item.get("interval"); iv && iv->as_int()) {
                    auto sec = *iv->as_int();
                    auto ms = sec <= 0 ? std::int64_t{500} : (sec >= 3600 ? std::int64_t{3600000} : sec * 1000);
                    g.interval_ms = static_cast<std::uint32_t>(std::clamp<std::int64_t>(ms, 500, 3600000));
                }
                if (auto* tl = item.get("tolerance"); tl && tl->as_int())
                    g.tolerance_ms = static_cast<std::uint32_t>(std::clamp<std::int64_t>(*tl->as_int(), 0, 10000));
                doc.groups.push_back(std::move(g));
            }
        }
        if (auto* rls = root->get("rules"); rls && rls->kind == YamlVal::Kind::arr_v) {
            for (auto const& r : rls->arr) {
                auto line = r.as_str();
                auto c1 = line.find(',');
                if (c1 == std::string::npos) continue;
                auto kind = lower_ascii(trim(std::string_view(line).substr(0, c1)));
                auto rest = std::string_view(line).substr(c1 + 1);
                if (kind == "match" || kind == "final") {
                    auto dl = lower_ascii(trim(rest));
                    doc.default_outbound = dl == "direct" ? "direct" : sanitize_tag(rest, "direct");
                    continue;
                }
                auto c2 = rest.find(',');
                if (c2 == std::string::npos) continue;
                auto val = std::string(trim(rest.substr(0, c2)));
                auto rem = trim(rest.substr(c2 + 1));
                if (auto c3 = rem.find(','); c3 != std::string_view::npos) rem = trim(rem.substr(0, c3));
                auto tl = lower_ascii(rem);
                auto target = tl == "direct" ? std::string("direct") : tl == "reject" ? std::string("block") : sanitize_tag(rem, "direct");
                std::string k;
                if (kind == "domain") k = "domain";
                else if (kind == "domain-suffix") k = "domain-suffix";
                else if (kind == "domain-keyword") k = "domain-keyword";
                else if (kind == "ip-cidr" || kind == "ip-cidr6") k = "ip-cidr";
                else if (kind == "src-ip-cidr") k = "source-ip-cidr";
                else if (kind == "dst-port") k = "port";
                else if (kind == "src-port") k = "source-port";
                else if (kind == "process-name") k = "process-name";
                else if (kind == "network") k = "network";
                else if (kind == "rule-set") k = "rule-set";
                if (!k.empty()) doc.rules.push_back({std::move(k), std::move(val), std::move(target), false});
            }
        }
        if (auto* dns = root->get("dns")) {
            for (auto const* k : {"nameserver", "fallback"}) {
                if (auto* arr = dns->get(k); arr && arr->kind == YamlVal::Kind::arr_v)
                    for (auto const& s : arr->arr) if (!s.as_str().empty()) doc.dns_servers.push_back(s.as_str());
            }
        }
        if (doc.proxies.empty() && doc.groups.empty() && !doc.warnings.empty())
            return std::unexpected("no supported proxies in Clash YAML (" + doc.warnings.front() + ")");
        return doc;
    }
}
