module provider;
import std;
import :detail;

namespace provider::detail {
    namespace {
        struct JsonVal {
            enum class Kind { null_v, bool_v, int_v, dbl_v, str_v, arr_v, obj_v } kind = Kind::null_v;
            bool bval = false;
            std::int64_t ival = 0;
            std::string sval;
            std::vector<JsonVal> arr;
            std::vector<std::pair<std::string, JsonVal>> obj;

            auto get(std::string_view key) const noexcept -> JsonVal const* {
                if (kind != Kind::obj_v) return nullptr;
                for (auto const& [k, v] : obj) if (k == key) return &v;
                return nullptr;
            }
            auto as_str() const -> std::string {
                if (kind == Kind::str_v) return sval;
                if (kind == Kind::int_v) return std::to_string(ival);
                if (kind == Kind::bool_v) return bval ? "true" : "false";
                return {};
            }
            auto as_int() const -> std::optional<std::int64_t> {
                if (kind == Kind::int_v) return ival;
                if (kind == Kind::str_v && !sval.empty()) {
                    std::int64_t v = 0;
                    auto [e, ec] = std::from_chars(sval.data(), sval.data() + sval.size(), v);
                    if (ec == std::errc{} && e == sval.data() + sval.size()) return v;
                }
                return std::nullopt;
            }
            auto as_bool(bool def = false) const noexcept -> bool {
                if (kind == Kind::bool_v) return bval;
                if (kind == Kind::int_v) return ival != 0;
                return def;
            }
        };

        struct JsonDomParser {
            std::string_view src;
            std::size_t pos = 0;

            auto skip_ws() noexcept -> void {
                while (pos < src.size() && (src[pos] == ' ' || src[pos] == '\t' || src[pos] == '\n' || src[pos] == '\r'))
                    ++pos;
            }
            auto take(char ch) noexcept -> bool {
                skip_ws();
                if (pos >= src.size() || src[pos] != ch) return false;
                ++pos;
                return true;
            }

            auto read_string() -> std::expected<std::string, std::string> {
                if (!take('"')) return std::unexpected("expected JSON string");
                std::string out;
                while (pos < src.size()) {
                    char c = src[pos++];
                    if (c == '"') return out;
                    if (static_cast<unsigned char>(c) < 0x20) return std::unexpected("unescaped JSON control character");
                    if (c != '\\') { out.push_back(c); continue; }
                    if (pos >= src.size()) return std::unexpected("truncated JSON escape");
                    char e = src[pos++];
                    switch (e) {
                    case '"': case '\\': case '/': out.push_back(e); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        if (pos + 4 > src.size()) return std::unexpected("truncated JSON unicode escape");
                        unsigned cp = 0;
                        auto [end, ec] = std::from_chars(src.data() + pos, src.data() + pos + 4, cp, 16);
                        if (ec != std::errc{} || end != src.data() + pos + 4) return std::unexpected("invalid JSON unicode escape");
                        pos += 4;
                        if (cp >= 0xd800 && cp <= 0xdbff && pos + 6 <= src.size() &&
                            src[pos] == '\\' && src[pos + 1] == 'u') {
                            unsigned lo = 0;
                            auto [e2, ec2] = std::from_chars(src.data() + pos + 2, src.data() + pos + 6, lo, 16);
                            if (ec2 == std::errc{} && e2 == src.data() + pos + 6 && lo >= 0xdc00 && lo <= 0xdfff) {
                                cp = 0x10000u + (((cp - 0xd800u) << 10) | (lo - 0xdc00u));
                                pos += 6;
                            }
                        }
                        if (cp < 0x80) out.push_back(static_cast<char>(cp));
                        else if (cp < 0x800) {
                            out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
                        } else if (cp < 0x10000) {
                            out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
                            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
                        } else {
                            out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
                            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
                            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
                            out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
                        }
                        break;
                    }
                    default: return std::unexpected("invalid JSON escape");
                    }
                }
                return std::unexpected("unterminated JSON string");
            }

            auto parse(unsigned depth = 0) -> std::expected<JsonVal, std::string> {
                if (depth > 32) return std::unexpected("JSON nesting exceeds depth 32");
                skip_ws();
                if (pos >= src.size()) return std::unexpected("unexpected end of JSON");
                char c = src[pos];
                if (c == '"') {
                    auto s = read_string();
                    if (!s) return std::unexpected(s.error());
                    return JsonVal{JsonVal::Kind::str_v, false, 0, std::move(*s)};
                }
                if (c == 't' && src.substr(pos).starts_with("true")) { pos += 4; return JsonVal{JsonVal::Kind::bool_v, true}; }
                if (c == 'f' && src.substr(pos).starts_with("false")) { pos += 5; return JsonVal{JsonVal::Kind::bool_v, false}; }
                if (c == 'n' && src.substr(pos).starts_with("null")) { pos += 4; return JsonVal{JsonVal::Kind::null_v}; }
                if (c == '[') {
                    ++pos;
                    JsonVal arr{JsonVal::Kind::arr_v};
                    if (take(']')) return arr;
                    for (;;) {
                        auto item = parse(depth + 1);
                        if (!item) return item;
                        arr.arr.push_back(std::move(*item));
                        if (take(']')) return arr;
                        if (!take(',')) return std::unexpected("expected ',' or ']' in JSON array");
                    }
                }
                if (c == '{') {
                    ++pos;
                    JsonVal obj{JsonVal::Kind::obj_v};
                    if (take('}')) return obj;
                    for (;;) {
                        auto k = read_string();
                        if (!k) return std::unexpected(k.error());
                        if (!take(':')) return std::unexpected("expected ':' in JSON object");
                        auto v = parse(depth + 1);
                        if (!v) return v;
                        obj.obj.emplace_back(std::move(*k), std::move(*v));
                        if (take('}')) return obj;
                        if (!take(',')) return std::unexpected("expected ',' or '}' in JSON object");
                    }
                }
                if (c == '-' || (c >= '0' && c <= '9')) {
                    auto start = pos;
                    if (src[pos] == '-') ++pos;
                    bool is_flt = false;
                    while (pos < src.size() && (std::isdigit(static_cast<unsigned char>(src[pos])) ||
                           src[pos] == '.' || src[pos] == 'e' || src[pos] == 'E' || src[pos] == '+' || src[pos] == '-')) {
                        if (src[pos] == '.' || src[pos] == 'e' || src[pos] == 'E') is_flt = true;
                        ++pos;
                    }
                    if (!is_flt) {
                        std::int64_t iv = 0;
                        auto [e, ec] = std::from_chars(src.data() + start, src.data() + pos, iv);
                        if (ec == std::errc{} && e == src.data() + pos)
                            return JsonVal{JsonVal::Kind::int_v, false, iv};
                    }
                    return JsonVal{JsonVal::Kind::dbl_v, false, 0, std::string(src.substr(start, pos - start))};
                }
                return std::unexpected("unexpected JSON token");
            }
        };

        auto parse_duration_ms(std::string_view s) -> std::uint32_t {
            s = trim(s);
            if (s.empty()) return 300000;
            std::int64_t num = 0;
            auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), num);
            if (ec != std::errc{} || num <= 0) return 300000;
            auto unit = trim(s.substr(static_cast<std::size_t>(ptr - s.data())));
            std::int64_t mult = (unit == "m" || unit == "min") ? 60000 : (unit == "h") ? 3600000 : (unit == "ms") ? 1 : 1000;
            if (num >= 3600000 / mult) return 3600000;
            return static_cast<std::uint32_t>(std::clamp<std::int64_t>(num * mult, 500, 3600000));
        }

        auto convert_sip008_list(JsonVal const& arr, ParsedDocument& doc) -> void {
            doc.detected_format = ProviderFormat::sip008_json;
            for (auto const& item : arr.arr) {
                auto* srv = item.get("server");
                auto* port_v = item.get("server_port");
                auto* meth = item.get("method");
                auto* pwd = item.get("password");
                auto port = port_v ? port_v->as_int() : std::nullopt;
                if (!srv || srv->as_str().empty() || !port || *port <= 0 || *port > 65535 || !meth || !pwd) {
                    doc.warnings.push_back("skipped incomplete SIP008 server entry");
                    continue;
                }
                ParsedProxy p{};
                p.protocol = ProxyProtocol::shadowsocks;
                p.tls_enabled = false;
                p.host = srv->as_str();
                p.port = static_cast<std::uint16_t>(*port);
                p.method = meth->as_str();
                p.secret = pwd->as_str();
                auto raw_tag = item.get("remarks") && !item.get("remarks")->as_str().empty() ? item.get("remarks")->as_str() :
                    (item.get("id") ? item.get("id")->as_str() : std::string{});
                p.tag = sanitize_tag(raw_tag, "ss-" + p.host);
                doc.proxies.push_back(std::move(p));
            }
        }

        auto parse_singbox_proxy(JsonVal const& ob) -> std::expected<ParsedProxy, std::string> {
            auto type = lower_ascii(ob.get("type") ? ob.get("type")->as_str() : std::string{});
            auto tag_raw = ob.get("tag") ? ob.get("tag")->as_str() : std::string{};
            ParsedProxy p{};
            if (type == "wireguard") {
                p.protocol = ProxyProtocol::wireguard;
                p.tls_enabled = false;
                if (auto* pk = ob.get("private_key")) p.wg_private_key = pk->as_str();
                for (std::string_view key : {"local_address", "address"}) {
                    if (auto* la = ob.get(key); la && la->kind == JsonVal::Kind::arr_v)
                        for (auto const& a : la->arr) {
                            auto s = a.as_str();
                            if (s.contains(':')) p.wg_local_ipv6 = s;
                            else if (!s.empty()) p.wg_local_ipv4 = s;
                        }
                }
                auto valid_port = [](JsonVal const* v) -> std::optional<std::uint16_t> {
                    auto iv = v ? v->as_int() : std::nullopt;
                    return (iv && *iv > 0 && *iv <= 65535) ? std::optional(static_cast<std::uint16_t>(*iv)) : std::nullopt;
                };
                if (auto* peers = ob.get("peers"); peers && peers->kind == JsonVal::Kind::arr_v && !peers->arr.empty()) {
                    auto const& peer = peers->arr.front();
                    if (auto* s = peer.get("server")) p.host = s->as_str();
                    else if (auto* sa = peer.get("address")) p.host = sa->as_str();
                    if (auto* sp = peer.get("server_port")) {
                        if (auto vp = valid_port(sp)) p.port = *vp; else return std::unexpected("invalid WireGuard server_port");
                    } else if (auto* pt = peer.get("port")) {
                        if (auto vp = valid_port(pt)) p.port = *vp; else return std::unexpected("invalid WireGuard port");
                    }
                    if (auto* pk = peer.get("public_key")) p.wg_peer_public_key = pk->as_str();
                    if (auto* psk = peer.get("pre_shared_key")) p.wg_preshared_key = psk->as_str();
                    if (auto* res = peer.get("reserved"); res && res->kind == JsonVal::Kind::arr_v && res->arr.size() == 3)
                        for (std::size_t i = 0; i < 3; ++i) p.wg_reserved[i] = static_cast<std::uint8_t>(res->arr[i].as_int().value_or(0));
                }
                if (p.host.empty() && ob.get("server")) p.host = ob.get("server")->as_str();
                if (!p.port && ob.get("server_port")) {
                    if (auto vp = valid_port(ob.get("server_port"))) p.port = *vp;
                    else return std::unexpected("invalid WireGuard server_port");
                }
                if (p.wg_peer_public_key.empty() && ob.get("peer_public_key")) p.wg_peer_public_key = ob.get("peer_public_key")->as_str();
                if (p.wg_preshared_key.empty() && ob.get("pre_shared_key")) p.wg_preshared_key = ob.get("pre_shared_key")->as_str();
                if (auto* mtu = ob.get("mtu"); mtu && mtu->as_int() && *mtu->as_int() >= 68 && *mtu->as_int() <= 65535)
                    p.wg_mtu = static_cast<std::uint16_t>(*mtu->as_int());
                p.tag = sanitize_tag(tag_raw, "wg-" + p.host);
                if (p.host.empty() || !p.port || p.wg_private_key.empty() || p.wg_peer_public_key.empty())
                    return std::unexpected("incomplete WireGuard outbound");
                return p;
            }
            auto* srv = ob.get("server");
            auto* port_v = ob.get("server_port");
            auto port = port_v ? port_v->as_int() : std::nullopt;
            if (!srv || srv->as_str().empty() || !port || *port <= 0 || *port > 65535)
                return std::unexpected("outbound '" + tag_raw + "' missing server/server_port");
            p.host = srv->as_str();
            p.port = static_cast<std::uint16_t>(*port);
            p.tag = sanitize_tag(tag_raw, type + "-" + p.host);
            if (auto* dt = ob.get("detour")) p.detour = sanitize_tag(dt->as_str(), {});

            if (type == "vless") {
                p.protocol = ProxyProtocol::vless;
                p.secret = ob.get("uuid") ? ob.get("uuid")->as_str() : std::string{};
                p.flow = ob.get("flow") ? ob.get("flow")->as_str() : std::string{};
            } else if (type == "trojan") {
                p.protocol = ProxyProtocol::trojan;
                p.secret = ob.get("password") ? ob.get("password")->as_str() : std::string{};
            } else if (type == "shadowsocks") {
                p.protocol = ProxyProtocol::shadowsocks;
                p.tls_enabled = false;
                p.method = ob.get("method") ? ob.get("method")->as_str() : std::string{};
                p.secret = ob.get("password") ? ob.get("password")->as_str() : std::string{};
                if (auto* uot = ob.get("udp_over_tcp"))
                    p.uot = uot->kind == JsonVal::Kind::obj_v ? (uot->get("enabled") && uot->get("enabled")->as_bool()) : uot->as_bool();
                return p;
            } else if (type == "hysteria2") {
                p.protocol = ProxyProtocol::hysteria2;
                p.secret = ob.get("password") ? ob.get("password")->as_str() : std::string{};
                if (auto* obfs = ob.get("obfs")) {
                    if (auto* ot = obfs->get("type")) p.obfs = ot->as_str();
                    if (auto* op = obfs->get("password")) p.obfs_password = op->as_str();
                }
            } else if (type == "tuic") {
                p.protocol = ProxyProtocol::tuic;
                p.username = ob.get("uuid") ? ob.get("uuid")->as_str() : std::string{};
                p.secret = ob.get("password") ? ob.get("password")->as_str() : std::string{};
                if (auto* cc = ob.get("congestion_control")) p.congestion_control = cc->as_str();
                if (auto* ur = ob.get("udp_relay_mode")) p.udp_relay_mode = ur->as_str();
            } else if (type == "anytls") {
                p.protocol = ProxyProtocol::anytls;
                p.secret = ob.get("password") ? ob.get("password")->as_str() : std::string{};
            } else if (type == "naive") {
                p.protocol = ProxyProtocol::naive;
                p.username = ob.get("username") ? ob.get("username")->as_str() : std::string{};
                p.secret = ob.get("password") ? ob.get("password")->as_str() : std::string{};
                if (auto* n = ob.get("network"); n && lower_ascii(n->as_str()) == "udp") p.naive_protocol = "h3";
            } else if (type == "ssh") {
                p.protocol = ProxyProtocol::ssh;
                p.tls_enabled = false;
                p.username = ob.get("user") ? ob.get("user")->as_str() : std::string{};
                p.secret = ob.get("password") ? ob.get("password")->as_str() : std::string{};
                if (auto* pk = ob.get("private_key_path")) p.path = pk->as_str();
                else if (auto* pk2 = ob.get("private_key")) p.path = pk2->as_str();
                if (auto* hk = ob.get("host_key"); hk && hk->kind == JsonVal::Kind::arr_v && !hk->arr.empty())
                    p.certificate_sha256 = hk->arr.front().as_str();
                return p;
            } else if (type == "socks") {
                p.protocol = ProxyProtocol::socks5;
                p.tls_enabled = false;
                p.username = ob.get("username") ? ob.get("username")->as_str() : std::string{};
                p.secret = ob.get("password") ? ob.get("password")->as_str() : std::string{};
                return p;
            } else if (type == "http") {
                p.protocol = ProxyProtocol::http_connect;
                p.tls_enabled = false;
                p.username = ob.get("username") ? ob.get("username")->as_str() : std::string{};
                p.secret = ob.get("password") ? ob.get("password")->as_str() : std::string{};
            } else {
                return std::unexpected("unsupported sing-box outbound type: " + type);
            }
            if (auto* tls = ob.get("tls"); tls && tls->kind == JsonVal::Kind::obj_v) {
                if (auto* en = tls->get("enabled")) p.tls_enabled = en->as_bool(true);
                if (auto* sni = tls->get("server_name")) p.sni = sni->as_str();
                if (auto* ins = tls->get("insecure")) p.skip_cert_verify = ins->as_bool(false);
                if (auto* ca = tls->get("certificate_path")) p.ca_file = ca->as_str();
                if (auto* utls = tls->get("utls")) if (auto* fp = utls->get("fingerprint")) p.fingerprint = fp->as_str();
                if (auto* real = tls->get("reality"); real && real->get("enabled") && real->get("enabled")->as_bool()) {
                    if (auto* pk = real->get("public_key")) p.reality_public_key = pk->as_str();
                    if (auto* sid = real->get("short_id")) p.reality_short_id = sid->as_str();
                }
            }
            if (p.tls_enabled && p.sni.empty()) p.sni = p.host;
            if (auto* tr = ob.get("transport"); tr && tr->kind == JsonVal::Kind::obj_v) {
                auto tt = lower_ascii(tr->get("type") ? tr->get("type")->as_str() : std::string{});
                p.transport = (tt == "ws") ? "websocket" : (tt == "splithttp" ? "xhttp" : tt);
                if (auto* pa = tr->get("path")) p.path = pa->as_str();
                if (auto* sn = tr->get("service_name")) p.service_name = sn->as_str();
                if (auto* hd = tr->get("headers")) if (auto* h = hd->get("Host")) p.host_header = h->as_str();
                if (p.host_header.empty() && tr->get("host")) {
                    auto const* hv = tr->get("host");
                    if (hv->kind == JsonVal::Kind::arr_v && !hv->arr.empty()) p.host_header = hv->arr.front().as_str();
                    else p.host_header = hv->as_str();
                }
                if (auto* m = tr->get("mode")) p.xhttp_mode = m->as_str();
            }
            if (auto* mux = ob.get("multiplex"); mux && mux->get("enabled") && mux->get("enabled")->as_bool()) {
                p.mux_enabled = true;
                if (auto* pr = mux->get("protocol")) p.mux_protocol = pr->as_str();
            }
            return p;
        }
    }

    auto parse_singbox_or_sip008(std::string_view body, ProviderFormat hint)
        -> std::expected<ParsedDocument, std::string> {
        JsonDomParser parser{body};
        auto root = parser.parse();
        if (!root) return std::unexpected(root.error());
        ParsedDocument doc{};
        if (hint == ProviderFormat::sip008_json || root->kind == JsonVal::Kind::arr_v || root->get("servers")) {
            auto const* arr = root->kind == JsonVal::Kind::arr_v ? &*root : root->get("servers");
            if (!arr || arr->kind != JsonVal::Kind::arr_v)
                return std::unexpected("SIP008 JSON expects array or object.servers array");
            convert_sip008_list(*arr, doc);
            if (doc.proxies.empty()) return std::unexpected("SIP008 JSON contains no valid Shadowsocks servers");
            return doc;
        }
        if (root->kind != JsonVal::Kind::obj_v) return std::unexpected("sing-box JSON root must be an object");
        doc.detected_format = ProviderFormat::singbox_json;
        if (auto* ins = root->get("inbounds"); ins && ins->kind == JsonVal::Kind::arr_v && !ins->arr.empty()) {
            auto const& in0 = ins->arr.front();
            auto it = lower_ascii(in0.get("type") ? in0.get("type")->as_str() : std::string("mixed"));
            if (it == "mixed" || it == "socks" || it == "http")
                doc.inbound_type = (it == "socks") ? "socks5" : it;
            if (auto* lp = in0.get("listen_port"); lp && lp->as_int() && *lp->as_int() > 0 && *lp->as_int() <= 65535)
                doc.inbound_port = static_cast<std::uint16_t>(*lp->as_int());
        }
        if (auto* obs = root->get("outbounds"); obs && obs->kind == JsonVal::Kind::arr_v) {
            for (auto const& ob : obs->arr) {
                auto type = lower_ascii(ob.get("type") ? ob.get("type")->as_str() : std::string{});
                if (type == "direct" || type == "block" || type == "dns") continue;
                if (type == "selector" || type == "urltest") {
                    ParsedGroup g{};
                    g.name = sanitize_tag(ob.get("tag") ? ob.get("tag")->as_str() : std::string("proxy"), "proxy");
                    g.type = (type == "urltest") ? "url-test" : "selector";
                    if (auto* mems = ob.get("outbounds"); mems && mems->kind == JsonVal::Kind::arr_v) {
                        for (auto const& m : mems->arr) {
                            auto ms = m.as_str();
                            auto ml = lower_ascii(ms);
                            if (ml == "direct") g.members.push_back("direct");
                            else if (ml == "block") g.members.push_back("block");
                            else if (!ms.empty()) g.members.push_back(sanitize_tag(ms, {}));
                        }
                    }
                    if (auto* u = ob.get("url"); u && !u->as_str().empty()) g.probe_url = u->as_str();
                    if (auto* iv = ob.get("interval")) {
                        if (iv->kind == JsonVal::Kind::int_v) {
                            auto v = iv->ival;
                            auto ms = v <= 0 ? std::int64_t{500} : (v >= 3600 ? std::int64_t{3600000} : v * 1000);
                            g.interval_ms = static_cast<std::uint32_t>(std::clamp<std::int64_t>(ms, 500, 3600000));
                        } else g.interval_ms = parse_duration_ms(iv->as_str());
                    }
                    if (auto* tol = ob.get("tolerance"); tol && tol->as_int())
                        g.tolerance_ms = static_cast<std::uint32_t>(std::clamp<std::int64_t>(*tol->as_int(), 0, 10000));
                    doc.groups.push_back(std::move(g));
                    continue;
                }
                auto p = parse_singbox_proxy(ob);
                if (!p) doc.warnings.push_back(p.error());
                else doc.proxies.push_back(std::move(*p));
            }
        }
        if (auto* route = root->get("route")) {
            if (auto* fn = route->get("final"); fn && !fn->as_str().empty()) {
                auto fl = lower_ascii(fn->as_str());
                doc.default_outbound = (fl == "direct") ? "direct" : sanitize_tag(fn->as_str(), "direct");
            }
            if (auto* rules = route->get("rules"); rules && rules->kind == JsonVal::Kind::arr_v) {
                for (auto const& r : rules->arr) {
                    auto out = r.get("outbound") ? r.get("outbound")->as_str() : std::string{};
                    auto act = r.get("action") ? lower_ascii(r.get("action")->as_str()) : std::string{};
                    if (act == "reject") out = "block";
                    if (out.empty()) continue;
                    auto ol = lower_ascii(out);
                    auto target = (ol == "direct") ? "direct" : (ol == "block") ? "block" : sanitize_tag(out, "direct");
                    bool inv = r.get("invert") && r.get("invert")->as_bool();
                    for (std::string_view k : {"domain", "domain_suffix", "domain_keyword", "ip_cidr", "port", "process_name", "network", "rule_set"}) {
                        auto const* v = r.get(k);
                        if (!v) continue;
                        std::string kk(k);
                        std::ranges::replace(kk, '_', '-');
                        auto emit = [&](std::string s) {
                            if (!s.empty()) doc.rules.push_back({kk, std::move(s), target, inv});
                        };
                        if (v->kind == JsonVal::Kind::arr_v) {
                            for (auto const& el : v->arr) emit(el.as_str());
                        } else emit(v->as_str());
                    }
                }
            }
        }
        if (auto* dns = root->get("dns")) {
            if (auto* srvs = dns->get("servers"); srvs && srvs->kind == JsonVal::Kind::arr_v) {
                for (auto const& s : srvs->arr)
                    if (auto* a = s.get("address"); a && !a->as_str().empty()) doc.dns_servers.push_back(a->as_str());
            }
        }
        if (doc.proxies.empty() && doc.groups.empty() && !doc.warnings.empty())
            return std::unexpected("no supported outbounds in sing-box JSON (" + doc.warnings.front() + ")");
        return doc;
    }
}

namespace provider {
    auto parse_subscription(std::string_view body, ProviderFormat fmt)
        -> std::expected<ParsedDocument, std::string> {
        if (body.size() >= 3 && body.substr(0, 3) == "\xef\xbb\xbf") body.remove_prefix(3);
        body = detail::trim(body);
        if (body.empty()) return std::unexpected("empty subscription input");
        if (fmt == ProviderFormat::uri_list) return detail::parse_uri_list(body, false);
        if (fmt == ProviderFormat::clash_yaml) return detail::parse_clash_yaml(body);
        if (fmt == ProviderFormat::singbox_json || fmt == ProviderFormat::sip008_json)
            return detail::parse_singbox_or_sip008(body, fmt);
        if (fmt == ProviderFormat::base64_uri) {
            auto dec = detail::base64_decode(body);
            if (!dec) return std::unexpected("invalid base64 subscription payload");
            return detail::parse_uri_list(*dec, true);
        }
        if (body.starts_with('{') || body.starts_with('['))
            return detail::parse_singbox_or_sip008(body, ProviderFormat::auto_detect);
        auto looks_clash_yaml = [](std::string_view sv) {
            return sv.starts_with("proxies:") || sv.starts_with("proxy-groups:") || sv.starts_with("mixed-port:") ||
                   sv.contains("\nproxies:") || sv.contains("\nproxy-groups:");
        };
        if (looks_clash_yaml(body)) return detail::parse_clash_yaml(body);
        if (body.contains("://")) return detail::parse_uri_list(body, false);
        if (auto dec = detail::base64_decode(body)) {
            auto dec_sv = detail::trim(*dec);
            if (dec_sv.starts_with('{') || dec_sv.starts_with('['))
                return detail::parse_singbox_or_sip008(dec_sv, ProviderFormat::auto_detect);
            if (looks_clash_yaml(dec_sv)) return detail::parse_clash_yaml(dec_sv);
            if (dec_sv.contains("://")) return detail::parse_uri_list(dec_sv, true);
        }
        return std::unexpected("unrecognized subscription or configuration format");
    }
}
