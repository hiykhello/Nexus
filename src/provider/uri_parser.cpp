module provider;
import std;
import rules.regex;
import :detail;

namespace provider {
    using namespace detail;

    namespace {
        auto parse_query(std::string_view query) -> std::map<std::string, std::string> {
            std::map<std::string, std::string> kv;
            while (!query.empty()) {
                auto amp = query.find('&');
                auto pair = amp == std::string_view::npos ? query : query.substr(0, amp);
                auto eq = pair.find('=');
                if (eq != std::string_view::npos)
                    kv[lower_ascii(percent_decode(pair.substr(0, eq)))] = percent_decode(pair.substr(eq + 1));
                if (amp == std::string_view::npos) break;
                query.remove_prefix(amp + 1);
            }
            return kv;
        }

        auto is_truthy(std::string_view v) noexcept -> bool {
            auto l = lower_ascii(v);
            return l == "1" || l == "true" || l == "yes";
        }
    }

    auto parse_subscription_userinfo(std::string_view header) -> std::optional<SubscriptionUserinfo> {
        if (header.empty()) return std::nullopt;
        SubscriptionUserinfo info{};
        bool any = false;
        while (!header.empty()) {
            auto semi = header.find(';');
            auto part = trim(semi == std::string_view::npos ? header : header.substr(0, semi));
            if (auto eq = part.find('='); eq != std::string_view::npos) {
                auto key = lower_ascii(trim(part.substr(0, eq)));
                auto val = trim(part.substr(eq + 1));
                std::uint64_t num = 0;
                auto [ptr, ec] = std::from_chars(val.data(), val.data() + val.size(), num);
                if (ec == std::errc{} && ptr == val.data() + val.size()) {
                    if (key == "upload") { info.upload = num; any = true; }
                    else if (key == "download") { info.download = num; any = true; }
                    else if (key == "total") { info.total = num; any = true; }
                    else if (key == "expire") { info.expire = num; any = true; }
                }
            }
            if (semi == std::string_view::npos) break;
            header.remove_prefix(semi + 1);
        }
        return any ? std::optional(info) : std::nullopt;
    }

    auto parse_share_uri(std::string_view uri) -> std::expected<ParsedProxy, std::string> {
        uri = trim(uri);
        auto sep = uri.find("://");
        if (sep == std::string_view::npos) return std::unexpected("missing URI scheme");
        auto scheme = lower_ascii(uri.substr(0, sep));
        auto rest = uri.substr(sep + 3);
        ParsedProxy out{};
        if (scheme == "vless") out.protocol = ProxyProtocol::vless;
        else if (scheme == "trojan") out.protocol = ProxyProtocol::trojan;
        else if (scheme == "ss") { out.protocol = ProxyProtocol::shadowsocks; out.tls_enabled = false; }
        else if (scheme == "hy2" || scheme == "hysteria2") out.protocol = ProxyProtocol::hysteria2;
        else if (scheme == "tuic") out.protocol = ProxyProtocol::tuic;
        else if (scheme == "anytls") out.protocol = ProxyProtocol::anytls;
        else if (scheme == "snell") { out.protocol = ProxyProtocol::snell; out.tls_enabled = false; }
        else if (scheme == "naive+https" || scheme == "naive+h2") { out.protocol = ProxyProtocol::naive; out.naive_protocol = "h2"; }
        else if (scheme == "naive+quic" || scheme == "naive+h3") { out.protocol = ProxyProtocol::naive; out.naive_protocol = "h3"; }
        else if (scheme == "ssh") { out.protocol = ProxyProtocol::ssh; out.tls_enabled = false; }
        else if (scheme == "socks5" || scheme == "socks") { out.protocol = ProxyProtocol::socks5; out.tls_enabled = false; }
        else if (scheme == "https" || scheme == "http") { out.protocol = ProxyProtocol::http_connect; out.tls_enabled = (scheme == "https"); }
        else if (scheme == "wg" || scheme == "wireguard") { out.protocol = ProxyProtocol::wireguard; out.tls_enabled = false; }
        else return std::unexpected("unsupported URI scheme: " + scheme);

        std::string fragment;
        if (auto hash = rest.find('#'); hash != std::string_view::npos) {
            fragment = percent_decode(rest.substr(hash + 1));
            rest = rest.substr(0, hash);
        }
        std::map<std::string, std::string> query;
        if (auto q = rest.find('?'); q != std::string_view::npos) {
            query = parse_query(rest.substr(q + 1));
            rest = rest.substr(0, q);
        }

        std::string userinfo;
        auto at = rest.rfind('@');
        if (at != std::string_view::npos) {
            userinfo = percent_decode(rest.substr(0, at));
            rest = rest.substr(at + 1);
        } else if (out.protocol == ProxyProtocol::shadowsocks) {
            auto dec = base64_decode(rest);
            if (!dec) return std::unexpected("invalid ss:// legacy URI");
            auto dec_at = dec->rfind('@');
            if (dec_at == std::string::npos) return std::unexpected("missing @ in ss:// URI");
            userinfo = dec->substr(0, dec_at);
            rest = {};
            auto hp = split_host_port(std::string_view(*dec).substr(dec_at + 1));
            if (!hp) return std::unexpected(hp.error());
            out.host = std::move(hp->first);
            out.port = hp->second;
        }
        if (out.host.empty()) {
            if (auto slash = rest.find('/'); slash != std::string_view::npos) rest = rest.substr(0, slash);
            auto hp = split_host_port(rest);
            if (!hp) return std::unexpected(hp.error());
            out.host = std::move(hp->first);
            out.port = hp->second;
        }
        out.tag = sanitize_tag(fragment, scheme + "-" + out.host);

        auto qget = [&](std::initializer_list<char const*> keys) -> std::string {
            for (auto* k : keys)
                if (auto it = query.find(k); it != query.end() && !it->second.empty()) return it->second;
            return {};
        };

        if (out.protocol == ProxyProtocol::shadowsocks) {
            auto cred = userinfo.contains(':') ? std::optional(userinfo) : base64_decode(userinfo);
            if (!cred) return std::unexpected("invalid ss:// userinfo");
            auto colon = cred->find(':');
            if (colon == std::string::npos || colon == 0) return std::unexpected("invalid ss:// method:password");
            out.method = cred->substr(0, colon);
            out.secret = cred->substr(colon + 1);
            if (is_truthy(qget({"uot"}))) out.uot = true;
            return out;
        }
        if (out.protocol == ProxyProtocol::wireguard) {
            out.wg_private_key = qget({"privatekey", "private-key"});
            if (out.wg_private_key.empty()) out.wg_private_key = userinfo;
            out.wg_peer_public_key = qget({"publickey", "public-key"});
            out.wg_preshared_key = qget({"presharedkey", "preshared-key"});
            auto addrs = qget({"address"});
            while (!addrs.empty()) {
                auto comma = addrs.find(',');
                auto a = std::string(trim(std::string_view(addrs).substr(0, comma)));
                if (a.contains(':')) out.wg_local_ipv6 = a;
                else if (!a.empty()) out.wg_local_ipv4 = a;
                if (comma == std::string::npos) break;
                addrs.erase(0, comma + 1);
            }
            if (auto m = qget({"mtu"}); !m.empty()) {
                unsigned mv = 1420;
                (void)std::from_chars(m.data(), m.data() + m.size(), mv);
                out.wg_mtu = static_cast<std::uint16_t>(mv);
            }
            if (auto r = qget({"reserved"}); !r.empty()) {
                auto rv = trim(r);
                if (rv.contains(',')) {
                    std::array<std::uint8_t, 3> bytes{};
                    std::size_t idx = 0;
                    bool ok = true, done = false;
                    while (!rv.empty() && idx < 3) {
                        auto c = rv.find(',');
                        auto tok = trim(rv.substr(0, c));
                        unsigned v = 0;
                        auto [e, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), v);
                        if (tok.empty() || ec != std::errc{} || e != tok.data() + tok.size() || v > 255) { ok = false; break; }
                        bytes[idx++] = static_cast<std::uint8_t>(v);
                        if (c == std::string_view::npos) { done = true; break; }
                        rv.remove_prefix(c + 1);
                    }
                    if (ok && idx == 3 && done) out.wg_reserved = bytes;
                } else if (auto dec = base64_decode(rv); dec && dec->size() == 3) {
                    out.wg_reserved = {
                        static_cast<std::uint8_t>((*dec)[0]),
                        static_cast<std::uint8_t>((*dec)[1]),
                        static_cast<std::uint8_t>((*dec)[2])};
                }
            }
            if (out.wg_private_key.empty() || out.wg_peer_public_key.empty())
                return std::unexpected("wg:// requires private key and publickey");
            return out;
        }
        if (out.protocol == ProxyProtocol::tuic || out.protocol == ProxyProtocol::naive ||
            out.protocol == ProxyProtocol::socks5 || out.protocol == ProxyProtocol::http_connect ||
            out.protocol == ProxyProtocol::ssh) {
            if (!userinfo.empty()) {
                if (auto colon = userinfo.find(':'); colon != std::string::npos) {
                    out.username = userinfo.substr(0, colon);
                    out.secret = userinfo.substr(colon + 1);
                } else if (out.protocol == ProxyProtocol::tuic) {
                    out.secret = std::move(userinfo);
                } else {
                    out.username = std::move(userinfo);
                }
            }
        } else {
            if (userinfo.empty()) return std::unexpected("empty credential in " + scheme + " URI");
            out.secret = std::move(userinfo);
        }

        out.sni = qget({"sni", "peer"});
        if (out.sni.empty() && out.tls_enabled) out.sni = out.host;
        out.fingerprint = qget({"fp"});
        out.certificate_sha256 = qget({"host-key-sha256", "host_key_sha256", "certificate-sha256", "pinsha256", "pcs"});
        out.flow = qget({"flow"});
        out.reality_public_key = qget({"pbk"});
        out.reality_short_id = qget({"sid"});
        if (is_truthy(qget({"insecure", "allowinsecure"}))) out.skip_cert_verify = true;
        auto sec = lower_ascii(qget({"security"}));
        if (sec == "none") out.tls_enabled = false;
        else if (sec == "tls" || sec == "reality") out.tls_enabled = true;

        auto rt = lower_ascii(qget({"type"}));
        out.transport = rt == "ws" ? "websocket" : (rt == "splithttp" ? "xhttp" : rt);
        out.path = qget({"path", "servicename", "service-name"});
        out.service_name = qget({"servicename", "service-name"});
        out.host_header = qget({"host", "authority"});
        out.xhttp_mode = qget({"mode"});
        out.obfs = qget({"obfs"});
        out.obfs_password = qget({"obfs-password"});
        if (out.protocol == ProxyProtocol::hysteria2) {
            out.hy2_ports = qget({"mport", "ports"});
            auto parse_u32 = [](std::string_view s) -> std::uint32_t {
                std::uint32_t v = 0;
                auto [e, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
                return (ec == std::errc{} && e > s.data()) ? v : 0;
            };
            if (auto hi_ms = qget({"hop-interval-ms", "hop_interval_ms"}); !hi_ms.empty()) {
                if (auto v = parse_u32(hi_ms); v > 0) out.hy2_hop_interval_ms = v;
            } else if (auto hi = qget({"hop-interval", "hop_interval"}); !hi.empty()) {
                if (auto v = parse_u32(hi); v > 0)
                    out.hy2_hop_interval_ms = static_cast<std::uint32_t>(std::min<std::uint64_t>(std::uint64_t(v) * 1000ull, 86400000ull));
            }
            out.hy2_up_mbps = parse_u32(qget({"upmbps", "up"}));
            out.hy2_down_mbps = parse_u32(qget({"downmbps", "down"}));
        }
        out.congestion_control = qget({"congestion_control", "cc"});
        out.udp_relay_mode = qget({"udp_relay_mode"});
        if (out.protocol == ProxyProtocol::snell) {
            if (auto v = qget({"version", "v"}); v == "4") out.snell_version = 4;
            else out.snell_version = 5;
            out.obfs_password = out.host_header = qget({"obfs-host", "obfs_host"});
        }
        if (out.protocol == ProxyProtocol::ssh) {
            out.method = qget({"cipher"});
            out.path = qget({"private-key-file", "private_key_file", "private-key", "key"});
        }
        if (out.protocol == ProxyProtocol::naive) {
            if (auto p = qget({"padding"}); !p.empty()) out.padding = is_truthy(p);
        }
        return out;
    }

    auto apply_filter(std::vector<ParsedProxy>& proxies, ProviderFilter const& filter)
        -> std::expected<void, std::string> {
        std::vector<rules::BoundedRegex> inc_list, exc_list;
        auto add_patterns = [](std::string_view single, std::span<std::string const> many,
                               std::vector<rules::BoundedRegex>& dst, std::string_view label)
            -> std::expected<void, std::string> {
            auto push = [&](std::string_view pat) -> std::expected<void, std::string> {
                if (pat.empty()) return {};
                auto compiled = compile_filter_regex(pat);
                if (!compiled) return std::unexpected("invalid provider " + std::string(label) + " filter regex");
                for (auto& re : *compiled) dst.push_back(std::move(re));
                return {};
            };
            if (!many.empty()) {
                for (auto const& pat : many) if (auto ok = push(pat); !ok) return ok;
            } else if (!single.empty()) {
                if (auto ok = push(single); !ok) return ok;
            }
            return {};
        };
        if (auto ok = add_patterns(filter.include_regex, filter.include_regexes, inc_list, "include"); !ok) return ok;
        if (auto ok = add_patterns(filter.exclude_regex, filter.exclude_regexes, exc_list, "exclude"); !ok) return ok;
        std::vector<ParsedProxy> kept;
        std::unordered_set<std::string> used_tags;
        kept.reserve(proxies.size());
        used_tags.reserve(proxies.size());
        for (auto& p : proxies) {
            if (!inc_list.empty() &&
                !std::ranges::any_of(inc_list, [&](auto const& re) { return re.search(p.tag); })) continue;
            if (!exc_list.empty() &&
                std::ranges::any_of(exc_list, [&](auto const& re) { return re.search(p.tag); })) continue;
            std::string raw_tag = filter.tag_prefix + p.tag;
            std::string base = sanitize_tag(raw_tag, "proxy-node");
            std::string unique = base;
            for (unsigned n = 2; !used_tags.insert(unique).second; ++n)
                unique = std::format("{}-{}", base, n);
            p.tag = std::move(unique);
            if (!filter.detour.empty() && p.detour.empty()) p.detour = filter.detour;
            if (!filter.ca_file.empty() && p.ca_file.empty()) p.ca_file = filter.ca_file;
            kept.push_back(std::move(p));
        }
        proxies = std::move(kept);
        return {};
    }
}

namespace provider::detail {
    auto parse_uri_list(std::string_view body, bool was_base64) -> std::expected<ParsedDocument, std::string> {
        ParsedDocument doc{};
        doc.detected_format = was_base64 ? ProviderFormat::base64_uri : ProviderFormat::uri_list;
        while (!body.empty()) {
            auto nl = body.find('\n');
            auto line = trim(nl == std::string_view::npos ? body : body.substr(0, nl));
            body = nl == std::string_view::npos ? std::string_view{} : body.substr(nl + 1);
            if (line.empty() || line.starts_with('#')) continue;
            auto p = parse_share_uri(line);
            if (!p) doc.warnings.push_back(std::string(line.substr(0, 32)) + ": " + p.error());
            else doc.proxies.push_back(std::move(*p));
        }
        if (doc.proxies.empty() && doc.warnings.empty())
            return std::unexpected("subscription contains no proxy URIs");
        if (doc.proxies.empty())
            return std::unexpected("no supported proxies found (" + doc.warnings.front() + ")");
        return doc;
    }
}
