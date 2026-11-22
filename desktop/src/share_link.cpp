module desktop.share_link;

import std;

namespace desktop {
    namespace {
        auto hex_val(char c) noexcept -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }

        auto percent_decode(std::string_view in) -> std::string {
            std::string out;
            out.reserve(in.size());
            for (std::size_t i = 0; i < in.size(); ++i) {
                if (in[i] == '%' && i + 2 < in.size()) {
                    int hi = hex_val(in[i + 1]);
                    int lo = hex_val(in[i + 2]);
                    if (hi >= 0 && lo >= 0) {
                        out.push_back(static_cast<char>((hi << 4) | lo));
                        i += 2;
                        continue;
                    }
                }
                out.push_back(in[i]);
            }
            return out;
        }

        auto base64_decode(std::string_view in) -> std::optional<std::string> {
            static constexpr std::string_view kTable =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string out;
            std::uint32_t acc = 0;
            int bits = 0;
            for (char ch : in) {
                if (ch == '=' || ch == ' ' || ch == '\r' || ch == '\n') continue;
                char mapped = ch == '-' ? '+' : (ch == '_' ? '/' : ch);
                auto pos = kTable.find(mapped);
                if (pos == std::string_view::npos) return std::nullopt;
                acc = (acc << 6) | static_cast<std::uint32_t>(pos);
                bits += 6;
                if (bits >= 8) {
                    bits -= 8;
                    out.push_back(static_cast<char>((acc >> bits) & 0xffu));
                }
            }
            return out;
        }

        auto sanitize_tag(std::string_view raw, std::string_view fallback) -> std::string {
            std::string out;
            for (unsigned char c : raw) {
                if (std::isalnum(c) || c == '-' || c == '_') out.push_back(static_cast<char>(c));
                else if (c == ' ' || c == '.' || c == '+') out.push_back('-');
            }
            while (!out.empty() && out.front() == '-') out.erase(out.begin());
            if (out.empty()) return std::string(fallback);
            if (out.size() > 48) out.resize(48);
            return out;
        }

        auto kdl_escape(std::string_view s) -> std::string {
            std::string out;
            out.reserve(s.size() + 2);
            out.push_back('"');
            for (char c : s) {
                if (c == '\\' || c == '"') out.push_back('\\');
                if (c != '\r' && c != '\n') out.push_back(c);
            }
            out.push_back('"');
            return out;
        }

        auto split_host_port(std::string_view hostport)
            -> std::expected<std::pair<std::string, std::uint16_t>, std::string> {
            std::string_view host, port_str;
            if (hostport.starts_with('[')) {
                auto end = hostport.find(']');
                if (end == std::string_view::npos || end + 2 > hostport.size() || hostport[end + 1] != ':')
                    return std::unexpected("invalid IPv6 host:port");
                host = hostport.substr(1, end - 1);
                port_str = hostport.substr(end + 2);
            } else {
                auto colon = hostport.rfind(':');
                if (colon == std::string_view::npos) return std::unexpected("missing port");
                host = hostport.substr(0, colon);
                port_str = hostport.substr(colon + 1);
            }
            if (host.empty()) return std::unexpected("empty server host");
            std::uint16_t port = 0;
            auto [ptr, ec] = std::from_chars(port_str.data(), port_str.data() + port_str.size(), port);
            if (ec != std::errc{} || ptr != port_str.data() + port_str.size() || port == 0)
                return std::unexpected("invalid server port");
            return std::pair{std::string(host), port};
        }

        auto parse_query(std::string_view query) -> std::map<std::string, std::string> {
            std::map<std::string, std::string> kv;
            while (!query.empty()) {
                auto amp = query.find('&');
                auto pair = amp == std::string_view::npos ? query : query.substr(0, amp);
                auto eq = pair.find('=');
                if (eq != std::string_view::npos)
                    kv[percent_decode(pair.substr(0, eq))] = percent_decode(pair.substr(eq + 1));
                if (amp == std::string_view::npos) break;
                query.remove_prefix(amp + 1);
            }
            return kv;
        }
    }

    auto parse_share_link(std::string_view uri) -> std::expected<ParsedOutbound, std::string> {
        while (!uri.empty() && std::isspace(static_cast<unsigned char>(uri.front()))) uri.remove_prefix(1);
        while (!uri.empty() && std::isspace(static_cast<unsigned char>(uri.back()))) uri.remove_suffix(1);
        auto sep = uri.find("://");
        if (sep == std::string_view::npos) return std::unexpected("missing URI scheme");

        auto scheme_str = uri.substr(0, sep);
        auto rest = uri.substr(sep + 3);
        ParsedOutbound out{};
        if (scheme_str == "vless") out.scheme = OutboundScheme::vless;
        else if (scheme_str == "trojan") out.scheme = OutboundScheme::trojan;
        else if (scheme_str == "anytls") out.scheme = OutboundScheme::anytls;
        else if (scheme_str == "hy2" || scheme_str == "hysteria2") out.scheme = OutboundScheme::hysteria2;
        else if (scheme_str == "tuic") out.scheme = OutboundScheme::tuic;
        else if (scheme_str == "snell") out.scheme = OutboundScheme::snell;
        else if (scheme_str == "ss") out.scheme = OutboundScheme::shadowsocks;
        else if (scheme_str == "ssh") out.scheme = OutboundScheme::ssh;
        else if (scheme_str == "naive+https" || scheme_str == "naive+h2") {
            out.scheme = OutboundScheme::naive;
            out.protocol = "h2";
        } else if (scheme_str == "naive+quic" || scheme_str == "naive+h3") {
            out.scheme = OutboundScheme::naive;
            out.protocol = "h3";
        } else if (scheme_str == "https") {
            out.scheme = OutboundScheme::http_connect;
        } else return std::unexpected("unsupported URI scheme: " + std::string(scheme_str));

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
        if (auto slash = rest.find('/'); slash != std::string_view::npos) rest = rest.substr(0, slash);

        auto at = rest.rfind('@');
        if (at == std::string_view::npos && out.scheme != OutboundScheme::http_connect)
            return std::unexpected("missing userinfo@host:port");
        std::string userinfo = at != std::string_view::npos ? percent_decode(rest.substr(0, at)) : std::string{};
        auto hp = split_host_port(at != std::string_view::npos ? rest.substr(at + 1) : rest);
        if (!hp) return std::unexpected(hp.error());
        out.host = std::move(hp->first);
        out.port = hp->second;
        out.tag = sanitize_tag(fragment, std::format("{}-{}", scheme_str, out.host));

        if (out.scheme == OutboundScheme::shadowsocks) {
            auto decoded = userinfo.contains(':') ? std::optional(userinfo) : base64_decode(userinfo);
            if (!decoded) return std::unexpected("invalid ss:// base64 userinfo");
            auto colon = decoded->find(':');
            if (colon == std::string::npos || colon == 0 || colon + 1 >= decoded->size())
                return std::unexpected("invalid ss:// method:password");
            out.method = decoded->substr(0, colon);
            out.secret = decoded->substr(colon + 1);
            return out;
        }

        if (userinfo.empty() && out.scheme != OutboundScheme::http_connect)
            return std::unexpected("empty credential in share link");
        if (out.scheme == OutboundScheme::tuic || out.scheme == OutboundScheme::naive) {
            if (auto colon = userinfo.find(':'); colon != std::string::npos) {
                out.username = userinfo.substr(0, colon);
                out.secret = userinfo.substr(colon + 1);
                if (out.username.empty() || out.secret.empty())
                    return std::unexpected("invalid user:password credential");
            } else if (out.scheme == OutboundScheme::naive) {
                return std::unexpected("naive:// requires user:password");
            } else {
                out.secret = std::move(userinfo);
            }
        } else if (out.scheme == OutboundScheme::ssh || out.scheme == OutboundScheme::http_connect) {
            if (!userinfo.empty()) {
                if (auto colon = userinfo.find(':'); colon != std::string::npos) {
                    out.username = userinfo.substr(0, colon);
                    out.secret = userinfo.substr(colon + 1);
                } else {
                    out.username = std::move(userinfo);
                }
                if (out.scheme == OutboundScheme::ssh && out.username.empty())
                    return std::unexpected("invalid ssh:// username");
            }
        } else {
            out.secret = std::move(userinfo);
        }
        auto qget = [&](std::initializer_list<char const*> keys) -> std::string {
            for (auto* k : keys)
                if (auto it = query.find(k); it != query.end() && !it->second.empty()) return it->second;
            return {};
        };
        out.sni = qget({"sni", "peer"});
        if (out.sni.empty()) out.sni = out.host;
        out.fingerprint = qget({"fp"});
        out.certificate_sha256 = qget({"host-key-sha256", "host_key_sha256", "certificate-sha256", "pinSHA256", "pcs"});
        out.flow = qget({"flow"});
        out.reality_public_key = qget({"pbk"});
        out.reality_short_id = qget({"sid"});
        auto raw_t = qget({"type"});
        if (raw_t == "ws") out.transport = "websocket";
        else if (raw_t == "splithttp") out.transport = "xhttp";
        else out.transport = std::move(raw_t);
        out.path = qget({"path", "serviceName", "service-name"});
        out.host_header = qget({"host", "authority"});
        out.xhttp_mode = qget({"mode"});
        if (out.scheme == OutboundScheme::snell) {
            auto ver = qget({"version", "v"});
            out.snell_version = (ver == "4") ? 4 : 5;
            out.obfs = qget({"obfs"});
            out.obfs_host = qget({"obfs-host", "obfs_host"});
        }
        if (out.scheme == OutboundScheme::ssh) {
            out.method = qget({"cipher"});
            out.private_key_file = qget({"private-key-file", "private_key_file", "private-key", "key"});
        }
        if (out.scheme == OutboundScheme::naive) {
            auto pad = qget({"padding"});
            if (pad == "0" || pad == "false" || pad == "off") out.padding = false;
        }
        if (out.scheme == OutboundScheme::http_connect) {
            auto hv = qget({"http-version", "ver"});
            auto h3v = qget({"h3"});
            auto h2v = qget({"h2"});
            auto udpv = qget({"udp"});
            if (hv == "h3" || hv == "3" || h3v == "1" || h3v == "true") out.http_version = "h3";
            else if (hv == "h2" || hv == "2" || h2v == "1" || h2v == "true") out.http_version = "h2";
            else if (hv == "h1" || hv == "1.1") out.http_version = "h1";
            else out.http_version = "auto";
            out.udp = (udpv == "1" || udpv == "true") && out.http_version == "h3";
        }
        out.congestion_control = qget({"congestion_control", "cc"});
        out.udp_relay_mode = qget({"udp_relay_mode"});
        return out;
    }

    auto render_kdl_outbound(ParsedOutbound const& node, std::string_view secret_file_path) -> std::string {
        auto scheme_type = [&] -> std::string_view {
            switch (node.scheme) {
            case OutboundScheme::vless: return "vless";
            case OutboundScheme::trojan: return "trojan";
            case OutboundScheme::anytls: return "anytls";
            case OutboundScheme::hysteria2: return "hysteria2";
            case OutboundScheme::tuic: return "tuic";
            case OutboundScheme::snell: return "snell";
            case OutboundScheme::shadowsocks: return "shadowsocks";
            case OutboundScheme::ssh: return "ssh";
            case OutboundScheme::naive: return "naive";
            case OutboundScheme::http_connect: return "http-connect";
            }
            std::unreachable();
        }();
        std::string out = std::format("outbound {} type={} {{\n", kdl_escape(node.tag), kdl_escape(scheme_type));
        if (node.scheme == OutboundScheme::naive) {
            out += std::format("    protocol {}\n", kdl_escape(node.protocol == "h3" ? "h3" : "h2"));
            out += std::format("    server host={} port={}\n", kdl_escape(node.host), node.port);
            out += std::format("    authentication username={} password-file={}\n",
                kdl_escape(node.username), kdl_escape(secret_file_path));
            out += "    tls {\n";
            out += std::format("        server-name {}\n", kdl_escape(node.sni));
            if (!node.fingerprint.empty()) out += std::format("        fingerprint {}\n", kdl_escape(node.fingerprint));
            if (!node.certificate_sha256.empty()) out += std::format("        certificate-sha256 {}\n", kdl_escape(node.certificate_sha256));
            out += "        verify #true\n    }\n";
            out += std::format("    padding {}\n}}\n", node.padding ? "#true" : "#false");
            return out;
        }
        if (node.scheme == OutboundScheme::http_connect) {
            if (!node.http_version.empty())
                out += std::format("    http-version {}\n", kdl_escape(node.http_version));
            out += std::format("    server host={} port={}\n", kdl_escape(node.host), node.port);
            if (!node.username.empty() && !secret_file_path.empty())
                out += std::format("    authentication username={} password-file={}\n",
                    kdl_escape(node.username), kdl_escape(secret_file_path));
            if (node.udp) out += "    udp #true\n";
            out += "    tls {\n";
            out += std::format("        server-name {}\n", kdl_escape(node.sni));
            if (!node.fingerprint.empty()) out += std::format("        fingerprint {}\n", kdl_escape(node.fingerprint));
            if (!node.certificate_sha256.empty()) out += std::format("        certificate-sha256 {}\n", kdl_escape(node.certificate_sha256));
            out += "        verify #true\n    }\n}\n";
            return out;
        }
        out += std::format("    server host={} port={}\n", kdl_escape(node.host), node.port);

        if (node.scheme == OutboundScheme::ssh) {
            if (!node.username.empty()) out += std::format("    user {}\n", kdl_escape(node.username));
            if (!node.secret.empty() && !secret_file_path.empty())
                out += std::format("    password-file {}\n", kdl_escape(secret_file_path));
            else if (!node.private_key_file.empty())
                out += std::format("    private-key-file {}\n", kdl_escape(node.private_key_file));
            else if (!secret_file_path.empty())
                out += std::format("    private-key-file {}\n", kdl_escape(secret_file_path));
            if (!node.certificate_sha256.empty())
                out += std::format("    host-key-sha256 {}\n", kdl_escape(node.certificate_sha256));
            if (!node.method.empty())
                out += std::format("    cipher {}\n", kdl_escape(node.method));
            out += "}\n";
            return out;
        }

        if (node.scheme == OutboundScheme::shadowsocks) {
            out += std::format("    method {}\n    key-file {}\n}}\n", kdl_escape(node.method), kdl_escape(secret_file_path));
            return out;
        }
        if (node.scheme == OutboundScheme::snell) {
            out += std::format("    version {}\n    psk-file {}\n", node.snell_version == 4 ? 4 : 5, kdl_escape(secret_file_path));
            if (node.obfs == "http") {
                out += "    obfs \"http\" {\n";
                if (!node.obfs_host.empty()) out += std::format("        host {}\n", kdl_escape(node.obfs_host));
                out += "    }\n";
            }
            out += "}\n";
            return out;
        }

        if (node.scheme == OutboundScheme::vless) {
            out += std::format("    authentication {{\n        uuid-file {}\n    }}\n", kdl_escape(secret_file_path));
            if (!node.flow.empty()) out += std::format("    flow {}\n", kdl_escape(node.flow));
        } else if (node.scheme == OutboundScheme::tuic) {
            out += "    authentication {\n";
            if (!node.username.empty()) out += std::format("        uuid {}\n", kdl_escape(node.username));
            out += std::format("        password-file {}\n    }}\n", kdl_escape(secret_file_path));
            if (!node.congestion_control.empty()) out += std::format("    congestion-control {}\n", kdl_escape(node.congestion_control));
            if (!node.udp_relay_mode.empty()) out += std::format("    udp-relay-mode {}\n", kdl_escape(node.udp_relay_mode));
        } else {
            out += std::format("    authentication {{\n        password-file {}\n    }}\n", kdl_escape(secret_file_path));
        }

        out += "    tls {\n";
        out += std::format("        server-name {}\n", kdl_escape(node.sni));
        if (!node.fingerprint.empty()) out += std::format("        fingerprint {}\n", kdl_escape(node.fingerprint));
        if (!node.certificate_sha256.empty()) out += std::format("        certificate-sha256 {}\n", kdl_escape(node.certificate_sha256));
        if (!node.reality_public_key.empty()) {
            out += "        reality {\n";
            out += std::format("            public-key {}\n", kdl_escape(node.reality_public_key));
            if (!node.reality_short_id.empty()) out += std::format("            short-id {}\n", kdl_escape(node.reality_short_id));
            out += "        }\n";
        }
        out += "    }\n";

        bool has_transport = node.scheme == OutboundScheme::vless || node.scheme == OutboundScheme::trojan || node.scheme == OutboundScheme::anytls;
        if (has_transport && !node.transport.empty() && node.transport != "tcp" && node.transport != "raw") {
            out += std::format("    transport {} {{\n", kdl_escape(node.transport));
            if (node.transport == "grpc") {
                if (!node.path.empty()) out += std::format("        service-name {}\n", kdl_escape(node.path));
                if (!node.host_header.empty()) out += std::format("        authority {}\n", kdl_escape(node.host_header));
            } else {
                if (!node.path.empty()) out += std::format("        path {}\n", kdl_escape(node.path));
                if (!node.host_header.empty()) out += std::format("        host {}\n", kdl_escape(node.host_header));
                if (node.transport == "xhttp" && !node.xhttp_mode.empty())
                    out += std::format("        mode {}\n", kdl_escape(node.xhttp_mode));
            }
            out += "    }\n";
        }
        out += "}\n";
        return out;
    }
}
