module openconnect.auth;
import std;
import crypto;

namespace openconnect {
    namespace {
        struct StrWipe {
            std::string& s;
            ~StrWipe() {
                if (!s.empty())
                    crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(s.data()), s.size()));
            }
        };
        [[nodiscard]] auto escape_xml(std::string_view text) -> std::string {
            std::string out;
            out.reserve(text.size());
            for (char c : text) {
                switch (c) {
                case '&': out += "&amp;"; break;
                case '<': out += "&lt;"; break;
                case '>': out += "&gt;"; break;
                case '"': out += "&quot;"; break;
                case '\'': out += "&apos;"; break;
                default: out.push_back(c); break;
                }
            }
            return out;
        }

        [[nodiscard]] auto extract_xml_tag(std::string_view xml, std::string_view tag) -> std::optional<std::string_view> {
            auto open = "<" + std::string(tag);
            std::size_t pos = 0;
            while (pos < xml.size()) {
                auto start = xml.find(open, pos);
                if (start == std::string_view::npos) return std::nullopt;
                std::size_t after = start + open.size();
                if (after < xml.size() && xml[after] != '>' && xml[after] != ' ' && xml[after] != '\t' && xml[after] != '/') {
                    pos = after;
                    continue;
                }
                auto gt = xml.find('>', after);
                if (gt == std::string_view::npos) return std::nullopt;
                if (gt > after && xml[gt - 1] == '/') return std::string_view{};
                auto close = "</" + std::string(tag) + ">";
                auto end = xml.find(close, gt + 1);
                if (end == std::string_view::npos) return std::nullopt;
                return xml.substr(gt + 1, end - (gt + 1));
            }
            return std::nullopt;
        }

        [[nodiscard]] auto trim(std::string_view sv) noexcept -> std::string_view {
            while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t' || sv.front() == '\r' || sv.front() == '\n')) sv.remove_prefix(1);
            while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r' || sv.back() == '\n')) sv.remove_suffix(1);
            return sv;
        }

        [[nodiscard]] auto eq_icase(std::string_view a, std::string_view b) noexcept -> bool {
            if (a.size() != b.size()) return false;
            for (std::size_t i = 0; i < a.size(); ++i) {
                auto ca = static_cast<unsigned char>(a[i]), cb = static_cast<unsigned char>(b[i]);
                if (ca >= 'A' && ca <= 'Z') ca = static_cast<unsigned char>(ca - 'A' + 'a');
                if (cb >= 'A' && cb <= 'Z') cb = static_cast<unsigned char>(cb - 'A' + 'a');
                if (ca != cb) return false;
            }
            return true;
        }

        [[nodiscard]] auto has_ctl_or_nul(std::string_view sv, bool allow_sp_tab) noexcept -> bool {
            for (unsigned char c : sv) {
                if (c == '\r' || c == '\n' || c == '\0' || c == 0x7f) return true;
                if (c < 0x20 && !(allow_sp_tab && c == '\t')) return true;
                if (!allow_sp_tab && c == ' ') return true;
            }
            return false;
        }

        [[nodiscard]] auto parse_u16(std::string_view val, unsigned min_v, unsigned max_v) noexcept -> std::optional<std::uint16_t> {
            unsigned parsed = 0;
            auto [p, ec] = std::from_chars(val.data(), val.data() + val.size(), parsed);
            if (ec != std::errc{} || p != val.data() + val.size() || parsed < min_v || parsed > max_v) return std::nullopt;
            return static_cast<std::uint16_t>(parsed);
        }
    }

    auto build_config_auth_xml(AuthRequest const& req) -> std::string {
        if (has_ctl_or_nul(req.user_agent, true) || has_ctl_or_nul(req.username, true) ||
            has_ctl_or_nul(req.group, true) || req.password.find('\0') != std::string::npos ||
            req.opaque.find('\0') != std::string::npos)
            return {};
        std::string opaque_block = req.opaque.empty()
            ? std::string{}
            : std::format("  <opaque>{}</opaque>\n", req.opaque);
        std::string escaped_pw = escape_xml(req.password);
        StrWipe pw_wipe{escaped_pw};
        return std::format(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<config-auth client=\"vpn\" type=\"auth-reply\">\n"
            "  <version who=\"vpn\">{}</version>\n"
            "  <group-access>{}</group-access>\n"
            "{}"
            "  <auth>\n"
            "    <username>{}</username>\n"
            "    <password>{}</password>\n"
            "  </auth>\n"
            "</config-auth>\n",
            escape_xml(req.user_agent), escape_xml(req.group), opaque_block,
            escape_xml(req.username), escaped_pw);
    }

    auto build_http_auth_request(std::string_view host, AuthRequest const& req, bool init_only) -> std::string {
        if (host.empty() || has_ctl_or_nul(host, false) || has_ctl_or_nul(req.user_agent, true)) return {};
        if (!init_only && (has_ctl_or_nul(req.username, true) || has_ctl_or_nul(req.group, true) ||
            req.password.find('\0') != std::string::npos || req.opaque.find('\0') != std::string::npos))
            return {};
        std::string body = init_only
            ? std::format(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<config-auth client=\"vpn\" type=\"init\">\n"
                "  <version who=\"vpn\">{}</version>\n"
                "</config-auth>\n", escape_xml(req.user_agent))
            : build_config_auth_xml(req);
        StrWipe body_wipe{body};
        if (body.empty()) return {};
        return std::format(
            "POST / HTTP/1.1\r\n"
            "Host: {}\r\n"
            "User-Agent: {}\r\n"
            "X-Aggregate-Auth: 1\r\n"
            "X-Transcend-Version: 1\r\n"
            "Content-Type: application/xml; charset=utf-8\r\n"
            "Content-Length: {}\r\n"
            "Connection: close\r\n"
            "\r\n"
            "{}",
            host, req.user_agent, body.size(), body);
    }

    auto parse_config_auth_response(std::string_view xml) -> std::expected<AuthResult, std::string> {
        if (!xml.contains("<config-auth")) return std::unexpected("missing <config-auth> root");
        AuthResult res;
        if (auto token = extract_xml_tag(xml, "session-token")) res.cookie = std::string(trim(*token));
        else if (auto cookie = extract_xml_tag(xml, "session-id")) res.cookie = std::string(trim(*cookie));
        if (auto banner = extract_xml_tag(xml, "banner")) res.banner = std::string(trim(*banner));
        if (auto opq = extract_xml_tag(xml, "opaque")) res.opaque = std::string(trim(*opq));
        if (!res.cookie.empty() && has_ctl_or_nul(res.cookie, false))
            return std::unexpected("invalid control character in OpenConnect session token");
        if (res.opaque.find('\0') != std::string::npos)
            return std::unexpected("invalid NUL character in OpenConnect opaque field");
        if (!res.cookie.empty()) {
            res.authenticated = true;
            return res;
        }
        if (xml.contains("<auth id=\"main\"") || !res.opaque.empty()) {
            res.needs_auth_reply = true;
            return res;
        }
        return std::unexpected("OpenConnect authentication failed or missing session-token");
    }

    auto build_cstp_connect_headers(std::string_view host, std::string_view cookie, std::uint16_t mtu,
                                    std::string_view dtls_master_secret_hex, std::string_view user_agent) -> std::string {
        if (host.empty() || has_ctl_or_nul(host, false) || cookie.empty() || has_ctl_or_nul(cookie, true) ||
            has_ctl_or_nul(dtls_master_secret_hex, false) || has_ctl_or_nul(user_agent, true))
            return {};
        std::string_view dtls = dtls_master_secret_hex.empty() ? std::string_view{"supported"} : dtls_master_secret_hex;
        return std::format(
            "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n"
            "Host: {}\r\n"
            "User-Agent: {}\r\n"
            "Cookie: webvpn={}\r\n"
            "X-CSTP-Version: 1\r\n"
            "X-CSTP-MTU: {}\r\n"
            "X-CSTP-Base-MTU: {}\r\n"
            "X-CSTP-Accept-Encoding: identity\r\n"
            "X-DTLS-Master-Secret: {}\r\n"
            "\r\n",
            host, user_agent, cookie, mtu, mtu, dtls);
    }

    auto parse_cstp_connect_headers(std::string_view raw_headers) -> std::expected<AuthResult, std::string> {
        auto first_nl = raw_headers.find('\n');
        auto status_line = (first_nl == std::string_view::npos) ? raw_headers : raw_headers.substr(0, first_nl);
        if (!status_line.empty() && status_line.back() == '\r') status_line.remove_suffix(1);
        bool status_ok = (status_line.starts_with("HTTP/1.1 200") || status_line.starts_with("HTTP/1.0 200")) &&
                         (status_line.size() == 12 || status_line[12] == ' ');
        if (!status_ok) return std::unexpected("CSTP CONNECT rejected");
        AuthResult res{.authenticated = true};
        std::size_t pos = (first_nl == std::string_view::npos) ? raw_headers.size() : first_nl + 1;
        while (pos < raw_headers.size()) {
            auto nl = raw_headers.find('\n', pos);
            auto line = (nl == std::string_view::npos) ? raw_headers.substr(pos) : raw_headers.substr(pos, nl - pos);
            pos = (nl == std::string_view::npos) ? raw_headers.size() : nl + 1;
            auto colon = line.find(':');
            if (colon == std::string_view::npos) continue;
            auto key = trim(line.substr(0, colon));
            auto val = trim(line.substr(colon + 1));
            if (eq_icase(key, "X-CSTP-Address")) res.ipv4_address = std::string(val);
            else if (eq_icase(key, "X-CSTP-Address-IP6")) {
                if (auto slash = val.find('/'); slash != std::string_view::npos) val = val.substr(0, slash);
                res.ipv6_address = std::string(val);
            } else if (eq_icase(key, "X-DTLS-Session-ID")) res.dtls_session_id = std::string(val);
            else if (eq_icase(key, "X-DTLS-CipherSuite")) res.dtls_cipher = std::string(val);
            else if (eq_icase(key, "X-DTLS-Port")) {
                if (auto p = parse_u16(val, 1, 65535)) res.dtls_port = *p;
            } else if (eq_icase(key, "X-CSTP-MTU")) {
                if (auto m = parse_u16(val, 576, 9000)) res.mtu = *m;
            } else if (eq_icase(key, "X-CSTP-DPD")) {
                if (auto d = parse_u16(val, 0, 3600)) res.dpd_s = *d;
            } else if (eq_icase(key, "X-CSTP-Keepalive")) {
                if (auto k = parse_u16(val, 0, 3600)) res.keepalive_s = *k;
            } else if (eq_icase(key, "X-CSTP-DNS") && !val.empty()) {
                res.dns_servers.emplace_back(val);
            }
        }
        return res;
    }
}
