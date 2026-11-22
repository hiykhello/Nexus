module openconnect.auth;
import std;

namespace openconnect {
    namespace {
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
            auto start = xml.find(open);
            if (start == std::string_view::npos) return std::nullopt;
            auto gt = xml.find('>', start + open.size());
            if (gt == std::string_view::npos) return std::nullopt;
            auto close = "</" + std::string(tag) + ">";
            auto end = xml.find(close, gt + 1);
            if (end == std::string_view::npos) return std::nullopt;
            return xml.substr(gt + 1, end - (gt + 1));
        }

        [[nodiscard]] auto trim(std::string_view sv) noexcept -> std::string_view {
            while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t' || sv.front() == '\r' || sv.front() == '\n')) sv.remove_prefix(1);
            while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r' || sv.back() == '\n')) sv.remove_suffix(1);
            return sv;
        }
    }

    auto build_config_auth_xml(AuthRequest const& req) -> std::string {
        return std::format(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<config-auth client=\"vpn\" type=\"auth-reply\">\n"
            "  <version who=\"vpn\">{}</version>\n"
            "  <group-access>{}</group-access>\n"
            "  <auth>\n"
            "    <username>{}</username>\n"
            "    <password>{}</password>\n"
            "  </auth>\n"
            "</config-auth>\n",
            escape_xml(req.user_agent), escape_xml(req.group),
            escape_xml(req.username), escape_xml(req.password));
    }

    auto parse_config_auth_response(std::string_view xml) -> std::expected<AuthResult, std::string> {
        if (!xml.contains("<config-auth")) return std::unexpected("missing <config-auth> root");
        AuthResult res;
        if (auto token = extract_xml_tag(xml, "session-token")) {
            res.cookie = std::string(trim(*token));
        } else if (auto cookie = extract_xml_tag(xml, "session-id")) {
            res.cookie = std::string(trim(*cookie));
        }
        if (auto banner = extract_xml_tag(xml, "banner")) {
            res.banner = std::string(trim(*banner));
        }
        if (xml.contains("<auth id=\"success\"") || !res.cookie.empty()) {
            res.authenticated = !res.cookie.empty();
        }
        if (!res.authenticated) return std::unexpected("OpenConnect authentication failed or missing session-token");
        return res;
    }

    auto build_cstp_connect_headers(std::string_view host, std::string_view cookie, std::uint16_t mtu) -> std::string {
        return std::format(
            "CONNECT /CSCOSSLC/tunnel HTTP/1.1\r\n"
            "Host: {}\r\n"
            "Cookie: webvpn={}\r\n"
            "X-CSTP-Version: 1\r\n"
            "X-CSTP-MTU: {}\r\n"
            "X-DTLS-Master-Secret: supported\r\n"
            "\r\n",
            host, cookie, mtu);
    }

    auto parse_cstp_connect_headers(std::string_view raw_headers) -> std::expected<AuthResult, std::string> {
        if (!raw_headers.contains(" 200 ")) return std::unexpected("CSTP CONNECT rejected");
        AuthResult res;
        res.authenticated = true;
        std::size_t pos = 0;
        while (pos < raw_headers.size()) {
            auto nl = raw_headers.find('\n', pos);
            auto line = (nl == std::string_view::npos) ? raw_headers.substr(pos) : raw_headers.substr(pos, nl - pos);
            pos = (nl == std::string_view::npos) ? raw_headers.size() : nl + 1;
            auto colon = line.find(':');
            if (colon == std::string_view::npos) continue;
            auto key = trim(line.substr(0, colon));
            auto val = trim(line.substr(colon + 1));
            if (key == "X-CSTP-Address") res.ipv4_address = std::string(val);
            else if (key == "X-DTLS-Session-ID") res.dtls_session_id = std::string(val);
            else if (key == "X-CSTP-MTU") {
                unsigned parsed = 0;
                auto [p, ec] = std::from_chars(val.data(), val.data() + val.size(), parsed);
                if (ec == std::errc{} && parsed >= 576 && parsed <= 9000) res.mtu = static_cast<std::uint16_t>(parsed);
            }
        }
        return res;
    }
}
