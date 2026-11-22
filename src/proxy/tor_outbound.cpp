module proxy.tor_outbound;
import std;

namespace proxy::tor {
    namespace {
        [[nodiscard]] auto is_loopback_host(std::string_view host) noexcept -> bool {
            return host == "127.0.0.1" || host == "::1" || host == "localhost";
        }

        [[nodiscard]] auto is_hex_string(std::string_view s) noexcept -> bool {
            return !s.empty() && (s.size() % 2 == 0) && std::ranges::all_of(s, [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            });
        }

        [[nodiscard]] auto has_crlf(std::string_view s) noexcept -> bool {
            return s.contains('\r') || s.contains('\n');
        }
    }

    auto validate_config(Config const& cfg) -> std::expected<void, std::string> {
        if (cfg.socks_host.empty() || cfg.socks_port == 0) {
            return std::unexpected("Tor socks_host and socks_port are required");
        }
        if (!cfg.allow_remote_socks && !is_loopback_host(cfg.socks_host)) {
            return std::unexpected("Tor socks_host must be loopback unless allow_remote_socks is enabled");
        }
        if (!cfg.cookie_hex.empty() && !is_hex_string(cfg.cookie_hex)) {
            return std::unexpected("Tor cookie_hex must be valid even-length hex");
        }
        if (has_crlf(cfg.control_password)) {
            return std::unexpected("Tor control_password cannot contain CR/LF");
        }
        return {};
    }

    auto build_socks5_greeting(bool with_isolation_auth) -> std::vector<std::uint8_t> {
        if (with_isolation_auth) return {0x05, 0x02, 0x00, 0x02};
        return {0x05, 0x01, 0x00};
    }

    auto build_socks5_isolation_auth(std::string_view username, std::string_view password)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (username.empty() || username.size() > 255 || password.size() > 255) {
            return std::unexpected("invalid RFC 1929 SOCKS5 credential length");
        }
        std::vector<std::uint8_t> out;
        out.reserve(3 + username.size() + password.size());
        out.push_back(0x01);
        out.push_back(static_cast<std::uint8_t>(username.size()));
        out.insert(out.end(), username.begin(), username.end());
        out.push_back(static_cast<std::uint8_t>(password.size()));
        out.insert(out.end(), password.begin(), password.end());
        return out;
    }

    auto build_socks5_connect_domain(std::string_view host, std::uint16_t port)
        -> std::expected<std::vector<std::uint8_t>, std::string> {
        if (host.empty() || host.size() > 255 || port == 0) {
            return std::unexpected("Tor SOCKS5 domain CONNECT requires valid host and port");
        }
        std::vector<std::uint8_t> out;
        out.reserve(7 + host.size());
        out.push_back(0x05);
        out.push_back(0x01);
        out.push_back(0x00);
        out.push_back(0x03); // ATYP DOMAINNAME so DNS & .onion resolve exclusively inside Tor
        out.push_back(static_cast<std::uint8_t>(host.size()));
        out.insert(out.end(), host.begin(), host.end());
        out.push_back(static_cast<std::uint8_t>((port >> 8) & 0xff));
        out.push_back(static_cast<std::uint8_t>(port & 0xff));
        return out;
    }

    auto build_control_authenticate(Config const& cfg) -> std::expected<std::string, std::string> {
        if (auto ok = validate_config(cfg); !ok) return std::unexpected(ok.error());
        if (!cfg.cookie_hex.empty()) return "AUTHENTICATE " + cfg.cookie_hex + "\r\n";
        if (!cfg.control_password.empty()) {
            std::string escaped;
            for (char c : cfg.control_password) {
                if (c == '"' || c == '\\') escaped.push_back('\\');
                escaped.push_back(c);
            }
            return "AUTHENTICATE \"" + escaped + "\"\r\n";
        }
        return std::string("AUTHENTICATE\r\n");
    }

    auto build_control_newnym() -> std::string { return "SIGNAL NEWNYM\r\n"; }

    auto build_control_getinfo(std::string_view key) -> std::expected<std::string, std::string> {
        if (key.empty() || has_crlf(key) || key.contains(' ')) {
            return std::unexpected("invalid Tor ControlPort GETINFO key");
        }
        return std::format("GETINFO {}\r\n", key);
    }

    auto parse_control_reply(std::string_view raw) -> std::expected<ControlReply, std::string> {
        ControlReply rep;
        std::size_t pos = 0;
        while (pos < raw.size()) {
            auto nl = raw.find('\n', pos);
            auto line = (nl == std::string_view::npos) ? raw.substr(pos) : raw.substr(pos, nl - pos);
            pos = (nl == std::string_view::npos) ? raw.size() : nl + 1;
            if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
            if (line.empty()) continue;
            if (line.size() < 4 || line[0] < '0' || line[0] > '9' || line[1] < '0' || line[1] > '9' ||
                line[2] < '0' || line[2] > '9') {
                return std::unexpected("malformed Tor ControlPort reply line");
            }
            int code = 0;
            (void)std::from_chars(line.data(), line.data() + 3, code);
            rep.code = code;
            rep.ok = code >= 200 && code < 300;
            auto body = line.substr(4);
            rep.lines.emplace_back(body);
            if (auto idx = body.find("PROGRESS="); idx != std::string_view::npos) {
                int pct = 0;
                auto psv = body.substr(idx + 9);
                auto [end, ec] = std::from_chars(psv.data(), psv.data() + psv.size(), pct);
                if (ec == std::errc{}) rep.bootstrap_progress = pct;
            }
        }
        if (rep.lines.empty()) return std::unexpected("empty Tor ControlPort reply");
        return rep;
    }
}
