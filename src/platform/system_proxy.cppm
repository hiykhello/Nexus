export module platform.system_proxy;
import std;

export namespace platform {
    struct SystemProxyConfig {
        std::string host = "127.0.0.1";
        std::uint16_t http_port = 0;
        std::uint16_t socks_port = 0;
        std::vector<std::string> bypass;
        std::string pac_url;
    };

    struct SystemProxyStatus {
        bool supported = false;
        bool enabled = false;
        std::string backend;
        std::string http_host;
        std::uint16_t http_port = 0;
        std::string socks_host;
        std::uint16_t socks_port = 0;
        std::string pac_url;
        std::vector<std::string> bypass;
    };

    [[nodiscard]] inline auto default_bypass_list() -> std::vector<std::string> {
        return {"localhost", "127.0.0.0/8", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "*.local"};
    }

    [[nodiscard]] inline auto parse_bypass_csv(std::string_view csv) -> std::vector<std::string> {
        std::vector<std::string> out;
        std::size_t pos = 0;
        while (pos < csv.size()) {
            auto sep = csv.find_first_of(",;", pos);
            auto token = sep == std::string_view::npos ? csv.substr(pos) : csv.substr(pos, sep - pos);
            while (!token.empty() && (token.front() == ' ' || token.front() == '\t')) token.remove_prefix(1);
            while (!token.empty() && (token.back() == ' ' || token.back() == '\t')) token.remove_suffix(1);
            if (!token.empty() && !std::ranges::contains(out, token))
                out.emplace_back(token);
            if (sep == std::string_view::npos) break;
            pos = sep + 1;
        }
        return out;
    }

    [[nodiscard]] inline auto validate_system_proxy_config(SystemProxyConfig const& cfg)
        -> std::expected<void, std::string> {
        auto has_bad_chars = [](std::string_view text) noexcept -> bool {
            return std::ranges::any_of(text, [](unsigned char c) {
                return c < 0x21 || c == 0x7f || c == '\'' || c == '"' || c == ';' || c == '`';
            });
        };
        if (cfg.http_port == 0 && cfg.socks_port == 0 && cfg.pac_url.empty())
            return std::unexpected("system proxy requires http_port, socks_port, or pac_url");
        if ((cfg.http_port != 0 || cfg.socks_port != 0) &&
            (cfg.host.empty() || cfg.host.size() > 255 || has_bad_chars(cfg.host)))
            return std::unexpected("invalid system proxy host");
        if (!cfg.pac_url.empty() &&
            ((!cfg.pac_url.starts_with("http://") && !cfg.pac_url.starts_with("https://")) ||
             has_bad_chars(cfg.pac_url)))
            return std::unexpected("system proxy pac_url must be a valid http:// or https:// URL");
        for (auto const& entry : cfg.bypass) {
            if (entry.empty() || entry.size() > 255 || has_bad_chars(entry))
                return std::unexpected("invalid system proxy bypass entry: " + entry);
        }
        return {};
    }

    [[nodiscard]] inline auto format_windows_bypass(std::span<std::string const> entries) -> std::string {
        std::string out;
        bool has_local = false;
        for (auto const& item : entries) {
            if (item.empty()) continue;
            if (item == "<local>") has_local = true;
            if (!out.empty()) out.push_back(';');
            out += item;
        }
        if (!has_local) {
            if (!out.empty()) out.push_back(';');
            out += "<local>";
        }
        return out;
    }

    [[nodiscard]] inline auto format_gnome_ignore_hosts(std::span<std::string const> entries) -> std::string {
        std::string out = "[";
        bool first = true;
        for (auto const& item : entries) {
            if (item.empty()) continue;
            if (!first) out += ", ";
            first = false;
            out.push_back('\'');
            out += item;
            out.push_back('\'');
        }
        out.push_back(']');
        return out;
    }

    [[nodiscard]] inline auto format_shell_env_exports(SystemProxyConfig const& cfg, bool enable) -> std::string {
        if (!enable) {
            return "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY\n";
        }
        std::string out;
        if (cfg.http_port != 0) {
            auto url = std::format("http://{}:{}", cfg.host, cfg.http_port);
            out += std::format("export http_proxy=\"{}\" https_proxy=\"{}\" HTTP_PROXY=\"{}\" HTTPS_PROXY=\"{}\"\n",
                url, url, url, url);
        }
        if (cfg.socks_port != 0) {
            auto url = std::format("socks5h://{}:{}", cfg.host, cfg.socks_port);
            out += std::format("export all_proxy=\"{}\" ALL_PROXY=\"{}\"\n", url, url);
        }
        auto bypass = cfg.bypass.empty() ? default_bypass_list() : cfg.bypass;
        std::string joined;
        for (auto const& b : bypass) {
            if (b.empty()) continue;
            if (!joined.empty()) joined.push_back(',');
            joined += b;
        }
        if (!joined.empty())
            out += std::format("export no_proxy=\"{}\" NO_PROXY=\"{}\"\n", joined, joined);
        return out;
    }

    [[nodiscard]] auto query_system_proxy() -> SystemProxyStatus;
    [[nodiscard]] auto enable_system_proxy(SystemProxyConfig const& cfg) -> std::expected<void, std::string>;
    [[nodiscard]] auto disable_system_proxy() -> std::expected<void, std::string>;
}
