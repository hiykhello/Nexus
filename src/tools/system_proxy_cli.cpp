import std;
import encoding.json;
import platform.system_proxy;

namespace {
    constexpr std::string_view usage =
        "usage:\n"
        "  nexus system-proxy status [--json]\n"
        "  nexus system-proxy on [--host <host>] [--port <http_port>] [--socks-port <port>] [--bypass <csv>] [--pac-url <url>] [--dry-run] [--shell-env]\n"
        "  nexus system-proxy off [--dry-run] [--shell-env]\n";

    using encoding::json_escape_raw;

    auto parse_port(std::string_view text) -> std::optional<std::uint16_t> {
        unsigned p = 0;
        auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), p);
        if (ec != std::errc{} || end != text.data() + text.size() || p == 0 || p > 65535u)
            return std::nullopt;
        return static_cast<std::uint16_t>(p);
    }
}

auto nexus_system_proxy(int argc, char** argv) -> int {
    if (argc == 1 || (argc == 2 && (std::string_view(argv[1]) == "--help" || std::string_view(argv[1]) == "-h"))) {
        (argc == 1 ? std::cerr : std::cout) << usage;
        return argc == 1 ? 2 : 0;
    }
    std::string_view sub(argv[1]);
    if (sub == "status") {
        bool as_json = false;
        for (int i = 2; i < argc; ++i) {
            std::string_view a(argv[i]);
            if (a == "--json") as_json = true;
            else if (a == "--help" || a == "-h") { std::cout << usage; return 0; }
            else { std::cerr << "unknown option: " << a << '\n' << usage; return 2; }
        }
        auto st = platform::query_system_proxy();
        if (as_json) {
            std::cout << std::format(
                "{{\"supported\":{},\"enabled\":{},\"backend\":\"{}\",\"http_host\":\"{}\",\"http_port\":{},\"socks_host\":\"{}\",\"socks_port\":{},\"pac_url\":\"{}\"}}\n",
                st.supported ? "true" : "false", st.enabled ? "true" : "false",
                json_escape_raw(st.backend), json_escape_raw(st.http_host), st.http_port,
                json_escape_raw(st.socks_host), st.socks_port, json_escape_raw(st.pac_url));
        } else {
            std::cout << std::format("supported: {}\nenabled: {}\nbackend: {}\n",
                st.supported ? "yes" : "no", st.enabled ? "yes" : "no", st.backend);
            if (st.http_port) std::cout << std::format("http: {}:{}\n", st.http_host, st.http_port);
            if (st.socks_port) std::cout << std::format("socks: {}:{}\n", st.socks_host, st.socks_port);
            if (!st.pac_url.empty()) std::cout << std::format("pac: {}\n", st.pac_url);
        }
        return 0;
    }
    if (sub == "off") {
        bool dry_run = false, shell_env = false;
        for (int i = 2; i < argc; ++i) {
            std::string_view a(argv[i]);
            if (a == "--dry-run") dry_run = true;
            else if (a == "--shell-env") shell_env = true;
            else if (a == "--help" || a == "-h") { std::cout << usage; return 0; }
            else { std::cerr << "unknown option: " << a << '\n' << usage; return 2; }
        }
        if (shell_env) {
            std::cout << platform::format_shell_env_exports({}, false);
            return 0;
        }
        if (dry_run) {
            std::cout << "[dry-run] system proxy disabled\n";
            return 0;
        }
        if (auto res = platform::disable_system_proxy(); !res) {
            std::cerr << "system-proxy off: " << res.error() << '\n';
            return 1;
        }
        return 0;
    }
    if (sub == "on") {
        platform::SystemProxyConfig cfg{};
        bool dry_run = false, shell_env = false;
        for (int i = 2; i < argc; ++i) {
            std::string_view a(argv[i]);
            auto next = [&]() -> std::expected<std::string_view, int> {
                if (i + 1 >= argc) { std::cerr << "missing value for " << a << '\n'; return std::unexpected(2); }
                return std::string_view(argv[++i]);
            };
            if (a == "--host") { auto v = next(); if (!v) return v.error(); cfg.host = std::string(*v); }
            else if (a == "--port" || a == "--http-port") {
                auto v = next(); if (!v) return v.error();
                auto p = parse_port(*v); if (!p) { std::cerr << "invalid port: " << *v << '\n'; return 2; }
                cfg.http_port = *p;
            } else if (a == "--socks-port") {
                auto v = next(); if (!v) return v.error();
                auto p = parse_port(*v); if (!p) { std::cerr << "invalid socks port: " << *v << '\n'; return 2; }
                cfg.socks_port = *p;
            } else if (a == "--bypass") {
                auto v = next(); if (!v) return v.error();
                cfg.bypass = platform::parse_bypass_csv(*v);
            } else if (a == "--pac-url") {
                auto v = next(); if (!v) return v.error();
                cfg.pac_url = std::string(*v);
            } else if (a == "--dry-run") dry_run = true;
            else if (a == "--shell-env") shell_env = true;
            else if (a == "--help" || a == "-h") { std::cout << usage; return 0; }
            else { std::cerr << "unknown option: " << a << '\n' << usage; return 2; }
        }
        if (auto ok = platform::validate_system_proxy_config(cfg); !ok) {
            std::cerr << "system-proxy on: " << ok.error() << '\n';
            return 2;
        }
        if (shell_env) {
            std::cout << platform::format_shell_env_exports(cfg, true);
            return 0;
        }
        if (dry_run) {
            std::cout << std::format("[dry-run] system proxy on host={} http_port={} socks_port={} pac={}\n",
                cfg.host, cfg.http_port, cfg.socks_port, cfg.pac_url);
            return 0;
        }
        if (auto res = platform::enable_system_proxy(cfg); !res) {
            std::cerr << "system-proxy on: " << res.error() << '\n';
            return 1;
        }
        return 0;
    }
    std::cerr << "unknown system-proxy subcommand: " << sub << '\n' << usage;
    return 2;
}
