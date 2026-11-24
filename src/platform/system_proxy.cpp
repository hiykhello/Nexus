module;
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wininet.h>
#else
#include <cctype>
#include <cerrno>
#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

module platform.system_proxy;
import std;

namespace platform {
#if defined(_WIN32)
    namespace {
        constexpr wchar_t const* kInetKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";
        struct WinSnap { bool valid=false, has_en=false, has_pac=false, has_srv=false, has_ovr=false; DWORD en=0; std::string pac, srv, ovr; };
        std::mutex g_proxy_mu;
        WinSnap g_win_snap;
        auto to_wide(std::string_view text) -> std::wstring {
            if (text.empty()) return {};
            int len = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
            if (len <= 0) return {};
            std::wstring out(static_cast<std::size_t>(len), L'\0');
            ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), len);
            return out;
        }

        auto read_reg_str(HKEY key, wchar_t const* name, bool* present = nullptr) -> std::string {
            wchar_t buf[1024]{};
            DWORD bytes = sizeof(buf), type = 0;
            bool ok = ::RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &bytes) == ERROR_SUCCESS && type == REG_SZ;
            if (present) *present = ok;
            if (!ok) return {};
            int len = ::WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
            if (len <= 1) return {};
            std::string out(static_cast<std::size_t>(len - 1), '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, buf, -1, out.data(), len - 1, nullptr, nullptr);
            return out;
        }
        auto capture_win_snap() -> void {
            if (g_win_snap.valid) return;
            HKEY r = nullptr;
            if (::RegOpenKeyExW(HKEY_CURRENT_USER, kInetKey, 0, KEY_READ, &r) != ERROR_SUCCESS) return;
            DWORD sz = sizeof(g_win_snap.en);
            g_win_snap.has_en = ::RegQueryValueExW(r, L"ProxyEnable", nullptr, nullptr, reinterpret_cast<LPBYTE>(&g_win_snap.en), &sz) == ERROR_SUCCESS;
            g_win_snap.pac = read_reg_str(r, L"AutoConfigURL", &g_win_snap.has_pac);
            g_win_snap.srv = read_reg_str(r, L"ProxyServer", &g_win_snap.has_srv);
            g_win_snap.ovr = read_reg_str(r, L"ProxyOverride", &g_win_snap.has_ovr);
            g_win_snap.valid = true;
            ::RegCloseKey(r);
        }

        auto write_reg_str(HKEY key, wchar_t const* name, std::string const& value) -> bool {
            auto w = to_wide(value);
            auto bytes = static_cast<DWORD>((w.size() + 1) * sizeof(wchar_t));
            return ::RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<BYTE const*>(w.c_str()), bytes) == ERROR_SUCCESS;
        }

        auto notify_wininet() -> void {
            if (HMODULE h = ::LoadLibraryW(L"wininet.dll")) {
                using fn = BOOL (WINAPI*)(HINTERNET, DWORD, LPVOID, DWORD);
                if (auto set_opt = reinterpret_cast<fn>(::GetProcAddress(h, "InternetSetOptionW"))) {
                    set_opt(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
                    set_opt(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
                }
                ::FreeLibrary(h);
            }
        }
    }

    auto query_system_proxy() -> SystemProxyStatus {
        SystemProxyStatus status;
        status.backend = "wininet";
        HKEY key = nullptr;
        if (::RegOpenKeyExW(HKEY_CURRENT_USER, kInetKey, 0, KEY_READ, &key) != ERROR_SUCCESS) return status;
        status.supported = true;
        DWORD enabled = 0, size = sizeof(enabled);
        if (::RegQueryValueExW(key, L"ProxyEnable", nullptr, nullptr, reinterpret_cast<LPBYTE>(&enabled), &size) == ERROR_SUCCESS)
            status.enabled = enabled != 0;
        status.pac_url = read_reg_str(key, L"AutoConfigURL");
        if (!status.pac_url.empty()) status.enabled = true;
        status.bypass = parse_bypass_csv(read_reg_str(key, L"ProxyOverride"));
        auto srv = read_reg_str(key, L"ProxyServer");
        ::RegCloseKey(key);
        auto parse_hp = [](std::string_view s, std::string& h, std::uint16_t& p) {
            auto colon = s.rfind(':');
            if (colon == std::string_view::npos) return;
            unsigned port = 0;
            auto ps = s.substr(colon + 1);
            auto [end, ec] = std::from_chars(ps.data(), ps.data() + ps.size(), port);
            if (ec == std::errc{} && end == ps.data() + ps.size() && port <= 65535u) {
                h = std::string(s.substr(0, colon));
                p = static_cast<std::uint16_t>(port);
            }
        };
        if (!srv.empty()) parse_hp(srv, status.http_host, status.http_port);
        return status;
    }

    auto enable_system_proxy(SystemProxyConfig const& cfg) -> std::expected<void, std::string> {
        if (auto ok = validate_system_proxy_config(cfg); !ok) return ok;
        std::lock_guard lock(g_proxy_mu);
        capture_win_snap();
        HKEY key = nullptr;
        if (::RegOpenKeyExW(HKEY_CURRENT_USER, kInetKey, 0, KEY_WRITE, &key) != ERROR_SUCCESS)
            return std::unexpected("failed opening Windows Internet Settings registry key");
        if (!cfg.pac_url.empty()) {
            bool ok = write_reg_str(key, L"AutoConfigURL", cfg.pac_url);
            DWORD off = 0;
            (void)::RegSetValueExW(key, L"ProxyEnable", 0, REG_DWORD, reinterpret_cast<BYTE const*>(&off), sizeof(off));
            ::RegCloseKey(key);
            if (!ok) return std::unexpected("failed setting Windows AutoConfigURL");
            notify_wininet();
            return {};
        }
        std::string server;
        if (cfg.http_port && cfg.socks_port) {
            server = std::format("http={0}:{1};https={0}:{1};socks={0}:{2}", cfg.host, cfg.http_port, cfg.socks_port);
        } else if (cfg.http_port) {
            server = std::format("{}:{}", cfg.host, cfg.http_port);
        } else {
            server = std::format("socks={}:{}", cfg.host, cfg.socks_port);
        }
        auto bypass = format_windows_bypass(cfg.bypass.empty() ? default_bypass_list() : cfg.bypass);
        DWORD on = 1;
        ::RegDeleteValueW(key, L"AutoConfigURL");
        bool ok = write_reg_str(key, L"ProxyServer", server) && write_reg_str(key, L"ProxyOverride", bypass) &&
            ::RegSetValueExW(key, L"ProxyEnable", 0, REG_DWORD, reinterpret_cast<BYTE const*>(&on), sizeof(on)) == ERROR_SUCCESS;
        ::RegCloseKey(key);
        if (!ok) return std::unexpected("failed updating Windows system proxy settings");
        notify_wininet();
        return {};
    }

    auto disable_system_proxy() -> std::expected<void, std::string> {
        std::lock_guard lock(g_proxy_mu);
        HKEY key = nullptr;
        if (::RegOpenKeyExW(HKEY_CURRENT_USER, kInetKey, 0, KEY_WRITE, &key) != ERROR_SUCCESS)
            return std::unexpected("failed opening Windows Internet Settings registry key");
        bool ok = true;
        if (g_win_snap.valid) {
            auto restore_str = [&](wchar_t const* name, bool has, std::string const& v) {
                return has ? write_reg_str(key, name, v) : (::RegDeleteValueW(key, name) == ERROR_SUCCESS || ::GetLastError() == ERROR_FILE_NOT_FOUND);
            };
            ok = restore_str(L"AutoConfigURL", g_win_snap.has_pac, g_win_snap.pac) &&
                 restore_str(L"ProxyServer", g_win_snap.has_srv, g_win_snap.srv) &&
                 restore_str(L"ProxyOverride", g_win_snap.has_ovr, g_win_snap.ovr);
            if (g_win_snap.has_en) ok = ok && ::RegSetValueExW(key, L"ProxyEnable", 0, REG_DWORD, reinterpret_cast<BYTE const*>(&g_win_snap.en), sizeof(g_win_snap.en)) == ERROR_SUCCESS;
            else (void)::RegDeleteValueW(key, L"ProxyEnable");
            g_win_snap = {};
        } else {
            DWORD off = 0;
            ::RegDeleteValueW(key, L"AutoConfigURL");
            ok = ::RegSetValueExW(key, L"ProxyEnable", 0, REG_DWORD, reinterpret_cast<BYTE const*>(&off), sizeof(off)) == ERROR_SUCCESS;
        }
        ::RegCloseKey(key);
        if (!ok) return std::unexpected("failed disabling Windows system proxy");
        notify_wininet();
        return {};
    }
#else
    namespace {
        auto trim_val(std::string& s, bool strip_quotes) -> void {
            while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
            if (strip_quotes && s.size() >= 2 && s.front() == '\'' && s.back() == '\'')
                s = s.substr(1, s.size() - 2);
        }

        auto run_capture(char const* program, char const* const argv[], std::string* out = nullptr,
            bool strip_quotes = true) -> bool {
            int pipefd[2]{-1, -1};
            if (out) {
                if (::pipe(pipefd) != 0) return false;
                (void)::fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
                (void)::fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
            }
            posix_spawn_file_actions_t actions;
            if (::posix_spawn_file_actions_init(&actions) != 0) {
                if (out) { ::close(pipefd[0]); ::close(pipefd[1]); }
                return false;
            }
            bool ok = ::posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0;
            ok = ok && (out
                ? (::posix_spawn_file_actions_addclose(&actions, pipefd[0]) == 0 &&
                   ::posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO) == 0 &&
                   ::posix_spawn_file_actions_addclose(&actions, pipefd[1]) == 0)
                : ::posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0) == 0);
            pid_t pid = -1;
            int rc = ok ? ::posix_spawnp(&pid, program, &actions, nullptr, const_cast<char* const*>(argv), environ) : -1;
            (void)::posix_spawn_file_actions_destroy(&actions);
            if (rc != 0) {
                if (out) { ::close(pipefd[0]); ::close(pipefd[1]); }
                return false;
            }
            if (out) {
                ::close(pipefd[1]);
                out->clear();
                char buf[256];
                for (;;) {
                    auto n = ::read(pipefd[0], buf, sizeof(buf));
                    if (n < 0 && errno == EINTR) continue;
                    if (n <= 0) break;
                    out->append(buf, static_cast<std::size_t>(n));
                }
                ::close(pipefd[0]);
                trim_val(*out, strip_quotes);
            }
            int status = 0;
            while (::waitpid(pid, &status, 0) < 0) {
                if (errno != EINTR) return false;
            }
            return WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
        std::mutex g_proxy_mu;
#ifdef __APPLE__
        auto primary_macos_service() -> std::string {
            std::string list;
            char const* argv[] = {"networksetup", "-listallnetworkservices", nullptr};
            if (!run_capture("networksetup", argv, &list, false)) return {};
            std::string fallback;
            std::size_t pos = 0;
            while (pos < list.size()) {
                auto nl = list.find('\n', pos);
                auto line = nl == std::string::npos ? list.substr(pos) : list.substr(pos, nl - pos);
                pos = nl == std::string::npos ? list.size() : nl + 1;
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty() || line.starts_with("An asterisk") || line.front() == '*') continue;
                if (line == "Wi-Fi" || line == "Ethernet") return line;
                if (fallback.empty()) fallback = std::move(line);
            }
            return fallback;
        }

        auto kv_value(std::string_view text, std::string_view key) -> std::string {
            std::size_t pos = 0;
            while (pos < text.size()) {
                auto nl = text.find('\n', pos);
                auto line = nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos);
                pos = nl == std::string_view::npos ? text.size() : nl + 1;
                if (line.starts_with(key)) {
                    auto v = line.substr(key.size());
                    while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
                    while (!v.empty() && (v.back() == '\r' || v.back() == ' ')) v.remove_suffix(1);
                    return std::string(v);
                }
            }
            return {};
        }
        struct MacSnap {
            bool valid = false, web_on = false, sec_on = false, socks_on = false, pac_on = false;
            std::string svc, web_h, web_p, sec_h, sec_p, socks_h, socks_p, pac_url;
        } g_mac_snap;
        struct MacProxyKind { char const* get, *set, *st; bool MacSnap::* on; std::string MacSnap::* h, MacSnap::* p; };
        constexpr std::array<MacProxyKind, 3> kMacKinds{{
            {"-getwebproxy", "-setwebproxy", "-setwebproxystate", &MacSnap::web_on, &MacSnap::web_h, &MacSnap::web_p},
            {"-getsecurewebproxy", "-setsecurewebproxy", "-setsecurewebproxystate", &MacSnap::sec_on, &MacSnap::sec_h, &MacSnap::sec_p},
            {"-getsocksfirewallproxy", "-setsocksfirewallproxy", "-setsocksfirewallproxystate", &MacSnap::socks_on, &MacSnap::socks_h, &MacSnap::socks_p},
        }};
        auto capture_mac_snap(std::string const& svc) -> void {
            if (g_mac_snap.valid) return;
            g_mac_snap = {.valid = true, .svc = svc};
            std::string out;
            for (auto const& k : kMacKinds) {
                if (run_capture("networksetup", (char const* const[]){"networksetup", k.get, svc.c_str(), nullptr}, &out, false)) {
                    g_mac_snap.*(k.on) = kv_value(out, "Enabled:") == "Yes";
                    g_mac_snap.*(k.h) = kv_value(out, "Server:"); g_mac_snap.*(k.p) = kv_value(out, "Port:");
                }
            }
            if (run_capture("networksetup", (char const* const[]){"networksetup", "-getautoproxyurl", svc.c_str(), nullptr}, &out, false)) {
                g_mac_snap.pac_on = kv_value(out, "Enabled:") == "Yes"; g_mac_snap.pac_url = kv_value(out, "URL:");
            }
        }
#else
        struct LinuxSnap {
            bool valid = false, gnome = false;
            std::string mode, pac, hh, hp, sh, sp, xh, xp, ignore_hosts, kread, kwrite, ktype, khttp, khttps;
        } g_linux_snap;
        struct GnomeField { char const* schema, *key; std::string LinuxSnap::* field; };
        constexpr std::array<GnomeField, 8> kGnomeFields{{
            {"org.gnome.system.proxy", "autoconfig-url", &LinuxSnap::pac}, {"org.gnome.system.proxy", "ignore-hosts", &LinuxSnap::ignore_hosts},
            {"org.gnome.system.proxy.http", "host", &LinuxSnap::hh}, {"org.gnome.system.proxy.http", "port", &LinuxSnap::hp},
            {"org.gnome.system.proxy.https", "host", &LinuxSnap::sh}, {"org.gnome.system.proxy.https", "port", &LinuxSnap::sp},
            {"org.gnome.system.proxy.socks", "host", &LinuxSnap::xh}, {"org.gnome.system.proxy.socks", "port", &LinuxSnap::xp},
        }};

        auto cap_gnome(char const* s, char const* k, std::string& d) -> void { (void)run_capture("gsettings", (char const* const[]){"gsettings", "get", s, k, nullptr}, &d); }
        auto set_gnome(char const* s, char const* k, std::string const& v) -> bool { return run_capture("gsettings", (char const* const[]){"gsettings", "set", s, k, v.c_str(), nullptr}); }
        auto cap_kde(std::string const& kr, char const* k, std::string& d) -> void {
            (void)run_capture(kr.c_str(), (char const* const[]){kr.c_str(), "--file", "kioslaverc", "--group", "Proxy Settings", "--key", k, nullptr}, &d, false);
        }
        auto set_kde(std::string const& kw, char const* k, std::string const& v) -> bool {
            return run_capture(kw.c_str(), (char const* const[]){kw.c_str(), "--file", "kioslaverc", "--group", "Proxy Settings", "--key", k, v.c_str(), nullptr});
        }
        auto detect_kde(std::string& kread, std::string& kwrite) -> bool {
            std::string out;
            if (run_capture("which", (char const* const[]){"which", "kwriteconfig6", nullptr}, &out, false)) { kread = "kreadconfig6"; kwrite = "kwriteconfig6"; return true; }
            if (run_capture("which", (char const* const[]){"which", "kwriteconfig5", nullptr}, &out, false)) { kread = "kreadconfig5"; kwrite = "kwriteconfig5"; return true; }
            return false;
        }
#endif
    }

#ifdef __APPLE__
    auto query_system_proxy() -> SystemProxyStatus {
        SystemProxyStatus status;
        status.backend = "networksetup";
        auto svc = primary_macos_service();
        if (svc.empty()) return status;
        status.supported = true;
        std::string w, s;
        char const* gw[] = {"networksetup", "-getwebproxy", svc.c_str(), nullptr};
        char const* gs[] = {"networksetup", "-getsocksfirewallproxy", svc.c_str(), nullptr};
        if (run_capture("networksetup", gw, &w, false)) {
            if (kv_value(w, "Enabled:") == "Yes") status.enabled = true;
            status.http_host = kv_value(w, "Server:");
            unsigned p = 0;
            auto ps = kv_value(w, "Port:");
            if (std::from_chars(ps.data(), ps.data() + ps.size(), p).ec == std::errc{}) status.http_port = static_cast<std::uint16_t>(p);
        }
        if (run_capture("networksetup", gs, &s, false)) {
            if (kv_value(s, "Enabled:") == "Yes") status.enabled = true;
            status.socks_host = kv_value(s, "Server:");
            unsigned p = 0;
            auto ps = kv_value(s, "Port:");
            if (std::from_chars(ps.data(), ps.data() + ps.size(), p).ec == std::errc{}) status.socks_port = static_cast<std::uint16_t>(p);
        }
        return status;
    }

    auto enable_system_proxy(SystemProxyConfig const& cfg) -> std::expected<void, std::string> {
        if (auto ok = validate_system_proxy_config(cfg); !ok) return ok;
        std::lock_guard lock(g_proxy_mu);
        auto svc = primary_macos_service();
        if (svc.empty()) return std::unexpected("no active macOS network service found");
        capture_mac_snap(svc);
        if (!cfg.pac_url.empty()) {
            char const* set_pac[] = {"networksetup", "-setautoproxyurl", svc.c_str(), cfg.pac_url.c_str(), nullptr};
            char const* on_pac[] = {"networksetup", "-setautoproxystate", svc.c_str(), "on", nullptr};
            if (!run_capture("networksetup", set_pac) || !run_capture("networksetup", on_pac))
                return std::unexpected("failed configuring macOS PAC proxy");
        }
        if (cfg.http_port != 0) {
            auto ps = std::to_string(cfg.http_port);
            for (std::size_t i = 0; i < 2; ++i)
                if (!run_capture("networksetup", (char const* const[]){"networksetup", kMacKinds[i].set, svc.c_str(), cfg.host.c_str(), ps.c_str(), nullptr}) ||
                    !run_capture("networksetup", (char const* const[]){"networksetup", kMacKinds[i].st, svc.c_str(), "on", nullptr}))
                    return std::unexpected("failed configuring macOS HTTP/HTTPS proxy");
        }
        if (cfg.socks_port != 0) {
            auto ps = std::to_string(cfg.socks_port);
            if (!run_capture("networksetup", (char const* const[]){"networksetup", kMacKinds[2].set, svc.c_str(), cfg.host.c_str(), ps.c_str(), nullptr}) ||
                !run_capture("networksetup", (char const* const[]){"networksetup", kMacKinds[2].st, svc.c_str(), "on", nullptr}))
                return std::unexpected("failed configuring macOS SOCKS proxy");
        }
        auto bypass = cfg.bypass.empty() ? default_bypass_list() : cfg.bypass;
        std::vector<char const*> bp{"networksetup", "-setproxybypassdomains", svc.c_str()};
        for (auto const& b : bypass) bp.push_back(b.c_str());
        bp.push_back(nullptr);
        (void)run_capture("networksetup", bp.data());
        return {};
    }

    auto disable_system_proxy() -> std::expected<void, std::string> {
        std::lock_guard lock(g_proxy_mu);
        auto svc = g_mac_snap.valid ? g_mac_snap.svc : primary_macos_service();
        if (svc.empty()) return std::unexpected("no active macOS network service found");
        if (g_mac_snap.valid) {
            for (auto const& k : kMacKinds) {
                auto const& h = g_mac_snap.*(k.h); auto const& p = g_mac_snap.*(k.p);
                if (!h.empty() && !p.empty())
                    (void)run_capture("networksetup", (char const* const[]){"networksetup", k.set, svc.c_str(), h.c_str(), p.c_str(), nullptr});
                (void)run_capture("networksetup", (char const* const[]){"networksetup", k.st, svc.c_str(), (g_mac_snap.*(k.on)) ? "on" : "off", nullptr});
            }
            if (!g_mac_snap.pac_url.empty())
                (void)run_capture("networksetup", (char const* const[]){"networksetup", "-setautoproxyurl", svc.c_str(), g_mac_snap.pac_url.c_str(), nullptr});
            (void)run_capture("networksetup", (char const* const[]){"networksetup", "-setautoproxystate", svc.c_str(), g_mac_snap.pac_on ? "on" : "off", nullptr});
            g_mac_snap = {};
            return {};
        }
        for (char const* flag : {"-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate", "-setautoproxystate"}) {
            char const* a[] = {"networksetup", flag, svc.c_str(), "off", nullptr};
            (void)run_capture("networksetup", a);
        }
        return {};
    }
#else
    auto query_system_proxy() -> SystemProxyStatus {
        SystemProxyStatus status;
        std::string mode;
        char const* gprobe[] = {"gsettings", "get", "org.gnome.system.proxy", "mode", nullptr};
        if (run_capture("gsettings", gprobe, &mode)) {
            status.supported = true;
            status.backend = "gsettings";
            status.enabled = (mode == "manual" || mode == "auto");
            (void)run_capture("gsettings", (char const* const[]){"gsettings", "get", "org.gnome.system.proxy.http", "host", nullptr}, &status.http_host);
            std::string hp;
            if (run_capture("gsettings", (char const* const[]){"gsettings", "get", "org.gnome.system.proxy.http", "port", nullptr}, &hp)) {
                unsigned p = 0;
                if (std::from_chars(hp.data(), hp.data() + hp.size(), p).ec == std::errc{}) status.http_port = static_cast<std::uint16_t>(p);
            }
            (void)run_capture("gsettings", (char const* const[]){"gsettings", "get", "org.gnome.system.proxy.socks", "host", nullptr}, &status.socks_host);
            std::string sp;
            if (run_capture("gsettings", (char const* const[]){"gsettings", "get", "org.gnome.system.proxy.socks", "port", nullptr}, &sp)) {
                unsigned p = 0;
                if (std::from_chars(sp.data(), sp.data() + sp.size(), p).ec == std::errc{}) status.socks_port = static_cast<std::uint16_t>(p);
            }
            return status;
        }
        std::string kr, kw;
        if (detect_kde(kr, kw)) {
            status.supported = true;
            status.backend = kw;
            std::string pt;
            if (run_capture(kr.c_str(), (char const* const[]){kr.c_str(), "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", nullptr}, &pt, false))
                status.enabled = (pt == "1" || pt == "2");
            return status;
        }
        status.backend = "none";
        return status;
    }

    auto enable_system_proxy(SystemProxyConfig const& cfg) -> std::expected<void, std::string> {
        if (auto ok = validate_system_proxy_config(cfg); !ok) return ok;
        std::lock_guard lock(g_proxy_mu);
        std::string out;
        if (run_capture("gsettings", (char const* const[]){"gsettings", "get", "org.gnome.system.proxy", "mode", nullptr}, &out)) {
            if (!g_linux_snap.valid) { g_linux_snap = {.valid = true, .gnome = true, .mode = out}; for (auto const& f : kGnomeFields) cap_gnome(f.schema, f.key, g_linux_snap.*(f.field)); }
            auto bypass = format_gnome_ignore_hosts(cfg.bypass.empty() ? default_bypass_list() : cfg.bypass);
            if (!cfg.pac_url.empty())
                return (set_gnome("org.gnome.system.proxy", "autoconfig-url", cfg.pac_url) && set_gnome("org.gnome.system.proxy", "mode", "auto"))
                    ? std::expected<void, std::string>{} : std::unexpected("failed configuring GNOME PAC proxy");
            bool ok = true;
            if (cfg.http_port != 0) {
                auto ps = std::to_string(cfg.http_port);
                ok = ok && set_gnome("org.gnome.system.proxy.http", "host", cfg.host) && set_gnome("org.gnome.system.proxy.http", "port", ps) &&
                           set_gnome("org.gnome.system.proxy.https", "host", cfg.host) && set_gnome("org.gnome.system.proxy.https", "port", ps);
            }
            if (cfg.socks_port != 0)
                ok = ok && set_gnome("org.gnome.system.proxy.socks", "host", cfg.host) && set_gnome("org.gnome.system.proxy.socks", "port", std::to_string(cfg.socks_port));
            ok = ok && set_gnome("org.gnome.system.proxy", "ignore-hosts", bypass) && set_gnome("org.gnome.system.proxy", "mode", "manual");
            return ok ? std::expected<void, std::string>{} : std::unexpected("failed configuring GNOME gsettings proxy");
        }
        std::string kr, kw;
        if (detect_kde(kr, kw)) {
            if (!g_linux_snap.valid) {
                g_linux_snap = {.valid = true, .gnome = false, .kread = kr, .kwrite = kw};
                cap_kde(kr, "ProxyType", g_linux_snap.ktype); cap_kde(kr, "httpProxy", g_linux_snap.khttp); cap_kde(kr, "httpsProxy", g_linux_snap.khttps);
            }
            bool ok = true;
            if (cfg.http_port != 0) { auto url = std::format("http://{}:{}", cfg.host, cfg.http_port); ok = set_kde(kw, "httpProxy", url) && set_kde(kw, "httpsProxy", url); }
            ok = ok && set_kde(kw, "ProxyType", cfg.pac_url.empty() ? "1" : "2");
            return ok ? std::expected<void, std::string>{} : std::unexpected("failed configuring KDE kioslaverc proxy");
        }
        return std::unexpected("no supported desktop proxy backend (gsettings/kwriteconfig) found; use --shell-env");
    }

    auto disable_system_proxy() -> std::expected<void, std::string> {
        std::lock_guard lock(g_proxy_mu);
        if (g_linux_snap.valid) {
            bool ok = true;
            if (g_linux_snap.gnome) {
                for (auto const& f : kGnomeFields) if (!(g_linux_snap.*(f.field)).empty()) ok = ok && set_gnome(f.schema, f.key, g_linux_snap.*(f.field));
                ok = ok && set_gnome("org.gnome.system.proxy", "mode", g_linux_snap.mode.empty() ? "none" : g_linux_snap.mode);
                g_linux_snap = {};
                return ok ? std::expected<void, std::string>{} : std::unexpected("failed restoring GNOME gsettings proxy");
            }
            if (!g_linux_snap.khttp.empty()) ok = ok && set_kde(g_linux_snap.kwrite, "httpProxy", g_linux_snap.khttp);
            if (!g_linux_snap.khttps.empty()) ok = ok && set_kde(g_linux_snap.kwrite, "httpsProxy", g_linux_snap.khttps);
            ok = ok && set_kde(g_linux_snap.kwrite, "ProxyType", g_linux_snap.ktype.empty() ? "0" : g_linux_snap.ktype);
            g_linux_snap = {};
            return ok ? std::expected<void, std::string>{} : std::unexpected("failed restoring KDE kioslaverc proxy");
        }
        std::string out, kr, kw;
        if (run_capture("gsettings", (char const* const[]){"gsettings", "get", "org.gnome.system.proxy", "mode", nullptr}, &out))
            return set_gnome("org.gnome.system.proxy", "mode", "none") ? std::expected<void, std::string>{} : std::unexpected("failed disabling GNOME gsettings proxy");
        if (detect_kde(kr, kw))
            return set_kde(kw, "ProxyType", "0") ? std::expected<void, std::string>{} : std::unexpected("failed disabling KDE kioslaverc proxy");
        return std::unexpected("no supported desktop proxy backend found");
    }
#endif
#endif
}
