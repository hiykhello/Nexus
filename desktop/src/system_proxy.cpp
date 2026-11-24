module;

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wininet.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

module desktop.system_proxy;

import std;

namespace desktop {
#ifdef _WIN32
    namespace {
        constexpr wchar_t const* kInetKey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

        auto read_reg_str(HKEY key, wchar_t const* name) -> std::string {
            wchar_t buf[1024]{};
            DWORD bytes = sizeof(buf), type = 0;
            if (::RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &bytes) != ERROR_SUCCESS ||
                type != REG_SZ) return {};
            int len = ::WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
            if (len <= 1) return {};
            std::string out(static_cast<std::size_t>(len - 1), '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, buf, -1, out.data(), len - 1, nullptr, nullptr);
            return out;
        }

        auto write_reg_str(HKEY key, wchar_t const* name, std::string const& value) -> bool {
            int len = ::MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
            std::wstring wide(static_cast<std::size_t>(len), L'\0');
            if (len > 0) ::MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), wide.data(), len);
            auto bytes = static_cast<DWORD>((wide.size() + 1) * sizeof(wchar_t));
            return ::RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<BYTE const*>(wide.c_str()), bytes) == ERROR_SUCCESS;
        }

        auto notify_wininet() -> void {
            ::InternetSetOptionW(nullptr, INTERNET_OPTION_SETTINGS_CHANGED, nullptr, 0);
            ::InternetSetOptionW(nullptr, INTERNET_OPTION_REFRESH, nullptr, 0);
        }
    }

    auto SystemProxyController::supported() noexcept -> bool { return true; }

    auto SystemProxyController::enable(this SystemProxyController& self, std::string const& host, std::uint16_t port) -> bool {
        if (self.diagnostic_mode_) return false;
        HKEY key = nullptr;
        if (::RegOpenKeyExW(HKEY_CURRENT_USER, kInetKey, 0, KEY_READ | KEY_WRITE, &key) != ERROR_SUCCESS) return false;
        if (!self.saved_) {
            SystemProxySnapshot snap{};
            DWORD enabled = 0, size = sizeof(enabled);
            if (::RegQueryValueExW(key, L"ProxyEnable", nullptr, nullptr, reinterpret_cast<LPBYTE>(&enabled), &size) == ERROR_SUCCESS)
                snap.enabled = enabled != 0;
            snap.server = read_reg_str(key, L"ProxyServer");
            snap.bypass_list = read_reg_str(key, L"ProxyOverride");
            snap.pac_url = read_reg_str(key, L"AutoConfigURL");
            self.saved_ = std::move(snap);
        }
        DWORD on = 1;
        std::string server = (host.contains(':') && !host.starts_with('['))
            ? std::format("[{}]:{}", host, port)
            : std::format("{}:{}", host, port);
        std::string bypass = "localhost;127.*;10.*;172.16.*;192.168.*;<local>";
        ::RegDeleteValueW(key, L"AutoConfigURL");
        bool ok = write_reg_str(key, L"ProxyServer", server) && write_reg_str(key, L"ProxyOverride", bypass) &&
            ::RegSetValueExW(key, L"ProxyEnable", 0, REG_DWORD, reinterpret_cast<BYTE const*>(&on), sizeof(on)) == ERROR_SUCCESS;
        ::RegCloseKey(key);
        if (ok) { notify_wininet(); self.active_ = true; }
        return ok;
    }

    auto SystemProxyController::restore(this SystemProxyController& self) -> bool {
        if (!self.active_ || !self.saved_) return true;
        HKEY key = nullptr;
        if (::RegOpenKeyExW(HKEY_CURRENT_USER, kInetKey, 0, KEY_WRITE, &key) != ERROR_SUCCESS) return false;
        DWORD flag = self.saved_->enabled ? 1u : 0u;
        (void)::RegSetValueExW(key, L"ProxyEnable", 0, REG_DWORD, reinterpret_cast<BYTE const*>(&flag), sizeof(flag));
        if (self.saved_->server.empty()) ::RegDeleteValueW(key, L"ProxyServer");
        else (void)write_reg_str(key, L"ProxyServer", self.saved_->server);
        if (self.saved_->bypass_list.empty()) ::RegDeleteValueW(key, L"ProxyOverride");
        else (void)write_reg_str(key, L"ProxyOverride", self.saved_->bypass_list);
        if (!self.saved_->pac_url.empty()) (void)write_reg_str(key, L"AutoConfigURL", self.saved_->pac_url);
        ::RegCloseKey(key);
        notify_wininet();
        self.active_ = false;
        self.saved_.reset();
        return true;
    }
#else
    namespace {
        auto trim_output(std::string& s, bool strip_single_quotes) -> void {
            while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
            if (strip_single_quotes && s.size() >= 2 && s.front() == '\'' && s.back() == '\'') s = s.substr(1, s.size() - 2);
        }

        auto run_tool_capture(char const* program, char const* const argv[], std::string* out = nullptr,
                              bool strip_quotes = true) -> bool {
            int pipefd[2]{-1, -1};
            if (out) {
                if (::pipe(pipefd) != 0) return false;
                (void)::fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
                (void)::fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
            }
            pid_t pid = ::fork();
            if (pid < 0) {
                if (out) { ::close(pipefd[0]); ::close(pipefd[1]); }
                return false;
            }
            if (pid == 0) {
                int devnull = ::open("/dev/null", O_WRONLY | O_CLOEXEC);
                if (devnull >= 0) {
                    (void)::dup2(devnull, STDERR_FILENO);
                    if (!out) (void)::dup2(devnull, STDOUT_FILENO);
                }
                if (out) {
                    ::close(pipefd[0]);
                    if (pipefd[1] == STDOUT_FILENO) (void)::fcntl(pipefd[1], F_SETFD, 0);
                    else (void)::dup2(pipefd[1], STDOUT_FILENO);
                }
                ::execvp(program, const_cast<char* const*>(argv));
                ::_exit(127);
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
                trim_output(*out, strip_quotes);
            }
            int status = 0;
            pid_t r = 0;
            do { r = ::waitpid(pid, &status, 0); } while (r < 0 && errno == EINTR);
            return r == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
#ifdef __APPLE__
        auto primary_macos_service() -> std::string {
            std::string list;
            char const* argv[] = {"networksetup", "-listallnetworkservices", nullptr};
            if (!run_tool_capture("networksetup", argv, &list, false)) return {};
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

        auto parse_kv_line(std::string_view text, std::string_view key) -> std::string {
            std::size_t pos = 0;
            while (pos < text.size()) {
                auto nl = text.find('\n', pos);
                auto line = nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos);
                pos = nl == std::string_view::npos ? text.size() : nl + 1;
                if (line.starts_with(key)) {
                    auto val = line.substr(key.size());
                    while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.remove_prefix(1);
                    while (!val.empty() && (val.back() == '\r' || val.back() == ' ')) val.remove_suffix(1);
                    return std::string(val);
                }
            }
            return {};
        }
#else
        auto detect_kde_tools(std::string& kread, std::string& kwrite) -> bool {
            char const* probe6[] = {"kreadconfig6", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", nullptr};
            std::string out;
            if (run_tool_capture("kreadconfig6", probe6, &out, false)) {
                char const* wprobe6[] = {"which", "kwriteconfig6", nullptr};
                if (run_tool_capture("which", wprobe6, &out, false)) {
                    kread = "kreadconfig6"; kwrite = "kwriteconfig6"; return true;
                }
            }
            char const* probe5[] = {"kreadconfig5", "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", nullptr};
            if (run_tool_capture("kreadconfig5", probe5, &out, false)) {
                char const* wprobe5[] = {"which", "kwriteconfig5", nullptr};
                if (run_tool_capture("which", wprobe5, &out, false)) {
                    kread = "kreadconfig5"; kwrite = "kwriteconfig5"; return true;
                }
            }
            return false;
        }

        auto prefers_kde() -> bool {
            char const* desk = std::getenv("XDG_CURRENT_DESKTOP");
            if (!desk) return false;
            std::string up(desk);
            for (char& c : up) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            return up.contains("KDE");
        }
#endif
    }

#ifdef __APPLE__
    auto SystemProxyController::supported() noexcept -> bool {
        return !primary_macos_service().empty();
    }

    auto SystemProxyController::enable(this SystemProxyController& self, std::string const& host, std::uint16_t port) -> bool {
        if (self.diagnostic_mode_) return false;
        if (self.service_name_.empty()) self.service_name_ = primary_macos_service();
        if (self.service_name_.empty()) return false;
        if (!self.saved_) {
            SystemProxySnapshot snap{};
            std::string web_out, sweb_out;
            char const* gweb[] = {"networksetup", "-getwebproxy", self.service_name_.c_str(), nullptr};
            char const* gsweb[] = {"networksetup", "-getsecurewebproxy", self.service_name_.c_str(), nullptr};
            if (!run_tool_capture("networksetup", gweb, &web_out, false)) return false;
            (void)run_tool_capture("networksetup", gsweb, &sweb_out, false);
            snap.mode = parse_kv_line(web_out, "Enabled:");
            snap.http_host = parse_kv_line(web_out, "Server:");
            snap.http_port = parse_kv_line(web_out, "Port:");
            snap.server = parse_kv_line(sweb_out, "Enabled:");
            snap.https_host = parse_kv_line(sweb_out, "Server:");
            snap.https_port = parse_kv_line(sweb_out, "Port:");
            self.saved_ = std::move(snap);
        }
        auto port_str = std::to_string(port);
        char const* sweb[] = {"networksetup", "-setwebproxy", self.service_name_.c_str(), host.c_str(), port_str.c_str(), nullptr};
        char const* ssweb[] = {"networksetup", "-setsecurewebproxy", self.service_name_.c_str(), host.c_str(), port_str.c_str(), nullptr};
        char const* on1[] = {"networksetup", "-setwebproxystate", self.service_name_.c_str(), "on", nullptr};
        char const* on2[] = {"networksetup", "-setsecurewebproxystate", self.service_name_.c_str(), "on", nullptr};
        bool ok = run_tool_capture("networksetup", sweb) && run_tool_capture("networksetup", ssweb) &&
            run_tool_capture("networksetup", on1) && run_tool_capture("networksetup", on2);
        if (ok) self.active_ = true;
        return ok;
    }

    auto SystemProxyController::restore(this SystemProxyController& self) -> bool {
        if (!self.active_ || self.service_name_.empty()) return true;
        bool ok = true;
        if (self.saved_) {
            char const* wstate = self.saved_->mode == "Yes" ? "on" : "off";
            char const* sstate = self.saved_->server == "Yes" ? "on" : "off";
            if (!self.saved_->http_host.empty() && !self.saved_->http_port.empty()) {
                char const* a[] = {"networksetup", "-setwebproxy", self.service_name_.c_str(),
                    self.saved_->http_host.c_str(), self.saved_->http_port.c_str(), nullptr};
                ok = run_tool_capture("networksetup", a) && ok;
            }
            if (!self.saved_->https_host.empty() && !self.saved_->https_port.empty()) {
                char const* a[] = {"networksetup", "-setsecurewebproxy", self.service_name_.c_str(),
                    self.saved_->https_host.c_str(), self.saved_->https_port.c_str(), nullptr};
                ok = run_tool_capture("networksetup", a) && ok;
            }
            char const* off1[] = {"networksetup", "-setwebproxystate", self.service_name_.c_str(), wstate, nullptr};
            char const* off2[] = {"networksetup", "-setsecurewebproxystate", self.service_name_.c_str(), sstate, nullptr};
            ok = run_tool_capture("networksetup", off1) && run_tool_capture("networksetup", off2) && ok;
            self.saved_.reset();
        } else {
            char const* off1[] = {"networksetup", "-setwebproxystate", self.service_name_.c_str(), "off", nullptr};
            char const* off2[] = {"networksetup", "-setsecurewebproxystate", self.service_name_.c_str(), "off", nullptr};
            ok = run_tool_capture("networksetup", off1) && run_tool_capture("networksetup", off2);
        }
        self.active_ = false;
        return ok;
    }
#else
    auto SystemProxyController::supported() noexcept -> bool {
        std::string kr, kw;
        if (prefers_kde() && detect_kde_tools(kr, kw)) return true;
        char const* argv[] = {"gsettings", "get", "org.gnome.system.proxy", "mode", nullptr};
        if (run_tool_capture("gsettings", argv)) return true;
        return detect_kde_tools(kr, kw);
    }

    auto SystemProxyController::enable(this SystemProxyController& self, std::string const& host, std::uint16_t port) -> bool {
        if (self.diagnostic_mode_) return false;
        if (self.kde_write_.empty()) {
            char const* gprobe[] = {"gsettings", "get", "org.gnome.system.proxy", "mode", nullptr};
            if (prefers_kde() || !run_tool_capture("gsettings", gprobe)) {
                (void)detect_kde_tools(self.kde_read_, self.kde_write_);
            }
        }
        if (!self.kde_write_.empty()) {
            auto const* kr = self.kde_read_.c_str();
            auto const* kw = self.kde_write_.c_str();
            if (!self.saved_) {
                SystemProxySnapshot snap{};
                char const* gtype[] = {kr, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", nullptr};
                char const* ghttp[] = {kr, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", nullptr};
                char const* ghttps[] = {kr, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", nullptr};
                (void)run_tool_capture(kr, gtype, &snap.mode, false);
                (void)run_tool_capture(kr, ghttp, &snap.http_host, false);
                (void)run_tool_capture(kr, ghttps, &snap.https_host, false);
                self.saved_ = std::move(snap);
            }
            auto proxy_url = (host.contains(':') && !host.starts_with('['))
                ? std::format("http://[{}]:{}", host, port)
                : std::format("http://{}:{}", host, port);
            char const* shttp[] = {kw, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", proxy_url.c_str(), nullptr};
            char const* shttps[] = {kw, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", proxy_url.c_str(), nullptr};
            char const* stype[] = {kw, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "1", nullptr};
            char const* reparse[] = {"dbus-send", "--type=signal", "/KIO/Scheduler",
                "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:", nullptr};
            bool ok = run_tool_capture(kw, shttp) && run_tool_capture(kw, shttps) && run_tool_capture(kw, stype);
            (void)run_tool_capture("dbus-send", reparse);
            if (ok) self.active_ = true;
            return ok;
        }
        if (!self.saved_) {
            SystemProxySnapshot snap{};
            char const* get_mode[] = {"gsettings", "get", "org.gnome.system.proxy", "mode", nullptr};
            char const* get_hhost[] = {"gsettings", "get", "org.gnome.system.proxy.http", "host", nullptr};
            char const* get_hport[] = {"gsettings", "get", "org.gnome.system.proxy.http", "port", nullptr};
            char const* get_shost[] = {"gsettings", "get", "org.gnome.system.proxy.https", "host", nullptr};
            char const* get_sport[] = {"gsettings", "get", "org.gnome.system.proxy.https", "port", nullptr};
            if (!run_tool_capture("gsettings", get_mode, &snap.mode)) return false;
            (void)run_tool_capture("gsettings", get_hhost, &snap.http_host);
            (void)run_tool_capture("gsettings", get_hport, &snap.http_port);
            (void)run_tool_capture("gsettings", get_shost, &snap.https_host);
            (void)run_tool_capture("gsettings", get_sport, &snap.https_port);
            self.saved_ = std::move(snap);
        }
        auto port_str = std::to_string(port);
        char const* set_host[] = {"gsettings", "set", "org.gnome.system.proxy.http", "host", host.c_str(), nullptr};
        char const* set_port[] = {"gsettings", "set", "org.gnome.system.proxy.http", "port", port_str.c_str(), nullptr};
        char const* set_shost[] = {"gsettings", "set", "org.gnome.system.proxy.https", "host", host.c_str(), nullptr};
        char const* set_sport[] = {"gsettings", "set", "org.gnome.system.proxy.https", "port", port_str.c_str(), nullptr};
        char const* set_mode[] = {"gsettings", "set", "org.gnome.system.proxy", "mode", "manual", nullptr};
        bool ok = run_tool_capture("gsettings", set_host) && run_tool_capture("gsettings", set_port) &&
            run_tool_capture("gsettings", set_shost) && run_tool_capture("gsettings", set_sport) && run_tool_capture("gsettings", set_mode);
        if (ok) self.active_ = true;
        return ok;
    }

    auto SystemProxyController::restore(this SystemProxyController& self) -> bool {
        if (!self.active_) return true;
        bool ok = true;
        if (!self.kde_write_.empty()) {
            auto const* kw = self.kde_write_.c_str();
            if (self.saved_) {
                auto const& mode = self.saved_->mode.empty() ? std::string("0") : self.saved_->mode;
                char const* shttp[] = {kw, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpProxy", self.saved_->http_host.c_str(), nullptr};
                char const* shttps[] = {kw, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "httpsProxy", self.saved_->https_host.c_str(), nullptr};
                char const* stype[] = {kw, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", mode.c_str(), nullptr};
                ok = run_tool_capture(kw, shttp) && run_tool_capture(kw, shttps) && run_tool_capture(kw, stype);
                self.saved_.reset();
            } else {
                char const* stype[] = {kw, "--file", "kioslaverc", "--group", "Proxy Settings", "--key", "ProxyType", "0", nullptr};
                ok = run_tool_capture(kw, stype);
            }
            char const* reparse[] = {"dbus-send", "--type=signal", "/KIO/Scheduler", "org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:", nullptr};
            (void)run_tool_capture("dbus-send", reparse);
            self.active_ = false;
            return ok;
        }
        if (self.saved_) {
            { char const* a[] = {"gsettings", "set", "org.gnome.system.proxy.http", "host", self.saved_->http_host.c_str(), nullptr}; ok = run_tool_capture("gsettings", a) && ok; }
            if (!self.saved_->http_port.empty()) { char const* a[] = {"gsettings", "set", "org.gnome.system.proxy.http", "port", self.saved_->http_port.c_str(), nullptr}; ok = run_tool_capture("gsettings", a) && ok; }
            { char const* a[] = {"gsettings", "set", "org.gnome.system.proxy.https", "host", self.saved_->https_host.c_str(), nullptr}; ok = run_tool_capture("gsettings", a) && ok; }
            if (!self.saved_->https_port.empty()) { char const* a[] = {"gsettings", "set", "org.gnome.system.proxy.https", "port", self.saved_->https_port.c_str(), nullptr}; ok = run_tool_capture("gsettings", a) && ok; }
            auto const& mode = self.saved_->mode.empty() ? std::string("none") : self.saved_->mode;
            char const* m[] = {"gsettings", "set", "org.gnome.system.proxy", "mode", mode.c_str(), nullptr};
            ok = run_tool_capture("gsettings", m) && ok;
            self.saved_.reset();
        } else {
            char const* argv[] = {"gsettings", "set", "org.gnome.system.proxy", "mode", "none", nullptr};
            ok = run_tool_capture("gsettings", argv);
        }
        self.active_ = false;
        return ok;
    }
#endif
#endif
}
