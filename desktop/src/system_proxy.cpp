module;

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wininet.h>
#else
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
            DWORD bytes = sizeof(buf);
            DWORD type = 0;
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
            if (::RegQueryValueExW(key, L"ProxyEnable", nullptr, nullptr, reinterpret_cast<LPBYTE>(&enabled), &size) == ERROR_SUCCESS) {
                snap.enabled = enabled != 0;
            }
            snap.server = read_reg_str(key, L"ProxyServer");
            snap.bypass_list = read_reg_str(key, L"ProxyOverride");
            snap.pac_url = read_reg_str(key, L"AutoConfigURL");
            self.saved_ = std::move(snap);
        }
        DWORD on = 1;
        std::string server = std::format("{}:{}", host, port);
        std::string bypass = "localhost;127.*;10.*;172.16.*;192.168.*;<local>";
        ::RegDeleteValueW(key, L"AutoConfigURL");
        bool ok = write_reg_str(key, L"ProxyServer", server) &&
            write_reg_str(key, L"ProxyOverride", bypass) &&
            ::RegSetValueExW(key, L"ProxyEnable", 0, REG_DWORD, reinterpret_cast<BYTE const*>(&on), sizeof(on)) == ERROR_SUCCESS;
        ::RegCloseKey(key);
        if (ok) {
            notify_wininet();
            self.active_ = true;
        }
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
        auto run_gsettings_capture(char const* const argv[], std::string* out = nullptr) -> bool {
            int pipefd[2]{-1, -1};
            if (out && ::pipe(pipefd) != 0) return false;
            pid_t pid = ::fork();
            if (pid < 0) {
                if (out) { ::close(pipefd[0]); ::close(pipefd[1]); }
                return false;
            }
            if (pid == 0) {
                int devnull = ::open("/dev/null", O_WRONLY);
                if (devnull >= 0) {
                    (void)::dup2(devnull, STDERR_FILENO);
                    if (!out) (void)::dup2(devnull, STDOUT_FILENO);
                    ::close(devnull);
                }
                if (out) {
                    ::close(pipefd[0]);
                    (void)::dup2(pipefd[1], STDOUT_FILENO);
                    ::close(pipefd[1]);
                }
                ::execvp("gsettings", const_cast<char* const*>(argv));
                ::_exit(127);
            }
            if (out) {
                ::close(pipefd[1]);
                out->clear();
                char buf[256];
                for (;;) {
                    auto n = ::read(pipefd[0], buf, sizeof(buf));
                    if (n <= 0) break;
                    out->append(buf, static_cast<std::size_t>(n));
                }
                ::close(pipefd[0]);
                while (!out->empty() && (out->back() == '\n' || out->back() == '\r' || out->back() == ' ')) {
                    out->pop_back();
                }
                if (out->size() >= 2 && out->front() == '\'' && out->back() == '\'') {
                    *out = out->substr(1, out->size() - 2);
                }
            }
            int status = 0;
            return ::waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
    }

    auto SystemProxyController::supported() noexcept -> bool {
        char const* argv[] = {"gsettings", "get", "org.gnome.system.proxy", "mode", nullptr};
        return run_gsettings_capture(argv);
    }

    auto SystemProxyController::enable(this SystemProxyController& self, std::string const& host, std::uint16_t port) -> bool {
        if (self.diagnostic_mode_) return false;
        if (!self.saved_) {
            SystemProxySnapshot snap{};
            char const* get_mode[] = {"gsettings", "get", "org.gnome.system.proxy", "mode", nullptr};
            char const* get_hhost[] = {"gsettings", "get", "org.gnome.system.proxy.http", "host", nullptr};
            char const* get_hport[] = {"gsettings", "get", "org.gnome.system.proxy.http", "port", nullptr};
            char const* get_shost[] = {"gsettings", "get", "org.gnome.system.proxy.https", "host", nullptr};
            char const* get_sport[] = {"gsettings", "get", "org.gnome.system.proxy.https", "port", nullptr};
            if (!run_gsettings_capture(get_mode, &snap.mode)) return false;
            (void)run_gsettings_capture(get_hhost, &snap.http_host);
            (void)run_gsettings_capture(get_hport, &snap.http_port);
            (void)run_gsettings_capture(get_shost, &snap.https_host);
            (void)run_gsettings_capture(get_sport, &snap.https_port);
            self.saved_ = std::move(snap);
        }
        auto port_str = std::to_string(port);
        char const* set_host[] = {"gsettings", "set", "org.gnome.system.proxy.http", "host", host.c_str(), nullptr};
        char const* set_port[] = {"gsettings", "set", "org.gnome.system.proxy.http", "port", port_str.c_str(), nullptr};
        char const* set_shost[] = {"gsettings", "set", "org.gnome.system.proxy.https", "host", host.c_str(), nullptr};
        char const* set_sport[] = {"gsettings", "set", "org.gnome.system.proxy.https", "port", port_str.c_str(), nullptr};
        char const* set_mode[] = {"gsettings", "set", "org.gnome.system.proxy", "mode", "manual", nullptr};
        bool ok = run_gsettings_capture(set_host) && run_gsettings_capture(set_port) &&
            run_gsettings_capture(set_shost) && run_gsettings_capture(set_sport) && run_gsettings_capture(set_mode);
        if (ok) self.active_ = true;
        return ok;
    }

    auto SystemProxyController::restore(this SystemProxyController& self) -> bool {
        if (!self.active_) return true;
        bool ok = true;
        if (self.saved_) {
            if (!self.saved_->http_host.empty()) {
                char const* a[] = {"gsettings", "set", "org.gnome.system.proxy.http", "host", self.saved_->http_host.c_str(), nullptr};
                ok = run_gsettings_capture(a) && ok;
            }
            if (!self.saved_->http_port.empty()) {
                char const* a[] = {"gsettings", "set", "org.gnome.system.proxy.http", "port", self.saved_->http_port.c_str(), nullptr};
                ok = run_gsettings_capture(a) && ok;
            }
            if (!self.saved_->https_host.empty()) {
                char const* a[] = {"gsettings", "set", "org.gnome.system.proxy.https", "host", self.saved_->https_host.c_str(), nullptr};
                ok = run_gsettings_capture(a) && ok;
            }
            if (!self.saved_->https_port.empty()) {
                char const* a[] = {"gsettings", "set", "org.gnome.system.proxy.https", "port", self.saved_->https_port.c_str(), nullptr};
                ok = run_gsettings_capture(a) && ok;
            }
            auto const& mode = self.saved_->mode.empty() ? std::string("none") : self.saved_->mode;
            char const* m[] = {"gsettings", "set", "org.gnome.system.proxy", "mode", mode.c_str(), nullptr};
            ok = run_gsettings_capture(m) && ok;
            self.saved_.reset();
        } else {
            char const* argv[] = {"gsettings", "set", "org.gnome.system.proxy", "mode", "none", nullptr};
            ok = run_gsettings_capture(argv);
        }
        self.active_ = false;
        return ok;
    }
#endif
}
