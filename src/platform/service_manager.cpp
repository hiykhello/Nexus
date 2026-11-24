module;
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

module platform.service_manager;
import std;

namespace platform {
    namespace {
        auto write_text_file(std::filesystem::path const& path, std::string_view text)
            -> std::expected<void, std::string> {
            std::error_code ec;
            if (!path.parent_path().empty()) {
                std::filesystem::create_directories(path.parent_path(), ec);
                if (ec) return std::unexpected("failed creating directory: " + ec.message());
            }
            std::ofstream out(path, std::ios::out | std::ios::trunc);
            if (!out) return std::unexpected("failed opening service file for write: " + path.string());
            out.write(text.data(), static_cast<std::streamsize>(text.size()));
            out.close();
            if (!out) return std::unexpected("failed writing service file: " + path.string());
            return {};
        }
    }

#if defined(_WIN32)
    namespace {
        auto to_wide(std::string_view text) -> std::wstring {
            if (text.empty()) return {};
            int len = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
            if (len <= 0) return {};
            std::wstring out(static_cast<std::size_t>(len), L'\0');
            ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), len);
            return out;
        }
    }

    auto install_service(ServiceSpec const& spec, std::string const& output_dir_override, bool dry_run)
        -> std::expected<std::string, std::string> {
        auto cmd = render_windows_service_command(spec);
        if (!cmd) return std::unexpected(cmd.error());
        if (dry_run) return *cmd;
        if (!output_dir_override.empty()) {
            auto dest = std::filesystem::path(output_dir_override) / (spec.name + ".service-cmd.txt");
            if (auto ok = write_text_file(dest, *cmd); !ok) return std::unexpected(ok.error());
            return dest.string();
        }
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
        if (!scm) return std::unexpected("OpenSCManagerW failed (Administrator privileges required)");
        auto wname = to_wide(spec.name), wdesc = to_wide(spec.description), wcmd = to_wide(*cmd);
        SC_HANDLE svc = ::CreateServiceW(scm, wname.c_str(), wdesc.c_str(), SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, wcmd.c_str(),
            nullptr, nullptr, nullptr, nullptr, nullptr);
        if (!svc) {
            DWORD err = ::GetLastError();
            ::CloseServiceHandle(scm);
            return std::unexpected(std::format("CreateServiceW failed (error={})", err));
        }
        ::CloseServiceHandle(svc);
        ::CloseServiceHandle(scm);
        return spec.name;
    }

    auto uninstall_service(std::string const& name, bool, bool dry_run) -> std::expected<void, std::string> {
        if (auto ok = validate_service_spec({.name = name}, false); !ok) return ok;
        if (dry_run) return {};
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) return std::unexpected("OpenSCManagerW failed");
        auto wname = to_wide(name);
        SC_HANDLE svc = ::OpenServiceW(scm, wname.c_str(), DELETE);
        if (!svc) { ::CloseServiceHandle(scm); return std::unexpected("service not found"); }
        BOOL deleted = ::DeleteService(svc);
        ::CloseServiceHandle(svc);
        ::CloseServiceHandle(scm);
        if (!deleted) return std::unexpected("DeleteService failed");
        return {};
    }

    auto control_service(std::string const& name, std::string_view action, bool) -> std::expected<void, std::string> {
        if (auto ok = validate_service_spec({.name = name}, false); !ok) return ok;
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) return std::unexpected("OpenSCManagerW failed");
        auto wname = to_wide(name);
        DWORD access = action == "start" ? SERVICE_START : (SERVICE_STOP | SERVICE_START);
        SC_HANDLE svc = ::OpenServiceW(scm, wname.c_str(), access);
        if (!svc) { ::CloseServiceHandle(scm); return std::unexpected("service not found"); }
        bool ok = true;
        SERVICE_STATUS st{};
        if (action == "stop" || action == "restart")
            ok = ::ControlService(svc, SERVICE_CONTROL_STOP, &st) != 0;
        if (action == "start" || action == "restart")
            ok = ::StartServiceW(svc, 0, nullptr) != 0 && ok;
        ::CloseServiceHandle(svc);
        ::CloseServiceHandle(scm);
        return ok ? std::expected<void, std::string>{} : std::unexpected("service control operation failed");
    }

    auto query_service_status(std::string const& name, bool) -> ServiceStatus {
        ServiceStatus out{.unit_path = name, .backend = "windows-scm"};
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) return out;
        auto wname = to_wide(name);
        SC_HANDLE svc = ::OpenServiceW(scm, wname.c_str(), SERVICE_QUERY_STATUS);
        if (svc) {
            out.installed = true;
            SERVICE_STATUS ss{};
            if (::QueryServiceStatus(svc, &ss)) {
                out.state = ss.dwCurrentState == SERVICE_RUNNING ? ServiceState::running
                    : ss.dwCurrentState == SERVICE_STOPPED ? ServiceState::stopped : ServiceState::unknown;
            }
            ::CloseServiceHandle(svc);
        }
        ::CloseServiceHandle(scm);
        return out;
    }
#else
    namespace {
        auto run_cmd(char const* const argv[], std::string* out = nullptr) -> bool {
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
                ::execvp(argv[0], const_cast<char* const*>(argv));
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
                while (!out->empty() && (out->back() == '\n' || out->back() == '\r')) out->pop_back();
            }
            int status = 0;
            return ::waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0;
        }
    }

    auto install_service(ServiceSpec const& spec, std::string const& output_dir_override, bool dry_run)
        -> std::expected<std::string, std::string> {
#ifdef __APPLE__
        auto rendered = render_launchd_plist(spec);
        auto filename = std::format("io.nexus.{}.plist", spec.name);
#else
        auto rendered = render_systemd_unit(spec);
        auto filename = std::format("{}.service", spec.name);
#endif
        if (!rendered) return std::unexpected(rendered.error());
        if (dry_run) return *rendered;
        std::filesystem::path dest = output_dir_override.empty()
            ? std::filesystem::path(default_unit_path(spec))
            : (std::filesystem::path(output_dir_override) / filename);
        if (auto ok = write_text_file(dest, *rendered); !ok) return std::unexpected(ok.error());
        if (output_dir_override.empty()) {
#ifdef __APPLE__
            auto domain = spec.user_scope ? std::format("gui/{}", ::getuid()) : std::string("system");
            (void)run_cmd((char const* const[]){"launchctl", "bootstrap", domain.c_str(), dest.c_str(), nullptr});
#else
            if (spec.user_scope)
                (void)run_cmd((char const* const[]){"systemctl", "--user", "daemon-reload", nullptr});
            else
                (void)run_cmd((char const* const[]){"systemctl", "daemon-reload", nullptr});
#endif
        }
        return dest.string();
    }

    auto uninstall_service(std::string const& name, bool user_scope, bool dry_run) -> std::expected<void, std::string> {
        if (auto ok = validate_service_spec({.name = name, .user_scope = user_scope}, false); !ok) return ok;
        auto path = std::filesystem::path(default_unit_path({.name = name, .user_scope = user_scope}));
        if (dry_run) return {};
#ifdef __APPLE__
        auto target = user_scope ? std::format("gui/{}/io.nexus.{}", ::getuid(), name)
                                 : std::format("system/io.nexus.{}", name);
        (void)run_cmd((char const* const[]){"launchctl", "bootout", target.c_str(), nullptr});
#else
        if (user_scope)
            (void)run_cmd((char const* const[]){"systemctl", "--user", "disable", "--now", name.c_str(), nullptr});
        else
            (void)run_cmd((char const* const[]){"systemctl", "disable", "--now", name.c_str(), nullptr});
#endif
        std::error_code ec;
        std::filesystem::remove(path, ec);
#ifndef __APPLE__
        if (user_scope)
            (void)run_cmd((char const* const[]){"systemctl", "--user", "daemon-reload", nullptr});
        else
            (void)run_cmd((char const* const[]){"systemctl", "daemon-reload", nullptr});
#endif
        return {};
    }

    auto control_service(std::string const& name, std::string_view action, bool user_scope)
        -> std::expected<void, std::string> {
        if (auto ok = validate_service_spec({.name = name, .user_scope = user_scope}, false); !ok) return ok;
        if (action != "start" && action != "stop" && action != "restart")
            return std::unexpected("unsupported service action");
#ifdef __APPLE__
        auto svc = user_scope ? std::format("gui/{}/io.nexus.{}", ::getuid(), name)
                              : std::format("system/io.nexus.{}", name);
        if (action == "restart") {
            if (!run_cmd((char const* const[]){"launchctl", "kickstart", "-k", svc.c_str(), nullptr}))
                return std::unexpected("launchctl kickstart failed");
            return {};
        }
        auto path = default_unit_path({.name = name, .user_scope = user_scope});
        auto dom = user_scope ? std::format("gui/{}", ::getuid()) : std::string("system");
        bool ok = action == "start"
            ? run_cmd((char const* const[]){"launchctl", "bootstrap", dom.c_str(), path.c_str(), nullptr})
            : run_cmd((char const* const[]){"launchctl", "bootout", svc.c_str(), nullptr});
        return ok ? std::expected<void, std::string>{} : std::unexpected("launchctl operation failed");
#else
        std::string act(action);
        bool ok = user_scope
            ? run_cmd((char const* const[]){"systemctl", "--user", act.c_str(), name.c_str(), nullptr})
            : run_cmd((char const* const[]){"systemctl", act.c_str(), name.c_str(), nullptr});
        return ok ? std::expected<void, std::string>{} : std::unexpected("systemctl " + act + " failed");
#endif
    }

    auto query_service_status(std::string const& name, bool user_scope) -> ServiceStatus {
        ServiceStatus st;
        st.unit_path = default_unit_path({.name = name, .user_scope = user_scope});
#ifdef __APPLE__
        st.backend = "launchd";
#else
        st.backend = "systemd";
#endif
        if (validate_service_spec({.name = name, .user_scope = user_scope}, false)) {
            std::error_code ec;
            st.installed = std::filesystem::exists(st.unit_path, ec);
        }
        if (!st.installed) return st;
#ifdef __APPLE__
        auto target = user_scope ? std::format("gui/{}/io.nexus.{}", ::getuid(), name)
                                 : std::format("system/io.nexus.{}", name);
        std::string out;
        st.state = run_cmd((char const* const[]){"launchctl", "print", target.c_str(), nullptr}, &out)
            ? ServiceState::running : ServiceState::stopped;
#else
        std::string out;
        bool active = user_scope
            ? run_cmd((char const* const[]){"systemctl", "--user", "is-active", name.c_str(), nullptr}, &out)
            : run_cmd((char const* const[]){"systemctl", "is-active", name.c_str(), nullptr}, &out);
        st.detail = out;
        st.state = active ? ServiceState::running : (out == "inactive" || out == "failed") ? ServiceState::stopped : ServiceState::unknown;
#endif
        return st;
    }
#endif
}
