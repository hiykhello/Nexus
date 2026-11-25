// Session-only elevated launch & safe stop helpers (Linux pkexec+setpriv & Windows UAC) for desktop/src/core_supervisor.cpp.
// Included inside module desktop.core_supervisor after OS headers, `import std;`, and `core_supervisor_detail.hpp`.
#pragma once

namespace desktop::detail {
#ifdef _WIN32
    struct WinElevatedLaunchResult {
        bool ok = false;
        bool cancelled = false;
        HANDLE process = nullptr;
        std::string error;
    };

    inline auto start_elevated_win(
        std::filesystem::path const& binary,
        std::filesystem::path const& config_path,
        std::filesystem::path const& workdir,
        bool has_dir,
        std::filesystem::path const& log_path) -> WinElevatedLaunchResult {
        WinElevatedLaunchResult out{};
        std::wstring params;
        if (has_dir) {
            params += L"-D ";
            params += quote_win_arg(workdir.wstring());
            params += L" ";
        }
        params += L"run --config ";
        params += quote_win_arg(config_path.wstring());

        std::wstring const bin_w = binary.wstring();
        std::wstring const dir_w = has_dir ? workdir.wstring() : std::wstring{};

        SHELLEXECUTEINFOW sei{};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
        sei.lpVerb = L"runas";
        sei.lpFile = bin_w.c_str();
        sei.lpParameters = params.c_str();
        sei.lpDirectory = has_dir ? dir_w.c_str() : nullptr;
        sei.nShow = SW_HIDE;

        if (!::ShellExecuteExW(&sei)) {
            DWORD err = ::GetLastError();
            if (err == ERROR_CANCELLED) {
                out.cancelled = true;
                out.error = "UAC session elevation cancelled";
            } else {
                out.error = std::format("ShellExecuteExW failed ({})", err);
            }
            return out;
        }
        if (!sei.hProcess) {
            out.error = "ShellExecuteExW did not return a process handle";
            return out;
        }
        if (::WaitForSingleObject(sei.hProcess, 250) == WAIT_OBJECT_0) {
            DWORD code = 1;
            ::GetExitCodeProcess(sei.hProcess, &code);
            ::CloseHandle(sei.hProcess);
            out.error = format_win_exit_error(log_path, code);
            return out;
        }
        out.ok = true;
        out.process = sei.hProcess;
        return out;
    }

    inline auto stop_win_process(HANDLE target, HANDLE job_h, bool is_elevated) -> std::string {
        std::string err;
        auto ev_name = L"Local\\nexus-stop-" + std::to_wstring(::GetProcessId(target));
        if (HANDLE ev = ::OpenEventW(EVENT_MODIFY_STATE, FALSE, ev_name.c_str())) {
            ::SetEvent(ev);
            ::CloseHandle(ev);
            (void)::WaitForSingleObject(target, 1500);
        }
        bool exited = (::WaitForSingleObject(target, 0) == WAIT_OBJECT_0);
        if (!exited) {
            if (::TerminateProcess(target, 0)) {
                (void)::WaitForSingleObject(target, 1000);
                exited = (::WaitForSingleObject(target, 0) == WAIT_OBJECT_0);
            } else {
                DWORD term_err = ::GetLastError();
                if (is_elevated && term_err == ERROR_ACCESS_DENIED) {
                    err = "Elevated core process could not be terminated from standard user (access denied)";
                } else {
                    err = std::format("TerminateProcess failed ({})", term_err);
                }
            }
        }
        ::CloseHandle(target);
        if (job_h) ::CloseHandle(job_h);
        return exited ? std::string{} : err;
    }
#elif defined(__linux__)
    struct LinuxElevatedLaunchResult {
        bool ok = false;
        bool cancelled = false;
        pid_t wait_pid = -1;
        pid_t signal_pid = -1;
        uid_t expected_uid = 0;
        std::filesystem::path canonical_bin;
        std::string config_path;
        std::string error;
    };

    inline auto collect_direct_children(pid_t parent_pid) -> std::vector<pid_t> {
        std::vector<pid_t> kids;
        std::error_code ec;
        auto task_dir = std::filesystem::path(std::format("/proc/{}/task", static_cast<long>(parent_pid)));
        if (!std::filesystem::is_directory(task_dir, ec)) return kids;
        for (auto const& ent : std::filesystem::directory_iterator(task_dir, ec)) {
            if (ec) break;
            std::ifstream in(ent.path() / "children");
            long p = 0;
            while (in >> p) {
                if (p > 0) kids.push_back(static_cast<pid_t>(p));
            }
        }
        return kids;
    }

    inline auto read_proc_cmdline(std::filesystem::path const& proc_dir) -> std::string {
        std::ifstream in(proc_dir / "cmdline", std::ios::binary);
        if (!in) return {};
        std::string out;
        char buf[512];
        while (out.size() < 16384 && in.read(buf, sizeof(buf))) {
            out.append(buf, static_cast<std::size_t>(in.gcount()));
        }
        if (out.size() < 16384 && in.gcount() > 0) {
            out.append(buf, static_cast<std::size_t>(in.gcount()));
        }
        return out;
    }

    inline auto proc_matches_core(
        pid_t pid,
        uid_t expected_uid,
        std::filesystem::path const& canonical_bin,
        std::string_view expected_config) -> bool {
        if (pid <= 0 || canonical_bin.empty() || expected_config.empty()) return false;
        auto const proc_dir = std::filesystem::path(std::format("/proc/{}", static_cast<long>(pid)));
        struct stat st{};
        if (::stat(proc_dir.c_str(), &st) != 0 || st.st_uid != expected_uid) return false;
        auto const cmdline = read_proc_cmdline(proc_dir);
        if (!match_linux_cmdline_for_core(cmdline, canonical_bin.string(), expected_config)) return false;

        // Optional fast-path check on /proc/<pid>/exe ONLY when readable; Linux cap_ptrace_access_check
        // returns EACCES for elevated same-UID processes when caller has empty CapPrm, which is expected.
        std::error_code ec;
        auto exe = std::filesystem::read_symlink(proc_dir / "exe", ec);
        if (!ec && !exe.empty()) {
            if (exe == canonical_bin) return true;
            auto exe_str = exe.string();
            if (exe_str.ends_with(" (deleted)")) {
                exe_str.resize(exe_str.size() - 10);
                if (exe_str == canonical_bin.string()) return true;
            }
            ec.clear();
            return std::filesystem::equivalent(exe, canonical_bin, ec) && !ec;
        }
        return true;
    }

    inline auto find_elevated_core_descendant(
        pid_t root_pid,
        uid_t expected_uid,
        std::filesystem::path const& canonical_bin,
        std::string_view expected_config) -> pid_t {
        auto level1 = collect_direct_children(root_pid);
        for (pid_t p : level1) {
            if (proc_matches_core(p, expected_uid, canonical_bin, expected_config)) return p;
        }
        for (pid_t p : level1) {
            for (pid_t g : collect_direct_children(p)) {
                if (proc_matches_core(g, expected_uid, canonical_bin, expected_config)) return g;
            }
        }
        return -1;
    }

    inline auto reap_child_bounded(pid_t child, int& status, int polls = 20, int sleep_ms = 25) -> bool {
        for (int i = 0; i < polls; ++i) {
            pid_t res = ::waitpid(child, &status, WNOHANG);
            if (res == child || (res < 0 && errno == ECHILD)) return true;
            if (res < 0 && errno != EINTR) return false;
            std::this_thread::sleep_for(std::chrono::milliseconds(sleep_ms));
        }
        return false;
    }

    inline auto start_elevated_linux(
        std::filesystem::path const& binary,
        std::filesystem::path const& config_path,
        std::filesystem::path const& workdir,
        bool has_dir,
        std::filesystem::path const& log_path) -> LinuxElevatedLaunchResult {
        LinuxElevatedLaunchResult out{};
        auto const pkexec = resolve_executable_path("pkexec");
        auto const setpriv = resolve_executable_path("setpriv");
        if (!pkexec || !setpriv) {
            out.error = "pkexec or setpriv not found for session elevation";
            return out;
        }
        std::error_code canon_ec;
        auto canon_bin = std::filesystem::weakly_canonical(binary, canon_ec);
        if (canon_ec || canon_bin.empty()) canon_bin = binary;
        auto const cfg_str = config_path.string();

        uid_t const my_uid = ::getuid();
        gid_t const my_gid = ::getgid();
        auto args = build_linux_session_elevated_argv(
            canon_bin, config_path, has_dir ? workdir : std::filesystem::path{},
            static_cast<std::uint32_t>(my_uid), static_cast<std::uint32_t>(my_gid),
            pkexec->string(), setpriv->string());
        if (args.empty()) {
            out.error = "Failed to build session elevation arguments";
            return out;
        }
        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (auto& a : args) argv.push_back(a.data());
        argv.push_back(nullptr);

        int log_fd = ::open(log_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
        int devnull = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        pid_t child = ::fork();
        if (child < 0) {
            if (log_fd >= 0) ::close(log_fd);
            if (devnull >= 0) ::close(devnull);
            out.error = std::string("fork failed: ") + std::strerror(errno);
            return out;
        }
        if (child == 0) {
            if (devnull >= 0) {
                if (devnull == STDIN_FILENO) (void)::fcntl(devnull, F_SETFD, 0);
                else (void)::dup2(devnull, STDIN_FILENO);
            }
            if (log_fd >= 0) {
                if (log_fd == STDOUT_FILENO || log_fd == STDERR_FILENO) (void)::fcntl(log_fd, F_SETFD, 0);
                (void)::dup2(log_fd, STDOUT_FILENO);
                (void)::dup2(log_fd, STDERR_FILENO);
            }
            ::execv(args[0].c_str(), argv.data());
            ::_exit(127);
        }
        if (log_fd >= 0) ::close(log_fd);
        if (devnull >= 0) ::close(devnull);

        pid_t nexus_pid = -1;
        int status = 0;
        for (int i = 0; i < 1200; ++i) {
            pid_t res = ::waitpid(child, &status, WNOHANG);
            if (res == child) {
                if (WIFEXITED(status) && (WEXITSTATUS(status) == 126 || WEXITSTATUS(status) == 127)) {
                    out.cancelled = true;
                    out.error = "Polkit session elevation cancelled";
                } else {
                    out.error = format_posix_exit_error(log_path, status);
                }
                return out;
            }
            if (res < 0 && errno != EINTR) {
                out.error = std::string("waitpid failed: ") + std::strerror(errno);
                return out;
            }
            nexus_pid = find_elevated_core_descendant(child, my_uid, canon_bin, cfg_str);
            if (nexus_pid > 0) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        if (nexus_pid <= 0) {
            if (pid_t late = find_elevated_core_descendant(child, my_uid, canon_bin, cfg_str); late > 0) {
                (void)::kill(late, SIGTERM);
            }
            (void)::kill(child, SIGTERM);
            (void)reap_child_bounded(child, status, 10, 25);
            out.error = "Timed out waiting for session elevation";
            return out;
        }

        for (int i = 0; i < 5; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            pid_t res = ::waitpid(child, &status, WNOHANG);
            if (res == child) {
                out.error = format_posix_exit_error(log_path, status);
                return out;
            }
        }
        if (::kill(nexus_pid, 0) != 0) {
            bool reaped = reap_child_bounded(child, status, 20, 25);
            out.error = reaped ? format_posix_exit_error(log_path, status) : read_error_excerpt(log_path);
            if (out.error.empty()) out.error = "Elevated core exited immediately after launch";
            return out;
        }

        out.ok = true;
        out.wait_pid = child;
        out.signal_pid = nexus_pid;
        out.expected_uid = my_uid;
        out.canonical_bin = std::move(canon_bin);
        out.config_path = cfg_str;
        return out;
    }
#elif defined(__APPLE__)
    struct MacElevatedLaunchResult {
        bool ok = false;
        bool cancelled = false;
        pid_t pid = -1;
        std::filesystem::path canonical_bin;
        std::string error;
    };

    inline auto macos_pid_matches_binary(pid_t pid, std::filesystem::path const& canonical_bin) -> bool {
        if (pid <= 0 || canonical_bin.empty()) return false;
        char pathbuf[PROC_PIDPATHINFO_MAXSIZE]{};
        if (::proc_pidpath(pid, pathbuf, sizeof(pathbuf)) <= 0) return false;
        std::error_code ec;
        auto live = std::filesystem::weakly_canonical(std::filesystem::path(pathbuf), ec);
        if (ec || live.empty()) live = std::filesystem::path(pathbuf);
        if (live == canonical_bin) return true;
        ec.clear();
        return std::filesystem::equivalent(live, canonical_bin, ec) && !ec;
    }

    inline auto start_elevated_macos(
        std::filesystem::path const& binary,
        std::filesystem::path const& config_path,
        std::filesystem::path const& workdir,
        bool has_dir) -> MacElevatedLaunchResult {
        MacElevatedLaunchResult out{};
        std::error_code ec;
        auto canon_bin = std::filesystem::weakly_canonical(binary, ec);
        if (ec || canon_bin.empty()) canon_bin = binary;

        auto q_bin = quote_posix_sh_arg(canon_bin.string());
        auto q_cfg = quote_posix_sh_arg(config_path.string());
        if (!q_bin || !q_cfg) { out.error = "Invalid characters in launch path"; return out; }

        std::string sh = *q_bin;
        if (has_dir) {
            auto q_wd = quote_posix_sh_arg(workdir.string());
            if (!q_wd) { out.error = "Invalid characters in workdir path"; return out; }
            sh += " -D " + *q_wd;
        }
        sh += " run --config " + *q_cfg + " >/dev/null 2>&1 </dev/null & echo $!";
        auto esc = escape_applescript_string(sh);
        if (!esc) { out.error = esc.error(); return out; }

        auto const exec = run_posix_execv_capture({"/usr/bin/osascript", "-e",
            std::format("do shell script \"{}\" with administrator privileges", *esc)});
        if (!exec.launched) { out.error = "Failed to launch osascript"; return out; }
        if (exec.exit_code != 0) {
            if (exec.output.contains("-128") || exec.output.contains("User canceled") || exec.output.contains("User cancelled")) {
                out.cancelled = true;
                out.error = "macOS administrator authorization cancelled";
            } else {
                out.error = exec.output.empty() ? std::format("osascript failed (exit {})", exec.exit_code) : exec.output;
            }
            return out;
        }
        std::string_view sv(exec.output);
        while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t' || sv.front() == '\r' || sv.front() == '\n')) sv.remove_prefix(1);
        while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r' || sv.back() == '\n')) sv.remove_suffix(1);
        long parsed_pid = 0;
        auto [ptr, pec] = std::from_chars(sv.data(), sv.data() + sv.size(), parsed_pid, 10);
        if (pec != std::errc{} || ptr != sv.data() + sv.size() || parsed_pid <= 0) {
            out.error = "Failed to capture elevated macOS core PID";
            return out;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (!macos_pid_matches_binary(static_cast<pid_t>(parsed_pid), canon_bin)) {
            out.error = "Elevated core exited immediately after launch";
            return out;
        }
        out.ok = true;
        out.pid = static_cast<pid_t>(parsed_pid);
        out.canonical_bin = std::move(canon_bin);
        return out;
    }

    inline auto stop_elevated_macos(pid_t pid, std::filesystem::path const& canonical_bin) -> void {
        if (!macos_pid_matches_binary(pid, canonical_bin)) return;
        if (::kill(pid, SIGTERM) == 0) {
            for (int i = 0; i < 30; ++i) {
                if (!macos_pid_matches_binary(pid, canonical_bin)) return;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            if (macos_pid_matches_binary(pid, canonical_bin)) (void)::kill(pid, SIGKILL);
            return;
        }
        if (!macos_pid_matches_binary(pid, canonical_bin)) return;
        auto pid_str = std::to_string(static_cast<long>(pid));
        std::array<std::string_view, 3> kill_argv{"/bin/kill", "-TERM", pid_str};
        if (auto script = build_macos_osascript_admin_script(kill_argv)) {
            (void)run_posix_execv_capture({"/usr/bin/osascript", "-e", *script});
        }
    }
#endif

#ifndef _WIN32
    inline auto stop_posix_process(
        pid_t wait_pid,
        pid_t sig_pid,
        uid_t expected_uid,
        std::filesystem::path const& canonical_bin,
        std::string_view expected_config) -> void {
        int status = 0;
        pid_t early = ::waitpid(wait_pid, &status, WNOHANG);
        if (early == wait_pid || (early < 0 && errno == ECHILD)) return;

        bool const is_grandchild = (sig_pid > 0 && sig_pid != wait_pid);
        auto can_signal = [&]() -> bool {
            if (!is_grandchild) return true;
#ifdef __linux__
            return proc_matches_core(sig_pid, expected_uid, canonical_bin, expected_config);
#else
            (void)expected_uid; (void)canonical_bin; (void)expected_config;
            return true;
#endif
        };

        if (can_signal()) (void)::kill(sig_pid, SIGTERM);
        for (int i = 0; i < 30; ++i) {
            pid_t res = ::waitpid(wait_pid, &status, WNOHANG);
            if (res == wait_pid || (res < 0 && errno == ECHILD)) return;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        if (can_signal()) (void)::kill(sig_pid, SIGKILL);
        if (!is_grandchild) {
            while (::waitpid(wait_pid, &status, 0) < 0 && errno == EINTR) {}
        } else {
            for (int i = 0; i < 40; ++i) {
                pid_t res = ::waitpid(wait_pid, &status, WNOHANG);
                if (res == wait_pid || (res < 0 && errno == ECHILD)) return;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
    }
#endif
}
