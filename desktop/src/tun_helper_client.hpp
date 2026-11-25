// Persistent TUN helper client IPC (Windows Named Pipe / macOS Unix Socket) & binary resolution.
// Included inside module desktop.tun_privilege / desktop.core_supervisor after OS headers, `import std;`, and `import desktop.tun_helper_protocol;`.
#pragma once

namespace desktop::detail {
    inline auto resolve_tun_helper_binary(std::filesystem::path const& core_binary) -> std::optional<std::filesystem::path> {
#ifdef _WIN32
        constexpr std::string_view kHelperName = "nexus-tun-helper.exe";
#elif defined(__APPLE__)
        constexpr std::string_view kHelperName = "nexus-tun-helper";
#else
        (void)core_binary;
        return std::nullopt;
#endif
#if defined(_WIN32) || defined(__APPLE__)
        auto check_dir = [&](std::filesystem::path const& dir) -> std::optional<std::filesystem::path> {
            if (dir.empty()) return std::nullopt;
            std::error_code ec;
            auto candidate = dir / kHelperName;
            if (!std::filesystem::is_regular_file(candidate, ec)) return std::nullopt;
#ifndef _WIN32
            if (::access(candidate.c_str(), X_OK) != 0) return std::nullopt;
#endif
            auto canon = std::filesystem::weakly_canonical(candidate, ec);
            return (!ec && !canon.empty()) ? canon : candidate;
        };
        if (!core_binary.empty()) {
            if (auto found = check_dir(core_binary.parent_path())) return found;
        }
#ifdef _WIN32
        wchar_t self_buf[MAX_PATH]{};
        if (DWORD len = ::GetModuleFileNameW(nullptr, self_buf, MAX_PATH); len > 0 && len < MAX_PATH) {
            if (auto found = check_dir(std::filesystem::path(self_buf).parent_path())) return found;
        }
#elif defined(__APPLE__)
        std::uint32_t sz = 0;
        (void)::_NSGetExecutablePath(nullptr, &sz);
        if (sz > 0 && sz < 4096) {
            std::string buf(sz, '\0');
            if (::_NSGetExecutablePath(buf.data(), &sz) == 0) {
                if (auto found = check_dir(std::filesystem::path(buf.c_str()).parent_path())) return found;
            }
        }
#endif
        return std::nullopt;
#endif
    }

#ifdef _WIN32
    inline auto utf8_to_wide_helper(std::string_view s) -> std::wstring {
        if (s.empty()) return {};
        int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
        if (n <= 0) return {};
        std::wstring out(static_cast<std::size_t>(n), L'\0');
        ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
        return out;
    }

    inline auto wide_to_utf8_helper(std::wstring_view ws) -> std::string {
        if (ws.empty()) return {};
        int n = ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
        if (n <= 0) return {};
        std::string out(static_cast<std::size_t>(n), '\0');
        ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), out.data(), n, nullptr, nullptr);
        return out;
    }

    inline auto quote_win_param_helper(std::wstring_view arg) -> std::wstring {
        std::wstring out{L'"'};
        std::size_t bs = 0;
        for (wchar_t ch : arg) {
            if (ch == L'\\') { ++bs; }
            else if (ch == L'"') { out.append(bs * 2 + 1, L'\\'); out.push_back(L'"'); bs = 0; }
            else { if (bs > 0) { out.append(bs, L'\\'); bs = 0; } out.push_back(ch); }
        }
        if (bs > 0) out.append(bs * 2, L'\\');
        out.push_back(L'"');
        return out;
    }

    inline auto win_current_user_sid_string() -> std::optional<std::string> {
        HANDLE tok = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tok)) return std::nullopt;
        DWORD needed = 0;
        (void)::GetTokenInformation(tok, TokenUser, nullptr, 0, &needed);
        if (needed == 0 || needed > 4096) { ::CloseHandle(tok); return std::nullopt; }
        std::vector<std::byte> buf(needed);
        bool ok = ::GetTokenInformation(tok, TokenUser, buf.data(), needed, &needed) != FALSE;
        ::CloseHandle(tok);
        if (!ok) return std::nullopt;
        auto const* user = reinterpret_cast<TOKEN_USER const*>(buf.data());
        LPWSTR sid_w = nullptr;
        if (!::ConvertSidToStringSidW(user->User.Sid, &sid_w) || !sid_w) return std::nullopt;
        auto out = wide_to_utf8_helper(sid_w);
        ::LocalFree(sid_w);
        return validate_windows_sid(out) ? std::optional<std::string>(std::move(out)) : std::nullopt;
    }

    inline auto win_read_reg_str(HKEY key, wchar_t const* name) -> std::optional<std::string> {
        DWORD type = 0;
        DWORD bytes = 0;
        if (::RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
            type != REG_SZ || bytes < sizeof(wchar_t) || bytes > 32768) {
            return std::nullopt;
        }
        std::wstring buf(bytes / sizeof(wchar_t), L'\0');
        if (::RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(buf.data()), &bytes) != ERROR_SUCCESS) {
            return std::nullopt;
        }
        while (!buf.empty() && buf.back() == L'\0') buf.pop_back();
        return wide_to_utf8_helper(buf);
    }

    inline auto win_read_pinned_helper_config() -> std::optional<TunHelperPinnedConfig> {
        HKEY key = nullptr;
        auto subkey = utf8_to_wide_helper(kWinTunHelperRegSubkey);
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
            return std::nullopt;
        }
        TunHelperPinnedConfig cfg{};
        auto bin = win_read_reg_str(key, L"Binary");
        auto staged = win_read_reg_str(key, L"StagedBinary");
        auto sha = win_read_reg_str(key, L"Sha256");
        auto cfg_p = win_read_reg_str(key, L"Config");
        auto wd = win_read_reg_str(key, L"Workdir");
        auto sid = win_read_reg_str(key, L"OwnerSid");
        ::RegCloseKey(key);
        if (!bin || !staged || staged->empty() || !sha || !cfg_p || !sid || !is_valid_sha256_hex(*sha)) return std::nullopt;
        cfg.binary = std::move(*bin);
        cfg.sha256 = std::move(*sha);
        cfg.config = std::move(*cfg_p);
        cfg.workdir = wd.value_or(std::string{});
        cfg.owner = std::move(*sid);
        cfg.staged_binary = std::move(*staged);
        return cfg;
    }

    inline auto win_pipe_overlapped_wait(HANDLE pipe, OVERLAPPED& ov, HANDLE ev, BOOL initial_ok, DWORD timeout_ms, DWORD& n) -> bool {
        if (initial_ok) return true;
        if (::GetLastError() != ERROR_IO_PENDING) { n = 0; return false; }
        if (::WaitForSingleObject(ev, timeout_ms) == WAIT_OBJECT_0) {
            if (::GetOverlappedResult(pipe, &ov, &n, FALSE)) return true;
            n = 0; return false;
        }
        (void)::CancelIoEx(pipe, &ov);
        (void)::GetOverlappedResult(pipe, &ov, &n, TRUE);
        n = 0; return false;
    }

    inline auto tun_helper_rpc(TunHelperCommand cmd, int timeout_ms = 5000) -> TunHelperReply {
        TunHelperReply err{};
        DWORD const io_timeout = static_cast<DWORD>(std::max(250, timeout_ms));
        auto const pipe_w = utf8_to_wide_helper(kWinTunHelperPipeName);
        HANDLE pipe = INVALID_HANDLE_VALUE;
        for (int attempt = 0; attempt < 5; ++attempt) {
            pipe = ::CreateFileW(
                pipe_w.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
            if (pipe != INVALID_HANDLE_VALUE) break;
            DWORD open_err = ::GetLastError();
            if (open_err == ERROR_PIPE_BUSY) {
                (void)::WaitNamedPipeW(pipe_w.c_str(), static_cast<DWORD>(std::max(200, timeout_ms / 5)));
                continue;
            }
            err.detail = std::format("helper pipe unavailable ({})", open_err);
            return err;
        }
        if (pipe == INVALID_HANDLE_VALUE) { err.detail = "helper pipe busy"; return err; }

        PSID owner_sid = nullptr;
        PSECURITY_DESCRIPTOR sec_desc = nullptr;
        bool const owner_ok = (::GetSecurityInfo(pipe, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
                                                 &owner_sid, nullptr, nullptr, nullptr, &sec_desc) == ERROR_SUCCESS)
                           && owner_sid != nullptr
                           && (::IsWellKnownSid(owner_sid, WinLocalSystemSid) || ::IsWellKnownSid(owner_sid, WinBuiltinAdministratorsSid));
        if (sec_desc) ::LocalFree(sec_desc);
        if (!owner_ok) {
            ::CloseHandle(pipe);
            err.detail = "helper pipe owner is not SYSTEM or Administrators";
            return err;
        }

        HANDLE ev = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ev) { ::CloseHandle(pipe); err.detail = "CreateEventW failed"; return err; }

        std::string req(format_tun_helper_request(cmd));
        req.push_back('\n');
        OVERLAPPED ov{}; ov.hEvent = ev;
        DWORD written = 0;
        if (!win_pipe_overlapped_wait(pipe, ov, ev, ::WriteFile(pipe, req.data(), static_cast<DWORD>(req.size()), &written, &ov), io_timeout, written) ||
            written != req.size()) {
            err.detail = "helper pipe write failed or timed out";
            ::CloseHandle(ev); ::CloseHandle(pipe);
            return err;
        }
        std::string resp;
        char buf[256];
        while (resp.size() < kTunHelperMaxReplyBytes) {
            ::ResetEvent(ev);
            ov = {}; ov.hEvent = ev;
            DWORD read_n = 0;
            if (!win_pipe_overlapped_wait(pipe, ov, ev, ::ReadFile(pipe, buf, sizeof(buf), &read_n, &ov), io_timeout, read_n) || read_n == 0) break;
            resp.append(buf, read_n);
            if (resp.contains('\n')) break;
        }
        ::CloseHandle(ev);
        ::CloseHandle(pipe);
        return parse_tun_helper_reply(resp);
    }

    inline auto run_win_uac_process(std::wstring const& file, std::wstring const& params, int timeout_ms = 30000)
        -> std::pair<bool, DWORD> {
        SHELLEXECUTEINFOW sei{};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
        sei.lpVerb = L"runas";
        sei.lpFile = file.c_str();
        sei.lpParameters = params.c_str();
        sei.nShow = SW_HIDE;
        if (!::ShellExecuteExW(&sei)) return {false, ::GetLastError()};
        DWORD exit_code = 1;
        if (sei.hProcess) {
            ::WaitForSingleObject(sei.hProcess, static_cast<DWORD>(timeout_ms));
            ::GetExitCodeProcess(sei.hProcess, &exit_code);
            ::CloseHandle(sei.hProcess);
        }
        return {true, exit_code};
    }
#elif defined(__APPLE__)
    inline auto macos_read_verified_pinned_config() -> std::optional<TunHelperPinnedConfig> {
        struct stat st{};
        std::string const path(kMacTunHelperConfigPath);
        if (::lstat(path.c_str(), &st) != 0) return std::nullopt;
        if (!S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 0022) != 0) return std::nullopt;
        std::ifstream in(path, std::ios::binary);
        if (!in) return std::nullopt;
        std::ostringstream ss;
        ss << in.rdbuf();
        auto parsed = parse_tun_helper_config(ss.str());
        if (!parsed) return std::nullopt;
        return *parsed;
    }

    inline auto tun_helper_rpc(TunHelperCommand cmd, int timeout_ms = 5000) -> TunHelperReply {
        TunHelperReply err{};
        int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) { err.detail = "socket() failed"; return err; }
        (void)::fcntl(fd, F_SETFD, FD_CLOEXEC);
        struct timeval tv{};
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        if (kMacTunHelperSocketPath.size() >= sizeof(addr.sun_path)) { ::close(fd); err.detail = "socket path too long"; return err; }
        std::memcpy(addr.sun_path, kMacTunHelperSocketPath.data(), kMacTunHelperSocketPath.size());
        if (::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            err.detail = "helper socket unavailable";
            ::close(fd);
            return err;
        }
        uid_t peer_uid = static_cast<uid_t>(-1);
        gid_t peer_gid = static_cast<gid_t>(-1);
        if (::getpeereid(fd, &peer_uid, &peer_gid) != 0 || peer_uid != 0) {
            err.detail = "helper socket peer is not root";
            ::close(fd);
            return err;
        }
        std::string req(format_tun_helper_request(cmd));
        req.push_back('\n');
        std::size_t sent = 0;
        while (sent < req.size()) {
            auto n = ::send(fd, req.data() + sent, req.size() - sent, 0);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { ::close(fd); err.detail = "helper socket send failed"; return err; }
            sent += static_cast<std::size_t>(n);
        }
        std::string resp;
        char buf[256];
        while (resp.size() < kTunHelperMaxReplyBytes) {
            auto n = ::recv(fd, buf, sizeof(buf), 0);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            resp.append(buf, static_cast<std::size_t>(n));
            if (resp.contains('\n')) break;
        }
        ::close(fd);
        return parse_tun_helper_reply(resp);
    }
#else
    inline auto tun_helper_rpc(TunHelperCommand, int = 5000) -> TunHelperReply {
        return {false, false, 0, "persistent helper not used on this platform"};
    }
#endif

#ifndef _WIN32
    struct PosixExecCapture {
        bool launched = false;
        int exit_code = -1;
        std::string output;
    };

    inline auto run_posix_execv_capture(std::vector<std::string> const& args) -> PosixExecCapture {
        PosixExecCapture res{};
        if (args.empty() || args[0].empty()) return res;
        int pipefd[2]{-1, -1};
        if (::pipe(pipefd) != 0) return res;
        (void)::fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
        (void)::fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (auto const& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        int devnull = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        pid_t child = ::fork();
        if (child < 0) {
            if (devnull >= 0) ::close(devnull);
            ::close(pipefd[0]); ::close(pipefd[1]);
            return res;
        }
        if (child == 0) {
            ::close(pipefd[0]);
            if (devnull >= 0) {
                if (devnull == STDIN_FILENO) (void)::fcntl(devnull, F_SETFD, 0);
                else (void)::dup2(devnull, STDIN_FILENO);
            }
            if (pipefd[1] == STDOUT_FILENO || pipefd[1] == STDERR_FILENO) (void)::fcntl(pipefd[1], F_SETFD, 0);
            (void)::dup2(pipefd[1], STDOUT_FILENO); (void)::dup2(pipefd[1], STDERR_FILENO);
            ::execv(args[0].c_str(), argv.data());
            ::_exit(127);
        }
        if (devnull >= 0) ::close(devnull);
        ::close(pipefd[1]);
        res.launched = true;
        char buf[512];
        for (;;) {
            auto n = ::read(pipefd[0], buf, sizeof(buf));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            if (res.output.size() < 4096) res.output.append(buf, static_cast<std::size_t>(n));
        }
        ::close(pipefd[0]);
        int status = 0;
        while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        if (WIFEXITED(status)) res.exit_code = WEXITSTATUS(status);
        else if (WIFSIGNALED(status)) res.exit_code = 128 + WTERMSIG(status);
        while (!res.output.empty() && (res.output.back() == ' ' || res.output.back() == '\t' || res.output.back() == '\r' || res.output.back() == '\n')) {
            res.output.pop_back();
        }
        return res;
    }
#ifdef __APPLE__
    inline auto run_macos_osascript_argv(
        std::vector<std::string> const& args,
        std::string const& osascript_path) -> std::tuple<bool, bool, std::string> {
        std::vector<std::string_view> views;
        views.reserve(args.size());
        for (auto const& a : args) views.push_back(a);
        auto script = build_macos_osascript_admin_script(views);
        if (!script) return {false, false, script.error()};
        auto const exec = run_posix_execv_capture({osascript_path, "-e", *script});
        if (!exec.launched) return {false, false, "Failed to launch osascript"};
        if (exec.exit_code != 0) {
            bool const cancelled = exec.output.contains("-128") || exec.output.contains("User canceled") || exec.output.contains("User cancelled");
            return {false, cancelled, exec.output};
        }
        return {true, false, {}};
    }
#endif
#endif
}
