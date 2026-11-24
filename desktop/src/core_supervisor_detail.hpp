// Internal process-capture and exit-formatting helpers for desktop/src/core_supervisor.cpp.
// Included inside module desktop.core_supervisor after OS headers and `import std;`.
#pragma once

namespace desktop::detail {
    inline auto read_error_excerpt(std::filesystem::path const& path) -> std::string {
        std::ifstream in(path, std::ios::binary);
        if (!in) return {};
        std::string raw(512, '\0');
        in.read(raw.data(), static_cast<std::streamsize>(raw.size()));
        raw.resize(static_cast<std::size_t>(in.gcount()));

        std::string out;
        out.reserve(raw.size());
        bool prev_space = true;
        for (unsigned char ch : raw) {
            if (ch == '\r' || ch == '\n' || ch == '\t' || ch == ' ') {
                if (!prev_space) {
                    out.push_back(' ');
                    prev_space = true;
                }
            } else {
                out.push_back(static_cast<char>(ch));
                prev_space = false;
            }
        }
        while (!out.empty() && out.back() == ' ') out.pop_back();
        if (out.size() > 220) { out.resize(217); out += "..."; }
        return out;
    }

#ifdef _WIN32
    inline auto utf8_to_wide(std::string_view text) -> std::wstring {
        if (text.empty()) return {};
        int len = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
        if (len <= 0) return {};
        std::wstring out(static_cast<std::size_t>(len), L'\0');
        ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(), len);
        return out;
    }

    inline auto quote_win_arg(std::wstring_view arg) -> std::wstring {
        std::wstring out;
        out.reserve(arg.size() + 4);
        out.push_back(L'"');
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

    inline auto build_win_cmdline(std::vector<std::wstring> const& args) -> std::wstring {
        std::wstring cmd;
        for (std::size_t i = 0; i < args.size(); ++i) {
            if (i > 0) cmd.push_back(L' ');
            cmd += quote_win_arg(args[i]);
        }
        return cmd;
    }

    inline auto format_win_exit_error(std::filesystem::path const& log_path, DWORD code) -> std::string {
        if (auto excerpt = read_error_excerpt(log_path); !excerpt.empty()) return excerpt;
        return std::format("exit code {}", code);
    }

    inline auto run_capture_win(std::vector<std::wstring> const& args, std::string_view ok_fallback,
                                std::string_view fail_fallback) -> ValidationResult {
        SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
        HANDLE read_pipe = nullptr, write_pipe = nullptr;
        bool has_pipe = ::CreatePipe(&read_pipe, &write_pipe, &sa, 0) != FALSE;
        if (has_pipe) (void)::SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        if (has_pipe) {
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = INVALID_HANDLE_VALUE;
            si.hStdOutput = write_pipe;
            si.hStdError = write_pipe;
        }
        auto cmd = build_win_cmdline(args);
        PROCESS_INFORMATION pi{};
        if (!::CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, has_pipe ? TRUE : FALSE,
                              CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            if (has_pipe) { ::CloseHandle(read_pipe); ::CloseHandle(write_pipe); }
            return {false, std::string(fail_fallback)};
        }
        if (has_pipe) ::CloseHandle(write_pipe);

        std::string output;
        bool timed_out = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        for (;;) {
            if (has_pipe) {
                DWORD avail = 0;
                while (::PeekNamedPipe(read_pipe, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
                    char buf[512];
                    DWORD got = 0;
                    if (!::ReadFile(read_pipe, buf, std::min<DWORD>(avail, sizeof(buf)), &got, nullptr) || got == 0) break;
                    if (output.size() < 4096) output.append(buf, got);
                }
            }
            if (::WaitForSingleObject(pi.hProcess, 25) == WAIT_OBJECT_0) break;
            if (std::chrono::steady_clock::now() >= deadline) {
                timed_out = true;
                ::TerminateProcess(pi.hProcess, 1);
                ::WaitForSingleObject(pi.hProcess, 1000);
                break;
            }
        }
        if (has_pipe) {
            DWORD avail = 0;
            while (::PeekNamedPipe(read_pipe, nullptr, 0, nullptr, &avail, nullptr) && avail > 0) {
                char buf[512];
                DWORD got = 0;
                if (!::ReadFile(read_pipe, buf, std::min<DWORD>(avail, sizeof(buf)), &got, nullptr) || got == 0) break;
                if (output.size() < 4096) output.append(buf, got);
            }
            ::CloseHandle(read_pipe);
        }
        DWORD exit_code = 1;
        ::GetExitCodeProcess(pi.hProcess, &exit_code);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        if (timed_out) return {false, "core check timed out"};
        while (!output.empty() && (output.back() == '\n' || output.back() == '\r')) output.pop_back();
        bool ok = exit_code == 0;
        return {ok, output.empty() ? std::string(ok ? ok_fallback : fail_fallback) : std::move(output)};
    }
#else
    inline auto format_posix_exit_error(std::filesystem::path const& log_path, int status) -> std::string {
        if (auto excerpt = read_error_excerpt(log_path); !excerpt.empty()) return excerpt;
        if (WIFEXITED(status)) return std::format("exit code {}", WEXITSTATUS(status));
        if (WIFSIGNALED(status)) return std::format("signal {}", WTERMSIG(status));
        return "process terminated";
    }

    inline auto run_capture_posix(std::vector<std::string> args, std::string_view ok_fallback,
                                  std::string_view fail_fallback) -> ValidationResult {
        int pipefd[2]{-1, -1};
        if (::pipe(pipefd) != 0) return {false, "pipe failed"};
        (void)::fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
        (void)::fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);

        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (auto& a : args) argv.push_back(a.data());
        argv.push_back(nullptr);
        int devnull = ::open("/dev/null", O_RDONLY | O_CLOEXEC);

        pid_t child = ::fork();
        if (child < 0) {
            if (devnull >= 0) ::close(devnull);
            ::close(pipefd[0]);
            ::close(pipefd[1]);
            return {false, "fork failed"};
        }
        if (child == 0) {
            ::close(pipefd[0]);
            if (devnull >= 0) {
                if (devnull == STDIN_FILENO) (void)::fcntl(devnull, F_SETFD, 0);
                else (void)::dup2(devnull, STDIN_FILENO);
            }
            if (pipefd[1] == STDOUT_FILENO || pipefd[1] == STDERR_FILENO) (void)::fcntl(pipefd[1], F_SETFD, 0);
            (void)::dup2(pipefd[1], STDOUT_FILENO);
            (void)::dup2(pipefd[1], STDERR_FILENO);
            ::execv(args[0].c_str(), argv.data());
            ::_exit(127);
        }
        if (devnull >= 0) ::close(devnull);
        ::close(pipefd[1]);
        std::string output;
        char buf[512];
        bool timed_out = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        for (;;) {
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) { timed_out = true; break; }
            int rem_ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
            pollfd pfd{pipefd[0], POLLIN, 0};
            int pr = ::poll(&pfd, 1, std::max(1, rem_ms));
            if (pr < 0) { if (errno == EINTR) continue; break; }
            if (pr == 0) { timed_out = true; break; }
            auto n = ::read(pipefd[0], buf, sizeof(buf));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            if (output.size() < 4096) output.append(buf, static_cast<std::size_t>(n));
        }
        ::close(pipefd[0]);
        if (timed_out) ::kill(child, SIGKILL);
        int status = 0;
        while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        if (timed_out) return {false, "core check timed out"};
        while (!output.empty() && (output.back() == '\n' || output.back() == '\r')) output.pop_back();
        bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        return {ok, output.empty() ? std::string(ok ? ok_fallback : fail_fallback) : std::move(output)};
    }
#endif
}
