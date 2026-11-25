// Private bounded subprocess runner and RAII 0600 wiped temp-file helper included by desktop/src/workspace_sync.cpp.
#pragma once

namespace desktop::ws_sync_detail {
    constexpr std::size_t kMaxSyncStdoutBytes = 16u * 1024u * 1024u;
    constexpr auto kSyncProcTimeout = std::chrono::seconds(15);

    inline auto path_to_utf8(std::filesystem::path const& p) -> std::string {
        auto u8 = p.u8string();
        return std::string(reinterpret_cast<char const*>(u8.data()), u8.size());
    }

    // RAII transient 0600 file that zeroes its content on disk and unlinks immediately on scope exit.
    class ScopedSecretTempFile {
        std::filesystem::path path_;
        std::size_t len_ = 0;
    public:
        ScopedSecretTempFile() = default;
        ~ScopedSecretTempFile() { wipe_and_remove(); }
        ScopedSecretTempFile(ScopedSecretTempFile const&) = delete;
        auto operator=(ScopedSecretTempFile const&) -> ScopedSecretTempFile& = delete;

        auto create(std::filesystem::path const& dir, std::string_view prefix, std::string_view content) -> bool {
            wipe_and_remove();
            std::error_code ec;
            auto base_dir = dir.empty() ? std::filesystem::temp_directory_path(ec) : dir;
            if (base_dir.empty()) return false;
            std::filesystem::create_directories(base_dir, ec);
#ifndef _WIN32
            if (!dir.empty()) (void)::chmod(base_dir.c_str(), 0700);
#endif
            static std::atomic<std::uint64_t> seq{0};
            auto const n = seq.fetch_add(1, std::memory_order_relaxed);
#ifdef _WIN32
            auto cand = base_dir / std::format(".{}.{}.{}.tmp", prefix, ::GetCurrentProcessId(), n);
            HANDLE hf = ::CreateFileW(cand.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hf == INVALID_HANDLE_VALUE) return false;
            std::size_t off = 0;
            bool ok = true;
            while (off < content.size()) {
                DWORD chunk = static_cast<DWORD>(std::min<std::size_t>(content.size() - off, 1u << 20));
                DWORD written = 0;
                if (!::WriteFile(hf, content.data() + off, chunk, &written, nullptr) || written == 0) { ok = false; break; }
                off += written;
            }
            ::CloseHandle(hf);
            if (!ok) { std::filesystem::remove(cand, ec); return false; }
            path_ = std::move(cand);
            len_ = content.size();
            return true;
#else
            auto cand = base_dir / std::format(".{}.{}.{}.tmp", prefix, ::getpid(), n);
            int fd = ::open(cand.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (fd < 0) return false;
            if (::fchmod(fd, 0600) != 0) { ::close(fd); ::unlink(cand.c_str()); return false; }
            std::size_t off = 0;
            while (off < content.size()) {
                auto w = ::write(fd, content.data() + off, content.size() - off);
                if (w < 0 && errno == EINTR) continue;
                if (w <= 0) { ::close(fd); ::unlink(cand.c_str()); return false; }
                off += static_cast<std::size_t>(w);
            }
            if (::close(fd) != 0) { ::unlink(cand.c_str()); return false; }
            path_ = std::move(cand);
            len_ = content.size();
            return true;
#endif
        }

        auto path() const noexcept -> std::filesystem::path const& { return path_; }

        auto wipe_and_remove() noexcept -> void {
            if (path_.empty()) return;
            std::error_code ec;
            if (len_ > 0) {
                std::array<char, 512> zeros{};
#ifdef _WIN32
                HANDLE hf = ::CreateFileW(path_.c_str(), GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hf != INVALID_HANDLE_VALUE) {
                    std::size_t rem = len_;
                    while (rem > 0) {
                        DWORD chunk = static_cast<DWORD>(std::min(rem, zeros.size()));
                        DWORD w = 0;
                        if (!::WriteFile(hf, zeros.data(), chunk, &w, nullptr) || w == 0) break;
                        rem -= w;
                    }
                    ::CloseHandle(hf);
                }
#else
                int fd = ::open(path_.c_str(), O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
                if (fd >= 0) {
                    std::size_t rem = len_;
                    while (rem > 0) {
                        auto w = ::write(fd, zeros.data(), std::min(rem, zeros.size()));
                        if (w <= 0) break;
                        rem -= static_cast<std::size_t>(w);
                    }
                    ::close(fd);
                }
#endif
            }
            std::filesystem::remove(path_, ec);
            path_.clear();
            len_ = 0;
        }
    };

#ifdef _WIN32
    inline auto utf8_to_wide(std::string_view s) -> std::wstring {
        if (s.empty()) return {};
        int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
        if (n <= 0) return {};
        std::wstring out(static_cast<std::size_t>(n), L'\0');
        ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
        return out;
    }

    inline auto quote_win_arg(std::wstring_view arg) -> std::wstring {
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

    inline auto run_core_sync_proc(std::vector<std::string> const& args) -> std::tuple<bool, int, std::string> {
        SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
        HANDLE r_pipe = nullptr, w_pipe = nullptr;
        if (!::CreatePipe(&r_pipe, &w_pipe, &sa, 0)) return {false, -1, "CreatePipe failed"};
        (void)::SetHandleInformation(r_pipe, HANDLE_FLAG_INHERIT, 0);

        std::wstring cmdline;
        for (std::size_t i = 0; i < args.size(); ++i) {
            if (i > 0) cmdline.push_back(L' ');
            cmdline += quote_win_arg(utf8_to_wide(args[i]));
        }
        auto bin_w = utf8_to_wide(args[0]);
        HANDLE nul_h = ::CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        STARTUPINFOW si{}; si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = (nul_h != INVALID_HANDLE_VALUE) ? nul_h : INVALID_HANDLE_VALUE;
        si.hStdOutput = w_pipe;
        si.hStdError = (nul_h != INVALID_HANDLE_VALUE) ? nul_h : INVALID_HANDLE_VALUE;

        PROCESS_INFORMATION pi{};
        BOOL created = ::CreateProcessW(bin_w.c_str(), cmdline.data(), nullptr, nullptr, TRUE,
                                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
        ::CloseHandle(w_pipe);
        if (nul_h != INVALID_HANDLE_VALUE) ::CloseHandle(nul_h);
        if (!created) { ::CloseHandle(r_pipe); return {false, -1, std::format("CreateProcessW failed ({})", ::GetLastError())}; }
        ::CloseHandle(pi.hThread);

        auto const deadline = std::chrono::steady_clock::now() + kSyncProcTimeout;
        std::string out;
        char buf[4096];
        bool timed_out = false;
        auto drain = [&] {
            for (;;) {
                DWORD avail = 0;
                if (!::PeekNamedPipe(r_pipe, nullptr, 0, nullptr, &avail, nullptr) || avail == 0) break;
                DWORD want = static_cast<DWORD>(std::min<std::size_t>(sizeof(buf), avail));
                DWORD n = 0;
                if (!::ReadFile(r_pipe, buf, want, &n, nullptr) || n == 0) break;
                if (out.size() < kMaxSyncStdoutBytes) {
                    out.append(buf, std::min<std::size_t>(n, kMaxSyncStdoutBytes - out.size()));
                }
            }
        };
        for (;;) {
            drain();
            if (::WaitForSingleObject(pi.hProcess, 25) == WAIT_OBJECT_0) { drain(); break; }
            if (std::chrono::steady_clock::now() >= deadline) {
                timed_out = true;
                ::TerminateProcess(pi.hProcess, 1);
                (void)::WaitForSingleObject(pi.hProcess, 2000);
                break;
            }
        }
        ::CloseHandle(r_pipe);
        DWORD code = 1;
        if (!timed_out) ::GetExitCodeProcess(pi.hProcess, &code);
        ::CloseHandle(pi.hProcess);
        if (timed_out) return {false, -1, "core process timed out after 15s"};
        return {true, static_cast<int>(code), std::move(out)};
    }
#else
    inline auto run_core_sync_proc(std::vector<std::string> const& args) -> std::tuple<bool, int, std::string> {
        int pipefd[2]{-1, -1};
        if (::pipe(pipefd) != 0) return {false, -1, "pipe() failed"};
        (void)::fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
        (void)::fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);

        std::vector<char*> argv;
        argv.reserve(args.size() + 1);
        for (auto const& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);

        int devnull = ::open("/dev/null", O_RDWR | O_CLOEXEC);
        pid_t child = ::fork();
        if (child < 0) {
            if (devnull >= 0) ::close(devnull);
            ::close(pipefd[0]); ::close(pipefd[1]);
            return {false, -1, "fork() failed"};
        }
        if (child == 0) {
            ::close(pipefd[0]);
            if (devnull >= 0) {
                if (devnull == STDIN_FILENO) (void)::fcntl(devnull, F_SETFD, 0); else (void)::dup2(devnull, STDIN_FILENO);
                if (devnull == STDERR_FILENO) (void)::fcntl(devnull, F_SETFD, 0); else (void)::dup2(devnull, STDERR_FILENO);
            }
            if (pipefd[1] == STDOUT_FILENO) (void)::fcntl(pipefd[1], F_SETFD, 0); else (void)::dup2(pipefd[1], STDOUT_FILENO);
            ::execv(args[0].c_str(), argv.data());
            ::_exit(127);
        }
        if (devnull >= 0) ::close(devnull);
        ::close(pipefd[1]);

        int flags = ::fcntl(pipefd[0], F_GETFL, 0);
        if (flags >= 0) (void)::fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
        auto const deadline = std::chrono::steady_clock::now() + kSyncProcTimeout;
        std::string out;
        char buf[4096];
        bool timed_out = false, eof = false;
        while (!eof) {
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) { timed_out = true; break; }
            int rem_ms = static_cast<int>(std::min<std::int64_t>(200, std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count()));
            struct pollfd pfd{pipefd[0], POLLIN, 0};
            int pr = ::poll(&pfd, 1, std::max(1, rem_ms));
            if (pr < 0 && errno == EINTR) continue;
            if (pr < 0) break;
            if (pr == 0) continue;
            for (;;) {
                auto n = ::read(pipefd[0], buf, sizeof(buf));
                if (n > 0) {
                    if (out.size() < kMaxSyncStdoutBytes) {
                        out.append(buf, std::min<std::size_t>(static_cast<std::size_t>(n), kMaxSyncStdoutBytes - out.size()));
                    }
                    continue;
                }
                if (n == 0) { eof = true; break; }
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                eof = true; break;
            }
            if (!eof && (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))) eof = true;
        }
        ::close(pipefd[0]);
        int st = 0;
        bool reaped = false;
        if (!timed_out) {
            for (;;) {
                pid_t w = ::waitpid(child, &st, WNOHANG);
                if (w == child || (w < 0 && errno != EINTR)) { reaped = true; break; }
                if (std::chrono::steady_clock::now() >= deadline) { timed_out = true; break; }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
        if (timed_out) {
            (void)::kill(child, SIGKILL);
            while (::waitpid(child, &st, 0) < 0 && errno == EINTR) {}
            return {false, -1, "core process timed out after 15s"};
        }
        if (!reaped) while (::waitpid(child, &st, 0) < 0 && errno == EINTR) {}
        return {true, WIFEXITED(st) ? WEXITSTATUS(st) : -1, std::move(out)};
    }
#endif
}
