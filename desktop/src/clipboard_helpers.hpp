// Cross-platform clipboard read/write helpers included by desktop/src/main_helpers.hpp.
#pragma once

namespace desktop_ui_helpers {
#ifndef _WIN32
    inline auto run_clipboard_tool(char const* const argv[], std::string const& text) -> bool {
        int pipefd[2]{-1, -1};
        if (::pipe(pipefd) != 0) return false;
        (void)::fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
        (void)::fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
        pid_t child = ::fork();
        if (child < 0) {
            ::close(pipefd[0]);
            ::close(pipefd[1]);
            return false;
        }
        if (child == 0) {
            ::close(pipefd[1]);
            if (pipefd[0] == STDIN_FILENO) (void)::fcntl(pipefd[0], F_SETFD, 0);
            else (void)::dup2(pipefd[0], STDIN_FILENO);
            int devnull = ::open("/dev/null", O_WRONLY | O_CLOEXEC);
            if (devnull >= 0) {
                (void)::dup2(devnull, STDOUT_FILENO);
                (void)::dup2(devnull, STDERR_FILENO);
            }
            ::execvp(argv[0], const_cast<char* const*>(argv));
            ::_exit(127);
        }
        ::close(pipefd[0]);
        std::size_t off = 0;
        while (off < text.size()) {
            auto n = ::write(pipefd[1], text.data() + off, text.size() - off);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            off += static_cast<std::size_t>(n);
        }
        ::close(pipefd[1]);
        int status = 0;
        while (::waitpid(child, &status, 0) < 0) { if (errno != EINTR) return false; }
        return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }

    inline auto run_clipboard_read_tool(char const* const argv[]) -> std::string {
        int pipefd[2]{-1, -1};
        if (::pipe(pipefd) != 0) return {};
        (void)::fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
        (void)::fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
        pid_t child = ::fork();
        if (child < 0) { ::close(pipefd[0]); ::close(pipefd[1]); return {}; }
        if (child == 0) {
            ::close(pipefd[0]);
            int devnull = ::open("/dev/null", O_RDWR | O_CLOEXEC);
            if (devnull >= 0) {
                (void)::dup2(devnull, STDIN_FILENO);
                (void)::dup2(devnull, STDERR_FILENO);
            }
            if (pipefd[1] == STDOUT_FILENO) (void)::fcntl(pipefd[1], F_SETFD, 0);
            else (void)::dup2(pipefd[1], STDOUT_FILENO);
            ::execvp(argv[0], const_cast<char* const*>(argv));
            ::_exit(127);
        }
        ::close(pipefd[1]);
        std::string out;
        char buf[4096];
        while (out.size() < 2u * 1024u * 1024u) {
            auto n = ::read(pipefd[0], buf, sizeof(buf));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            out.append(buf, static_cast<std::size_t>(n));
        }
        ::close(pipefd[0]);
        int status = 0;
        while (::waitpid(child, &status, 0) < 0) { if (errno != EINTR) return {}; }
        return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? out : std::string{};
    }
#endif

    inline auto copy_text_to_clipboard(std::string const& text) -> bool {
        if (text.empty()) return false;
#ifdef _WIN32
        int wlen = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
        if (wlen <= 0) return false;
        if (!::OpenClipboard(nullptr)) return false;
        ::EmptyClipboard();
        HGLOBAL hmem = ::GlobalAlloc(GMEM_MOVEABLE, static_cast<SIZE_T>(wlen + 1) * sizeof(wchar_t));
        if (!hmem) { ::CloseClipboard(); return false; }
        auto* dst = static_cast<wchar_t*>(::GlobalLock(hmem));
        if (!dst) { ::GlobalFree(hmem); ::CloseClipboard(); return false; }
        ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), dst, wlen);
        dst[wlen] = L'\0';
        ::GlobalUnlock(hmem);
        if (!::SetClipboardData(CF_UNICODETEXT, hmem)) { ::GlobalFree(hmem); ::CloseClipboard(); return false; }
        ::CloseClipboard();
        return true;
#else
#ifdef __APPLE__
        char const* const pbcopy_argv[] = {"pbcopy", nullptr};
        if (run_clipboard_tool(pbcopy_argv, text)) return true;
#else
        if (char const* wl = std::getenv("WAYLAND_DISPLAY"); wl && *wl) {
            char const* const wl_argv[] = {"wl-copy", nullptr};
            if (run_clipboard_tool(wl_argv, text)) return true;
        }
        if (char const* x11 = std::getenv("DISPLAY"); x11 && *x11) {
            char const* const xclip_argv[] = {"xclip", "-selection", "clipboard", nullptr};
            if (run_clipboard_tool(xclip_argv, text)) return true;
            char const* const xsel_argv[] = {"xsel", "--clipboard", "--input", nullptr};
            if (run_clipboard_tool(xsel_argv, text)) return true;
        }
#endif
        return false;
#endif
    }

    inline auto read_text_from_clipboard() -> std::string {
#ifdef _WIN32
        if (!::OpenClipboard(nullptr)) return {};
        HANDLE h = ::GetClipboardData(CF_UNICODETEXT);
        if (!h) { ::CloseClipboard(); return {}; }
        auto const* wptr = static_cast<wchar_t const*>(::GlobalLock(h));
        if (!wptr) { ::CloseClipboard(); return {}; }
        int len = ::WideCharToMultiByte(CP_UTF8, 0, wptr, -1, nullptr, 0, nullptr, nullptr);
        std::string out;
        if (len > 1) {
            out.resize(static_cast<std::size_t>(len - 1));
            ::WideCharToMultiByte(CP_UTF8, 0, wptr, -1, out.data(), len - 1, nullptr, nullptr);
        }
        ::GlobalUnlock(h);
        ::CloseClipboard();
        return out;
#else
#ifdef __APPLE__
        char const* const pbpaste_argv[] = {"pbpaste", nullptr};
        if (auto s = run_clipboard_read_tool(pbpaste_argv); !s.empty()) return s;
#else
        if (char const* wl = std::getenv("WAYLAND_DISPLAY"); wl && *wl) {
            char const* const wl_argv[] = {"wl-paste", "--no-newline", nullptr};
            if (auto s = run_clipboard_read_tool(wl_argv); !s.empty()) return s;
        }
        if (char const* x11 = std::getenv("DISPLAY"); x11 && *x11) {
            char const* const xclip_argv[] = {"xclip", "-selection", "clipboard", "-o", nullptr};
            if (auto s = run_clipboard_read_tool(xclip_argv); !s.empty()) return s;
            char const* const xsel_argv[] = {"xsel", "--clipboard", "--output", nullptr};
            if (auto s = run_clipboard_read_tool(xsel_argv); !s.empty()) return s;
        }
#endif
        return {};
#endif
    }
}
