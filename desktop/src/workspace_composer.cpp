module;

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

module desktop.workspace_composer;

import std;
import desktop.mini_json;
import desktop.workspace_models;

namespace desktop {
    namespace {
        constexpr std::size_t kMaxComposeStdoutBytes = 16u * 1024u * 1024u;
        constexpr auto kComposeTimeout = std::chrono::seconds(15);

        auto path_to_utf8_cmp(std::filesystem::path const& p) -> std::string {
            auto u8 = p.u8string();
            return std::string(reinterpret_cast<char const*>(u8.data()), u8.size());
        }

#ifdef _WIN32
        auto utf8_to_wide_cmp(std::string_view s) -> std::wstring {
            if (s.empty()) return {};
            int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
            if (n <= 0) return {};
            std::wstring out(static_cast<std::size_t>(n), L'\0');
            ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
            return out;
        }

        auto quote_win_cmp_arg(std::wstring_view arg) -> std::wstring {
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

        auto run_core_compose_proc(std::vector<std::string> const& args) -> std::tuple<bool, int, std::string> {
            SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
            HANDLE r_pipe = nullptr, w_pipe = nullptr;
            if (!::CreatePipe(&r_pipe, &w_pipe, &sa, 0)) return {false, -1, "CreatePipe failed"};
            (void)::SetHandleInformation(r_pipe, HANDLE_FLAG_INHERIT, 0);

            std::wstring cmdline;
            for (std::size_t i = 0; i < args.size(); ++i) {
                if (i > 0) cmdline.push_back(L' ');
                cmdline += quote_win_cmp_arg(utf8_to_wide_cmp(args[i]));
            }
            auto bin_w = utf8_to_wide_cmp(args[0]);
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

            auto const deadline = std::chrono::steady_clock::now() + kComposeTimeout;
            std::string out;
            char buf[4096];
            bool timed_out = false;
            auto drain_pipe = [&] {
                for (;;) {
                    DWORD avail = 0;
                    if (!::PeekNamedPipe(r_pipe, nullptr, 0, nullptr, &avail, nullptr) || avail == 0) break;
                    DWORD want = static_cast<DWORD>(std::min<std::size_t>(sizeof(buf), avail));
                    DWORD n = 0;
                    if (!::ReadFile(r_pipe, buf, want, &n, nullptr) || n == 0) break;
                    if (out.size() < kMaxComposeStdoutBytes) {
                        out.append(buf, std::min<std::size_t>(n, kMaxComposeStdoutBytes - out.size()));
                    }
                }
            };
            for (;;) {
                drain_pipe();
                DWORD wait_rc = ::WaitForSingleObject(pi.hProcess, 25);
                if (wait_rc == WAIT_OBJECT_0) {
                    drain_pipe();
                    break;
                }
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
            if (timed_out) return {false, -1, "nexus workspace compose timed out after 15s"};
            return {true, static_cast<int>(code), std::move(out)};
        }
#else
        auto run_core_compose_proc(std::vector<std::string> const& args) -> std::tuple<bool, int, std::string> {
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
                    if (devnull == STDIN_FILENO) (void)::fcntl(devnull, F_SETFD, 0);
                    else (void)::dup2(devnull, STDIN_FILENO);
                    if (devnull == STDERR_FILENO) (void)::fcntl(devnull, F_SETFD, 0);
                    else (void)::dup2(devnull, STDERR_FILENO);
                }
                if (pipefd[1] == STDOUT_FILENO) (void)::fcntl(pipefd[1], F_SETFD, 0);
                else (void)::dup2(pipefd[1], STDOUT_FILENO);
                ::execv(args[0].c_str(), argv.data());
                ::_exit(127);
            }
            if (devnull >= 0) ::close(devnull);
            ::close(pipefd[1]);

            int flags = ::fcntl(pipefd[0], F_GETFL, 0);
            if (flags >= 0) (void)::fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

            auto const deadline = std::chrono::steady_clock::now() + kComposeTimeout;
            std::string out;
            char buf[4096];
            bool timed_out = false;
            bool eof = false;
            while (!eof) {
                auto now = std::chrono::steady_clock::now();
                if (now >= deadline) { timed_out = true; break; }
                int rem_ms = static_cast<int>(std::min<std::int64_t>(
                    200, std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count()));
                struct pollfd pfd{pipefd[0], POLLIN, 0};
                int pr = ::poll(&pfd, 1, std::max(1, rem_ms));
                if (pr < 0 && errno == EINTR) continue;
                if (pr < 0) break;
                if (pr == 0) continue;
                for (;;) {
                    auto n = ::read(pipefd[0], buf, sizeof(buf));
                    if (n > 0) {
                        if (out.size() < kMaxComposeStdoutBytes) {
                            out.append(buf, std::min<std::size_t>(static_cast<std::size_t>(n), kMaxComposeStdoutBytes - out.size()));
                        }
                        continue;
                    }
                    if (n == 0) { eof = true; break; }
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    eof = true;
                    break;
                }
                if (!eof && (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))) eof = true;
            }
            ::close(pipefd[0]);

            int st = 0;
            bool reaped = false;
            if (!timed_out) {
                for (;;) {
                    pid_t w = ::waitpid(child, &st, WNOHANG);
                    if (w == child) { reaped = true; break; }
                    if (w < 0 && errno != EINTR) { reaped = true; break; }
                    if (std::chrono::steady_clock::now() >= deadline) { timed_out = true; break; }
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
            if (timed_out) {
                (void)::kill(child, SIGKILL);
                while (::waitpid(child, &st, 0) < 0 && errno == EINTR) {}
                return {false, -1, "nexus workspace compose timed out after 15s"};
            }
            if (!reaped) {
                while (::waitpid(child, &st, 0) < 0 && errno == EINTR) {}
            }
            int code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
            return {true, code, std::move(out)};
        }
#endif
    }

    auto sanitize_core_tag(std::string_view raw, std::string_view fallback) -> std::string {
        std::string out;
        for (unsigned char c : raw) {
            if (std::isalnum(c) || c == '-' || c == '_') out.push_back(static_cast<char>(c));
            else if (c == ' ' || c == '.' || c == '+' || c == '/') out.push_back('-');
        }
        while (!out.empty() && out.front() == '-') out.erase(out.begin());
        while (!out.empty() && out.back() == '-') out.pop_back();
        if (out.empty()) out = std::string(fallback);
        if (out.size() > 56) out.resize(56);
        if (out == "direct" || out == "block" || out == "proxy") out += "-node";
        return out;
    }

    auto resolve_live_switch_tag(WorkspaceDocument const& doc, std::string_view profile_id) -> std::string {
        WorkspaceProfileItem const* target = nullptr;
        for (auto const& p : doc.profiles) {
            if (p.id == profile_id) { target = &p; break; }
        }
        if (!target || target->kind != "node") return {};
        // Decline live switch when target's subscription has an active Sub-Chain (requires detour wrapping)
        if (!target->subscription_id.empty()) {
            for (auto const& s : doc.subscriptions) {
                if (s.id == target->subscription_id && (!s.prev_profile_id.empty() || !s.next_profile_id.empty())) {
                    return {};
                }
            }
        }
        auto candidate = sanitize_core_tag(!target->remarks.empty() ? target->remarks : target->id, "node");
        std::size_t matches = 0;
        for (auto const& p : doc.profiles) {
            if (sanitize_core_tag(!p.remarks.empty() ? p.remarks : p.id, "node") == candidate) ++matches;
        }
        return matches == 1 ? candidate : std::string{};
    }

    auto parse_workspace_compose_json(std::string_view json_text) -> WorkspaceComposeResult {
        WorkspaceComposeResult res{};
        auto parsed = json_parse(json_text);
        if (!parsed) {
            res.errors.push_back("invalid compose JSON: " + parsed.error());
            return res;
        }
        if (!parsed->is_object()) {
            res.errors.push_back("compose JSON root must be an object");
            return res;
        }
        auto const& obj = std::get<JsonObject>(parsed->data);
        res.ok = json_get_bool(obj, "ok", false);
        res.active_tag = json_get_string(obj, "active_tag");
        res.selector_tag = json_get_string(obj, "selector_tag", "proxy");
        res.selector_members = json_get_string_vec(obj, "selector_members");
        res.warnings = json_get_string_vec(obj, "warnings");
        res.errors = json_get_string_vec(obj, "errors");
        res.secret_files = json_get_string_vec(obj, "secret_files");
        res.kdl = json_get_string(obj, "kdl");
        if (!res.ok && res.errors.empty()) res.errors.push_back("workspace compose returned ok=false");
        return res;
    }

    auto decide_tun_live_switch(
        bool core_running,
        bool tun_enabled,
        std::string_view running_selector_tag,
        std::span<std::string const> running_selector_members,
        std::string_view target_tag) -> TunLiveSwitchDecision {
        TunLiveSwitchDecision d{};
        if (!core_running || !tun_enabled || target_tag.empty() || running_selector_tag.empty()) return d;
        for (auto const& m : running_selector_members) {
            if (m == target_tag) {
                d.can_live_switch = true;
                d.selector_tag = std::string(running_selector_tag);
                d.target_tag = std::string(target_tag);
                return d;
            }
        }
        return d;
    }

    auto build_workspace_compose_argv(
        std::filesystem::path const& core_binary,
        std::filesystem::path const& workspace_file,
        std::filesystem::path const& host_file,
        std::filesystem::path const& secrets_dir,
        std::string_view active_profile_id,
        std::filesystem::path const& emit_kdl_file) -> std::vector<std::string> {
        if (core_binary.empty() || workspace_file.empty() || host_file.empty() || secrets_dir.empty()) return {};
        std::vector<std::string> argv{
            path_to_utf8_cmp(core_binary), "workspace", "compose",
            "--workspace", path_to_utf8_cmp(workspace_file),
            "--host", path_to_utf8_cmp(host_file),
            "--secrets-dir", path_to_utf8_cmp(secrets_dir),
        };
        if (!active_profile_id.empty()) {
            argv.push_back("--active");
            argv.emplace_back(active_profile_id);
        }
        if (!emit_kdl_file.empty()) {
            argv.push_back("--emit-kdl");
            argv.push_back(path_to_utf8_cmp(emit_kdl_file));
        }
        argv.push_back("--json-result");
        return argv;
    }

    auto compose_workspace_via_core(
        std::filesystem::path const& core_binary,
        std::filesystem::path const& workspace_file,
        std::filesystem::path const& host_file,
        std::filesystem::path const& secrets_dir,
        std::string_view active_profile_id,
        std::filesystem::path const& emit_kdl_file) -> WorkspaceComposeResult {
        WorkspaceComposeResult err{};
        std::error_code ec;
        if (!std::filesystem::is_regular_file(core_binary, ec)) {
            err.errors.push_back("core binary not found: " + path_to_utf8_cmp(core_binary));
            return err;
        }
        auto argv = build_workspace_compose_argv(core_binary, workspace_file, host_file, secrets_dir, active_profile_id, emit_kdl_file);
        if (argv.empty()) { err.errors.push_back("missing required workspace compose arguments"); return err; }
        auto [launched, code, output] = run_core_compose_proc(argv);
        if (!launched) { err.errors.push_back(output); return err; }
        if (output.empty()) {
            err.errors.push_back(std::format("nexus workspace compose produced no output (exit {})", code));
            return err;
        }
        auto res = parse_workspace_compose_json(output);
        if (code != 0) {
            res.ok = false;
            if (res.errors.empty()) res.errors.push_back(std::format("nexus workspace compose exited with code {}", code));
        }
        return res;
    }
}
