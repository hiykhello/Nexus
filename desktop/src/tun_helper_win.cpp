#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <winsvc.h>

#ifndef PIPE_REJECT_REMOTE_CLIENTS
#define PIPE_REJECT_REMOTE_CLIENTS 0x00000008
#endif

import std;
import desktop.tun_helper_protocol;

namespace {
    using desktop::TunHelperCommand;
    using desktop::TunHelperPinnedConfig;
    using desktop::TunHelperReply;

    auto utf8_to_wide(std::string_view s) -> std::wstring {
        if (s.empty()) return {};
        int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
        if (n <= 0) return {};
        std::wstring out(static_cast<std::size_t>(n), L'\0');
        ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
        return out;
    }

    auto wide_to_utf8(std::wstring_view ws) -> std::string {
        if (ws.empty()) return {};
        int n = ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
        if (n <= 0) return {};
        std::string out(static_cast<std::size_t>(n), '\0');
        ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), out.data(), n, nullptr, nullptr);
        return out;
    }

    auto quote_win_arg(std::wstring_view arg) -> std::wstring {
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

    auto canonical_path(std::filesystem::path const& p) -> std::filesystem::path {
        std::error_code ec;
        auto c = std::filesystem::weakly_canonical(p, ec);
        return (!ec && !c.empty()) ? c : p;
    }
}

#include "tun_helper_win_stage.hpp"

namespace {
    auto stop_service_handle(SC_HANDLE svc) -> void {
        SERVICE_STATUS_PROCESS ssp{};
        DWORD needed = 0;
        if (!::QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed)) return;
        if (ssp.dwCurrentState == SERVICE_STOPPED) return;
        SERVICE_STATUS ss{};
        (void)::ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        for (int i = 0; i < 80; ++i) {
            if (::QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed) &&
                ssp.dwCurrentState == SERVICE_STOPPED) {
                return;
            }
            ::Sleep(100);
        }
    }

    auto cmd_install(std::vector<std::wstring> const& args) -> int {
        std::filesystem::path bin, cfg, wd;
        std::string owner_sid;
        for (std::size_t i = 2; i + 1 < args.size(); i += 2) {
            if (args[i] == L"--binary") bin = args[i + 1];
            else if (args[i] == L"--config") cfg = args[i + 1];
            else if (args[i] == L"--workdir") wd = args[i + 1];
            else if (args[i] == L"--owner-sid") owner_sid = wide_to_utf8(args[i + 1]);
        }
        if (bin.empty() || cfg.empty() || !desktop::validate_windows_sid(owner_sid)) return 2;
        bin = canonical_path(bin);
        cfg = canonical_path(cfg);
        wd = wd.empty() ? cfg.parent_path() : canonical_path(wd);

        auto digest = desktop::sha256_file(bin);
        if (!digest) return 3;

        wchar_t self_buf[MAX_PATH]{};
        DWORD len = ::GetModuleFileNameW(nullptr, self_buf, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) return 5;
        auto self_canon = canonical_path(std::filesystem::path(self_buf));

        auto svc_name = utf8_to_wide(desktop::kWinTunHelperServiceName);
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm) return 6;
        SC_HANDLE existing = ::OpenServiceW(scm, svc_name.c_str(), SERVICE_ALL_ACCESS);
        if (existing) stop_service_handle(existing);

        auto const stage_dir = resolve_win_stage_dir();
        auto const staged_helper = stage_dir / L"nexus-tun-helper.exe";
        auto const staged_core = stage_dir / L"nexus.exe";
        if (!ensure_privileged_stage_dir(stage_dir) ||
            !stage_file_atomic_win(self_canon, staged_helper) ||
            !stage_file_atomic_win(bin, staged_core)) {
            if (existing) ::CloseServiceHandle(existing);
            ::CloseServiceHandle(scm);
            return 9;
        }
        std::error_code wintun_ec;
        if (auto wintun_src = bin.parent_path() / L"wintun.dll"; std::filesystem::is_regular_file(wintun_src, wintun_ec)) {
            if (!stage_file_atomic_win(wintun_src, stage_dir / L"wintun.dll")) {
                if (existing) ::CloseServiceHandle(existing);
                ::CloseServiceHandle(scm);
                return 10;
            }
        }
        auto staged_sha = desktop::sha256_file(staged_core);
        if (!staged_sha || *staged_sha != *digest) {
            if (existing) ::CloseServiceHandle(existing);
            ::CloseServiceHandle(scm);
            return 11;
        }

        TunHelperPinnedConfig pinned{
            wide_to_utf8(bin.wstring()), *digest, wide_to_utf8(cfg.wstring()),
            wide_to_utf8(wd.wstring()), owner_sid, wide_to_utf8(staged_core.wstring()),
        };
        if (!save_pinned_config_to_hklm(pinned)) {
            if (existing) ::CloseServiceHandle(existing);
            ::CloseServiceHandle(scm);
            return 4;
        }

        std::wstring svc_cmd = quote_win_arg(staged_helper.wstring()) + L" --service";
        SC_HANDLE svc = existing;
        if (!svc) {
            svc = ::CreateServiceW(
                scm, svc_name.c_str(), L"Nexus TUN Privilege Helper",
                SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                svc_cmd.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
        } else {
            (void)::ChangeServiceConfigW(
                svc, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                svc_cmd.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, L"Nexus TUN Privilege Helper");
        }
        if (!svc) { ::CloseServiceHandle(scm); return 7; }

        bool started = ::StartServiceW(svc, 0, nullptr) != FALSE || ::GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
        bool running = false;
        if (started) {
            SERVICE_STATUS_PROCESS ssp{};
            DWORD needed = 0;
            for (int i = 0; i < 100; ++i) {
                if (::QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed)) {
                    if (ssp.dwCurrentState == SERVICE_RUNNING) { running = true; break; }
                    if (ssp.dwCurrentState == SERVICE_STOPPED) break;
                }
                ::Sleep(100);
            }
        }
        ::CloseServiceHandle(svc);
        ::CloseServiceHandle(scm);
        return running ? 0 : 8;
    }

    auto cmd_uninstall() -> int {
        auto svc_name = utf8_to_wide(desktop::kWinTunHelperServiceName);
        if (SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)) {
            if (SC_HANDLE svc = ::OpenServiceW(scm, svc_name.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE)) {
                stop_service_handle(svc);
                (void)::DeleteService(svc);
                ::CloseServiceHandle(svc);
            }
            ::CloseServiceHandle(scm);
        }
        auto subkey = utf8_to_wide(desktop::kWinTunHelperRegSubkey);
        (void)::RegDeleteTreeW(HKEY_LOCAL_MACHINE, subkey.c_str());
        (void)::RegDeleteKeyExW(HKEY_LOCAL_MACHINE, subkey.c_str(), KEY_WOW64_64KEY, 0);
        cleanup_win_stage_dir(resolve_win_stage_dir());
        return 0;
    }

    struct ChildRuntime {
        std::mutex mu;
        HANDLE proc = nullptr;
        HANDLE job = nullptr;
        DWORD pid = 0;

        auto refresh_locked() -> bool {
            if (!proc) return false;
            DWORD code = 0;
            if (::GetExitCodeProcess(proc, &code) && code == STILL_ACTIVE) return true;
            ::CloseHandle(proc); proc = nullptr;
            if (job) { ::CloseHandle(job); job = nullptr; }
            pid = 0;
            return false;
        }

        auto status() -> TunHelperReply {
            std::scoped_lock lk(mu);
            return refresh_locked() ? TunHelperReply{true, true, pid, "RUNNING"} : TunHelperReply{true, false, 0, "STOPPED"};
        }

        auto stop() -> TunHelperReply {
            std::scoped_lock lk(mu);
            if (!refresh_locked()) return {true, false, 0, "STOPPED"};
            auto ev_name = L"Local\\nexus-stop-" + std::to_wstring(pid);
            if (HANDLE ev = ::OpenEventW(EVENT_MODIFY_STATE, FALSE, ev_name.c_str())) {
                ::SetEvent(ev); ::CloseHandle(ev);
            }
            if (::WaitForSingleObject(proc, 1500) == WAIT_TIMEOUT) {
                (void)::TerminateProcess(proc, 0);
                (void)::WaitForSingleObject(proc, 1000);
            }
            ::CloseHandle(proc); proc = nullptr;
            if (job) { ::CloseHandle(job); job = nullptr; }
            pid = 0;
            return {true, false, 0, "STOPPED"};
        }

        auto start(TunHelperPinnedConfig const& cfg) -> TunHelperReply {
            std::scoped_lock lk(mu);
            if (refresh_locked()) return {true, true, pid, "RUNNING"};
            auto bin_path = std::filesystem::path(utf8_to_wide(cfg.staged_binary));
            if (bin_path.empty() || is_reparse_point_win(bin_path)) return {false, false, 0, "invalid staged core binary"};
            auto actual_sha = desktop::sha256_file(bin_path);
            if (!actual_sha) return {false, false, 0, actual_sha.error()};
            if (*actual_sha != cfg.sha256) return {false, false, 0, "core binary SHA-256 mismatch; re-authorize TUN"};

            auto cfg_w = utf8_to_wide(cfg.config);
            auto wd_w = utf8_to_wide(cfg.workdir);
            auto bin_w = bin_path.wstring();
            std::wstring cmdline = quote_win_arg(bin_w);
            if (!wd_w.empty()) { cmdline += L" -D "; cmdline += quote_win_arg(wd_w); }
            cmdline += L" run --config ";
            cmdline += quote_win_arg(cfg_w);

            SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
            HANDLE nul_h = ::CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                         &sa, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            STARTUPINFOW si{}; si.cb = sizeof(si);
            if (nul_h != INVALID_HANDLE_VALUE) {
                si.dwFlags = STARTF_USESTDHANDLES;
                si.hStdInput = INVALID_HANDLE_VALUE; si.hStdOutput = nul_h; si.hStdError = nul_h;
            }
            PROCESS_INFORMATION pi{};
            BOOL created = ::CreateProcessW(
                bin_w.c_str(), cmdline.data(), nullptr, nullptr, nul_h != INVALID_HANDLE_VALUE ? TRUE : FALSE,
                CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, nullptr, wd_w.empty() ? nullptr : wd_w.c_str(), &si, &pi);
            if (nul_h != INVALID_HANDLE_VALUE) ::CloseHandle(nul_h);
            if (!created) return {false, false, 0, std::format("CreateProcessW failed ({})", ::GetLastError())};
            ::CloseHandle(pi.hThread);

            HANDLE job_h = ::CreateJobObjectW(nullptr, nullptr);
            if (job_h) {
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
                jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                if (!::SetInformationJobObject(job_h, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli)) ||
                    !::AssignProcessToJobObject(job_h, pi.hProcess)) {
                    ::CloseHandle(job_h); job_h = nullptr;
                }
            }
            if (::WaitForSingleObject(pi.hProcess, 250) == WAIT_OBJECT_0) {
                DWORD code = 1;
                ::GetExitCodeProcess(pi.hProcess, &code);
                ::CloseHandle(pi.hProcess);
                if (job_h) ::CloseHandle(job_h);
                return {false, false, 0, std::format("core exited immediately (code {})", code)};
            }
            proc = pi.hProcess; job = job_h; pid = pi.dwProcessId;
            return {true, true, pid, "RUNNING"};
        }
    };

    SERVICE_STATUS_HANDLE g_svc_status_handle = nullptr;
    HANDLE g_stop_event = nullptr;
    ChildRuntime g_runtime;

    auto report_status(DWORD state, DWORD win32_exit = NO_ERROR, DWORD wait_hint = 0) -> void {
        if (!g_svc_status_handle) return;
        SERVICE_STATUS status{};
        status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        status.dwCurrentState = state;
        status.dwWin32ExitCode = win32_exit;
        status.dwWaitHint = wait_hint;
        status.dwControlsAccepted = (state == SERVICE_RUNNING) ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
        ::SetServiceStatus(g_svc_status_handle, &status);
    }

    auto WINAPI svc_ctrl_handler(DWORD ctrl, DWORD, LPVOID, LPVOID) -> DWORD {
        if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
            report_status(SERVICE_STOP_PENDING, NO_ERROR, 5000);
            if (g_stop_event) ::SetEvent(g_stop_event);
            return NO_ERROR;
        }
        return (ctrl == SERVICE_CONTROL_INTERROGATE) ? NO_ERROR : ERROR_CALL_NOT_IMPLEMENTED;
    }

    auto finish_overlapped(HANDLE pipe, OVERLAPPED& ov, HANDLE ev, BOOL initial_ok, DWORD timeout_ms, DWORD& n) -> bool {
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

    auto read_overlapped_timeout(HANDLE pipe, void* buf, DWORD cap, DWORD timeout_ms) -> DWORD {
        HANDLE ev = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ev) return 0;
        OVERLAPPED ov{}; ov.hEvent = ev;
        DWORD n = 0;
        bool done = finish_overlapped(pipe, ov, ev, ::ReadFile(pipe, buf, cap, &n, &ov), timeout_ms, n);
        ::CloseHandle(ev);
        return done ? n : 0;
    }

    auto write_overlapped_timeout(HANDLE pipe, void const* buf, DWORD len, DWORD timeout_ms) -> bool {
        HANDLE ev = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ev) return false;
        OVERLAPPED ov{}; ov.hEvent = ev;
        DWORD n = 0;
        bool done = finish_overlapped(pipe, ov, ev, ::WriteFile(pipe, buf, len, &n, &ov), timeout_ms, n);
        ::CloseHandle(ev);
        return done && n == len;
    }

    auto handle_pipe_client(HANDLE pipe, TunHelperPinnedConfig const& cfg) -> void {
        std::string req;
        char buf[desktop::kTunHelperMaxRequestBytes + 2]{};
        if (DWORD read_n = read_overlapped_timeout(pipe, buf, static_cast<DWORD>(sizeof(buf) - 1), 3000); read_n > 0) {
            req.assign(buf, read_n);
            while (!req.empty() && (req.back() == '\n' || req.back() == '\r')) req.pop_back();
        }
        TunHelperReply reply{};
        if (auto cmd = desktop::parse_tun_helper_request(req)) {
            switch (*cmd) {
            case TunHelperCommand::ping: reply = {true, false, 0, "PONG"}; break;
            case TunHelperCommand::status: reply = g_runtime.status(); break;
            case TunHelperCommand::start: reply = g_runtime.start(cfg); break;
            case TunHelperCommand::stop: reply = g_runtime.stop(); break;
            }
        } else {
            reply = {false, false, 0, "invalid command"};
        }
        auto wire = desktop::format_tun_helper_reply(reply) + "\n";
        (void)write_overlapped_timeout(pipe, wire.data(), static_cast<DWORD>(wire.size()), 3000);
        (void)::FlushFileBuffers(pipe);
        (void)::DisconnectNamedPipe(pipe);
    }

    auto WINAPI service_main(DWORD, LPWSTR*) -> void {
        auto svc_name = utf8_to_wide(desktop::kWinTunHelperServiceName);
        g_svc_status_handle = ::RegisterServiceCtrlHandlerExW(svc_name.c_str(), svc_ctrl_handler, nullptr);
        if (!g_svc_status_handle) return;
        report_status(SERVICE_START_PENDING, NO_ERROR, 3000);

        auto cfg = load_pinned_config_from_hklm();
        if (!cfg) { report_status(SERVICE_STOPPED, ERROR_INVALID_DATA); return; }
        auto sddl = desktop::build_win_helper_pipe_sddl(cfg->owner);
        if (!sddl) { report_status(SERVICE_STOPPED, ERROR_INVALID_SID); return; }

        PSECURITY_DESCRIPTOR sd = nullptr;
        auto sddl_w = utf8_to_wide(*sddl);
        if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl_w.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
            report_status(SERVICE_STOPPED, ::GetLastError()); return;
        }
        SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
        auto pipe_w = utf8_to_wide(desktop::kWinTunHelperPipeName);
        HANDLE pipe = ::CreateNamedPipeW(
            pipe_w.c_str(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, desktop::kTunHelperMaxReplyBytes, desktop::kTunHelperMaxRequestBytes, 1000, &sa);
        ::LocalFree(sd);
        if (pipe == INVALID_HANDLE_VALUE) { report_status(SERVICE_STOPPED, ::GetLastError()); return; }

        g_stop_event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        HANDLE conn_event = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!g_stop_event || !conn_event) {
            if (conn_event) ::CloseHandle(conn_event);
            if (g_stop_event) { ::CloseHandle(g_stop_event); g_stop_event = nullptr; }
            ::CloseHandle(pipe);
            report_status(SERVICE_STOPPED, ERROR_OUTOFMEMORY);
            return;
        }

        report_status(SERVICE_RUNNING);
        while (::WaitForSingleObject(g_stop_event, 0) != WAIT_OBJECT_0) {
            ::ResetEvent(conn_event);
            OVERLAPPED ov{}; ov.hEvent = conn_event;
            BOOL ok = ::ConnectNamedPipe(pipe, &ov);
            bool connected = ok != FALSE;
            if (!connected) {
                DWORD err = ::GetLastError();
                if (err == ERROR_PIPE_CONNECTED) {
                    connected = true;
                } else if (err == ERROR_IO_PENDING) {
                    HANDLE waits[2] = {g_stop_event, conn_event};
                    DWORD w = ::WaitForMultipleObjects(2, waits, FALSE, INFINITE);
                    if (w == WAIT_OBJECT_0 + 1) {
                        DWORD dummy = 0;
                        connected = ::GetOverlappedResult(pipe, &ov, &dummy, FALSE) != FALSE;
                    } else {
                        DWORD dummy = 0;
                        (void)::CancelIoEx(pipe, &ov);
                        (void)::GetOverlappedResult(pipe, &ov, &dummy, TRUE);
                    }
                } else {
                    ::Sleep(50);
                }
            }
            if (connected) handle_pipe_client(pipe, *cfg);
        }

        (void)g_runtime.stop();
        ::CloseHandle(conn_event);
        ::CloseHandle(g_stop_event);
        g_stop_event = nullptr;
        ::CloseHandle(pipe);
        report_status(SERVICE_STOPPED);
    }
}

auto main() -> int {
    int argc = 0;
    LPWSTR* wargv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
    if (!wargv || argc < 2) { if (wargv) ::LocalFree(wargv); return 1; }
    std::vector<std::wstring> args;
    args.reserve(static_cast<std::size_t>(argc));
    for (int i = 0; i < argc; ++i) args.emplace_back(wargv[i]);
    ::LocalFree(wargv);

    if (args[1] == L"--install") return cmd_install(args);
    if (args[1] == L"--uninstall") return cmd_uninstall();
    if (args[1] == L"--service") {
        auto svc_name = utf8_to_wide(desktop::kWinTunHelperServiceName);
        SERVICE_TABLE_ENTRYW table[] = {{svc_name.data(), service_main}, {nullptr, nullptr}};
        return ::StartServiceCtrlDispatcherW(table) ? 0 : 1;
    }
    return 1;
}
#endif
