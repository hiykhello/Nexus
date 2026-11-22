module;
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

module desktop.firewall_helper;

import std;

namespace desktop {
    auto normalize_firewall_executable_path(std::string_view raw) -> std::string {
        if (raw.starts_with(R"(\\?\UNC\)")) {
            return R"(\\)" + std::string(raw.substr(8));
        }
        if (raw.starts_with(R"(\\?\)")) {
            return std::string(raw.substr(4));
        }
        return std::string(raw);
    }

    auto ensure_loopback_firewall_rule(std::string_view executable_path,
                                       std::string_view rule_name,
                                       bool diagnostic_mode) -> FirewallResult {
        if (diagnostic_mode) {
            return {.ok = true, .skipped = true, .message = "diagnostic mode: host firewall mutation skipped"};
        }
        auto normalized = normalize_firewall_executable_path(executable_path);
        if (normalized.empty() || rule_name.empty()) {
            return {.ok = false, .skipped = false, .message = "empty executable path or rule name"};
        }
#ifdef _WIN32
        auto run_netsh = [](std::string const& cmd_utf8) -> std::pair<bool, std::string> {
            SECURITY_ATTRIBUTES sa{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
            HANDLE read_pipe = nullptr, write_pipe = nullptr;
            if (!::CreatePipe(&read_pipe, &write_pipe, &sa, 0)) return {false, "CreatePipe failed"};
            ::SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

            STARTUPINFOA si{};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            si.hStdOutput = write_pipe;
            si.hStdError = write_pipe;

            PROCESS_INFORMATION pi{};
            std::string mutable_cmd = cmd_utf8;
            BOOL ok = ::CreateProcessA(nullptr, mutable_cmd.data(), nullptr, nullptr, TRUE,
                CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
            ::CloseHandle(write_pipe);
            if (!ok) {
                ::CloseHandle(read_pipe);
                return {false, "CreateProcess netsh failed"};
            }
            std::string output;
            char buf[512];
            DWORD read_bytes = 0;
            while (::ReadFile(read_pipe, buf, sizeof(buf), &read_bytes, nullptr) && read_bytes > 0) {
                output.append(buf, read_bytes);
            }
            ::CloseHandle(read_pipe);
            ::WaitForSingleObject(pi.hProcess, 5000);
            DWORD code = 1;
            ::GetExitCodeProcess(pi.hProcess, &code);
            ::CloseHandle(pi.hThread);
            ::CloseHandle(pi.hProcess);
            return {code == 0, std::move(output)};
        };

        auto check_cmd = std::format("netsh advfirewall firewall show rule name=\"{}\"", rule_name);
        if (auto [exists, _] = run_netsh(check_cmd); exists) {
            return {.ok = true, .skipped = true, .message = "firewall rule already present"};
        }
        auto add_cmd = std::format(
            "netsh advfirewall firewall add rule name=\"{}\" dir=in action=allow program=\"{}\" "
            "localip=127.0.0.1,::1 enable=yes profile=any",
            rule_name, normalized);
        auto [added, out] = run_netsh(add_cmd);
        return {.ok = added, .skipped = false, .message = out.empty() ? (added ? "rule added" : "netsh failed") : out};
#else
        (void)rule_name;
        return {.ok = true, .skipped = true, .message = "non-Windows host: loopback firewall rule not required"};
#endif
    }
}
