module;

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

module desktop.core_supervisor;

import std;

namespace desktop {
    struct CoreSupervisor::Impl {
#ifdef _WIN32
        HANDLE process = nullptr;
#else
        pid_t pid = -1;
#endif
    };

    CoreSupervisor::CoreSupervisor(std::filesystem::path binary)
        : impl_(std::make_unique<Impl>()), binary_(std::move(binary)) {}

    CoreSupervisor::~CoreSupervisor() { stop(); }

    auto CoreSupervisor::running(this CoreSupervisor const& self) noexcept -> bool {
#ifdef _WIN32
        if (!self.impl_->process) return false;
        DWORD code = 0;
        return ::GetExitCodeProcess(self.impl_->process, &code) && code == STILL_ACTIVE;
#else
        if (self.impl_->pid <= 0) return false;
        int status = 0;
        pid_t res = ::waitpid(self.impl_->pid, &status, WNOHANG);
        if (res == self.impl_->pid) {
            self.impl_->pid = -1;
            return false;
        }
        return res == 0;
#endif
    }

    auto CoreSupervisor::start(this CoreSupervisor& self, std::filesystem::path const& config_path) -> bool {
        if (self.running()) return true;
        if (!std::filesystem::is_regular_file(self.binary_)) return false;
#ifdef _WIN32
        auto workdir = config_path.parent_path();
        std::wstring cmd = L"\"" + self.binary_.wstring() + L"\"";
        if (!workdir.empty() && std::filesystem::is_directory(workdir))
            cmd += L" -D \"" + workdir.wstring() + L"\"";
        cmd += L" run --config \"" + config_path.wstring() + L"\"";
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (!::CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            return false;
        }
        ::CloseHandle(pi.hThread);
        self.impl_->process = pi.hProcess;
        return true;
#else
        pid_t child = ::fork();
        if (child < 0) return false;
        if (child == 0) {
            auto bin = self.binary_.string();
            auto cfg = config_path.string();
            auto dir = config_path.parent_path().string();
            if (!dir.empty() && std::filesystem::is_directory(dir)) {
                char* argv[] = {bin.data(), const_cast<char*>("-D"), dir.data(),
                    const_cast<char*>("run"), const_cast<char*>("--config"), cfg.data(), nullptr};
                ::execv(bin.c_str(), argv);
            } else {
                char* argv[] = {bin.data(), const_cast<char*>("run"), const_cast<char*>("--config"), cfg.data(), nullptr};
                ::execv(bin.c_str(), argv);
            }
            ::_exit(127);
        }
        self.impl_->pid = child;
        return true;
#endif
    }

    auto CoreSupervisor::stop(this CoreSupervisor& self) -> void {
#ifdef _WIN32
        if (!self.impl_->process) return;
        ::TerminateProcess(self.impl_->process, 0);
        ::WaitForSingleObject(self.impl_->process, 1500);
        ::CloseHandle(self.impl_->process);
        self.impl_->process = nullptr;
#else
        if (self.impl_->pid <= 0) return;
        ::kill(self.impl_->pid, SIGTERM);
        for (int i = 0; i < 30; ++i) {
            int status = 0;
            if (::waitpid(self.impl_->pid, &status, WNOHANG) == self.impl_->pid) {
                self.impl_->pid = -1;
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        ::kill(self.impl_->pid, SIGKILL);
        int status = 0;
        (void)::waitpid(self.impl_->pid, &status, 0);
        self.impl_->pid = -1;
#endif
    }

    auto CoreSupervisor::validate_config(
        this CoreSupervisor const& self,
        std::filesystem::path const& config_path) -> ValidationResult {
        if (!std::filesystem::is_regular_file(self.binary_)) {
            return {false, "未找到 nexus 核心二进制: " + self.binary_.string()};
        }
#ifdef _WIN32
        auto workdir = config_path.parent_path();
        std::wstring cmd = L"\"" + self.binary_.wstring() + L"\"";
        if (!workdir.empty() && std::filesystem::is_directory(workdir))
            cmd += L" -D \"" + workdir.wstring() + L"\"";
        cmd += L" check --config \"" + config_path.wstring() + L"\"";
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (!::CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            return {false, "无法启动 nexus check"};
        }
        ::WaitForSingleObject(pi.hProcess, 5000);
        DWORD exit_code = 1;
        ::GetExitCodeProcess(pi.hProcess, &exit_code);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        return {exit_code == 0, exit_code == 0 ? "配置校验通过" : std::format("配置校验失败（退出码 {}）", exit_code)};
#else
        int pipefd[2]{-1, -1};
        if (::pipe(pipefd) != 0) return {false, "pipe failed"};
        pid_t child = ::fork();
        if (child < 0) {
            ::close(pipefd[0]);
            ::close(pipefd[1]);
            return {false, "fork failed"};
        }
        if (child == 0) {
            ::close(pipefd[0]);
            ::dup2(pipefd[1], STDOUT_FILENO);
            ::dup2(pipefd[1], STDERR_FILENO);
            ::close(pipefd[1]);
            auto bin = self.binary_.string();
            auto cfg = config_path.string();
            auto dir = config_path.parent_path().string();
            if (!dir.empty() && std::filesystem::is_directory(dir)) {
                char* argv[] = {bin.data(), const_cast<char*>("-D"), dir.data(),
                    const_cast<char*>("check"), const_cast<char*>("--config"), cfg.data(), nullptr};
                ::execv(bin.c_str(), argv);
            } else {
                char* argv[] = {bin.data(), const_cast<char*>("check"), const_cast<char*>("--config"), cfg.data(), nullptr};
                ::execv(bin.c_str(), argv);
            }
            ::_exit(127);
        }
        ::close(pipefd[1]);
        std::string output;
        char buf[512];
        for (;;) {
            auto n = ::read(pipefd[0], buf, sizeof(buf));
            if (n <= 0) break;
            if (output.size() < 4096) output.append(buf, static_cast<std::size_t>(n));
        }
        ::close(pipefd[0]);
        int status = 0;
        (void)::waitpid(child, &status, 0);
        bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        return {ok, output.empty() ? (ok ? "配置校验通过" : "配置校验失败") : output};
#endif
    }

    auto CoreSupervisor::explain_rule(
        this CoreSupervisor const& self,
        std::filesystem::path const& config_path,
        std::string_view inbound,
        std::string_view network,
        std::string_view target,
        std::string_view extra_options) -> ValidationResult {
        if (!std::filesystem::is_regular_file(self.binary_))
            return {false, "未找到 nexus 核心二进制: " + self.binary_.string()};
        if (inbound.empty() || network.empty() || target.empty())
            return {false, "入站名称、协议 (tcp/udp) 与目标 host:port 不能为空"};
        std::vector<std::string> extras;
        std::string cur;
        for (char ch : extra_options) {
            if (std::isspace(static_cast<unsigned char>(ch))) {
                if (!cur.empty()) { extras.push_back(std::move(cur)); cur.clear(); }
            } else cur.push_back(ch);
        }
        if (!cur.empty()) extras.push_back(std::move(cur));
#ifdef _WIN32
        std::wstring cmd = L"\"" + self.binary_.wstring() + L"\" rule explain \"" + config_path.wstring() + L"\"";
        STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
        if (!::CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
            return {false, "无法启动 nexus rule explain"};
        ::WaitForSingleObject(pi.hProcess, 5000);
        DWORD exit_code = 1;
        ::GetExitCodeProcess(pi.hProcess, &exit_code);
        ::CloseHandle(pi.hThread); ::CloseHandle(pi.hProcess);
        return {exit_code == 0, exit_code == 0 ? "规则测试通过" : "规则测试失败"};
#else
        int pipefd[2]{-1, -1};
        if (::pipe(pipefd) != 0) return {false, "pipe failed"};
        pid_t child = ::fork();
        if (child < 0) { ::close(pipefd[0]); ::close(pipefd[1]); return {false, "fork failed"}; }
        if (child == 0) {
            ::close(pipefd[0]);
            ::dup2(pipefd[1], STDOUT_FILENO);
            ::dup2(pipefd[1], STDERR_FILENO);
            ::close(pipefd[1]);
            std::vector<std::string> args{self.binary_.string(), "rule", "explain",
                config_path.string(), std::string(inbound), std::string(network), std::string(target), "--oneline"};
            for (auto& e : extras) args.push_back(std::move(e));
            std::vector<char*> argv;
            argv.reserve(args.size() + 1);
            for (auto& a : args) argv.push_back(a.data());
            argv.push_back(nullptr);
            ::execv(args[0].c_str(), argv.data());
            ::_exit(127);
        }
        ::close(pipefd[1]);
        std::string output;
        char buf[512];
        for (;;) {
            auto n = ::read(pipefd[0], buf, sizeof(buf));
            if (n <= 0) break;
            if (output.size() < 4096) output.append(buf, static_cast<std::size_t>(n));
        }
        ::close(pipefd[0]);
        int status = 0;
        (void)::waitpid(child, &status, 0);
        while (!output.empty() && (output.back() == '\n' || output.back() == '\r')) output.pop_back();
        bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        return {ok, output.empty() ? (ok ? "ok" : "rule explain failed") : output};
#endif
    }
}
