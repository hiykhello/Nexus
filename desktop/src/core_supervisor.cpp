module;

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#else
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <sys/wait.h>
#include <unistd.h>
#endif

module desktop.core_supervisor;

import std;

#include "core_supervisor_detail.hpp"

namespace desktop {
    using namespace detail;

    struct CoreSupervisor::Impl {
        std::mutex lifecycle_mu;
        mutable std::mutex state_mu;
        bool stopping = false;
        std::string last_error;
        std::filesystem::path startup_log;
#ifdef _WIN32
        HANDLE process = nullptr;
        HANDLE job = nullptr;
#else
        pid_t pid = -1;
#endif
    };

    CoreSupervisor::CoreSupervisor(std::filesystem::path binary)
        : impl_(std::make_unique<Impl>()), binary_(std::move(binary)) {}

    CoreSupervisor::~CoreSupervisor() { stop(); }

    auto CoreSupervisor::last_error(this CoreSupervisor const& self) -> std::string {
        std::scoped_lock lk(self.impl_->state_mu);
        return self.impl_->last_error;
    }

    auto CoreSupervisor::running(this CoreSupervisor const& self) noexcept -> bool {
        std::scoped_lock lk(self.impl_->state_mu);
        if (self.impl_->stopping) return false;
#ifdef _WIN32
        if (!self.impl_->process) return false;
        DWORD code = 0;
        if (::GetExitCodeProcess(self.impl_->process, &code) && code == STILL_ACTIVE) return true;
        ::CloseHandle(self.impl_->process);
        self.impl_->process = nullptr;
        if (self.impl_->job) {
            ::CloseHandle(self.impl_->job);
            self.impl_->job = nullptr;
        }
        self.impl_->last_error = format_win_exit_error(self.impl_->startup_log, code);
        return false;
#else
        if (self.impl_->pid <= 0) return false;
        int status = 0;
        pid_t res = ::waitpid(self.impl_->pid, &status, WNOHANG);
        if (res == self.impl_->pid) {
            self.impl_->pid = -1;
            self.impl_->last_error = format_posix_exit_error(self.impl_->startup_log, status);
            return false;
        }
        if (res < 0) {
            if (errno == EINTR) return true;
            self.impl_->pid = -1;
            return false;
        }
        return res == 0;
#endif
    }

    namespace {
#ifdef _WIN32
        auto query_win_working_set_bytes(HANDLE proc) noexcept -> std::uint64_t {
            if (!proc) return 0;
            PROCESS_MEMORY_COUNTERS pmc{};
            pmc.cb = sizeof(pmc);
            if (::K32GetProcessMemoryInfo(proc, &pmc, sizeof(pmc))) {
                return static_cast<std::uint64_t>(pmc.WorkingSetSize);
            }
            return 0;
        }
#elif defined(__linux__)
        auto read_proc_smaps_rollup_pss_bytes(char const* smaps_path) noexcept -> std::uint64_t {
            if (!smaps_path || !*smaps_path) return 0;
            int fd = ::open(smaps_path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) return 0;
            char buf[2048]{};
            std::size_t total = 0;
            while (total < sizeof(buf) - 1) {
                ssize_t n = ::read(fd, buf + total, sizeof(buf) - 1 - total);
                if (n < 0) {
                    if (errno == EINTR) continue;
                    total = 0;
                    break;
                }
                if (n == 0) break;
                total += static_cast<std::size_t>(n);
            }
            ::close(fd);
            if (total == 0) return 0;
            std::string_view sv(buf, total);
            std::size_t pos = 0;
            while (pos < sv.size()) {
                auto nl = sv.find('\n', pos);
                auto line = sv.substr(pos, nl == std::string_view::npos ? sv.size() - pos : nl - pos);
                if (line.starts_with("Pss:")) {
                    auto rest = line.substr(4);
                    while (!rest.empty() && (rest.front() == ' ' || rest.front() == '\t')) rest.remove_prefix(1);
                    std::uint64_t pss_kb = 0;
                    auto [ptr, ec] = std::from_chars(rest.data(), rest.data() + rest.size(), pss_kb);
                    if (ec == std::errc{} && (ptr == rest.data() + rest.size() || *ptr == ' ' || *ptr == '\t' || *ptr == '\r')) {
                        constexpr std::uint64_t kKiB = 1024;
                        if (pss_kb <= std::numeric_limits<std::uint64_t>::max() / kKiB) return pss_kb * kKiB;
                    }
                    return 0;
                }
                if (nl == std::string_view::npos) break;
                pos = nl + 1;
            }
            return 0;
        }

        auto read_proc_statm_rss_bytes(char const* statm_path) noexcept -> std::uint64_t {
            if (!statm_path || !*statm_path) return 0;
            int fd = ::open(statm_path, O_RDONLY | O_CLOEXEC);
            if (fd < 0) return 0;
            char buf[128]{};
            ssize_t n = 0;
            do { n = ::read(fd, buf, sizeof(buf) - 1); } while (n < 0 && errno == EINTR);
            ::close(fd);
            if (n <= 0) return 0;
            std::string_view sv(buf, static_cast<std::size_t>(n));
            auto sp1 = sv.find(' ');
            if (sp1 == std::string_view::npos) return 0;
            while (sp1 < sv.size() && sv[sp1] == ' ') ++sp1;
            auto sp2 = sv.find_first_of(" \t\r\n", sp1);
            auto rss_sv = sv.substr(sp1, sp2 == std::string_view::npos ? sv.size() - sp1 : sp2 - sp1);
            std::uint64_t rss_pages = 0;
            auto [ptr, ec] = std::from_chars(rss_sv.data(), rss_sv.data() + rss_sv.size(), rss_pages);
            if (ec != std::errc{} || ptr != rss_sv.data() + rss_sv.size()) return 0;
            long const page_size = ::sysconf(_SC_PAGESIZE);
            if (page_size <= 0) return 0;
            auto const page_u64 = static_cast<std::uint64_t>(page_size);
            if (rss_pages > std::numeric_limits<std::uint64_t>::max() / page_u64) return 0;
            return rss_pages * page_u64;
        }

        auto read_proc_memory_bytes(char const* smaps_path, char const* statm_path) noexcept -> std::uint64_t {
            if (auto const pss = read_proc_smaps_rollup_pss_bytes(smaps_path); pss > 0) return pss;
            return read_proc_statm_rss_bytes(statm_path);
        }
#endif
    }

    auto current_process_memory_bytes() noexcept -> std::uint64_t {
#ifdef _WIN32
        return query_win_working_set_bytes(::GetCurrentProcess());
#elif defined(__linux__)
        return read_proc_memory_bytes("/proc/self/smaps_rollup", "/proc/self/statm");
#else
        return 0;
#endif
    }

    auto CoreSupervisor::memory_bytes(this CoreSupervisor const& self) noexcept -> std::uint64_t {
        if (!self.impl_) return 0;
        try {
#ifdef _WIN32
            std::scoped_lock lk(self.impl_->state_mu);
            if (self.impl_->stopping || !self.impl_->process) return 0;
            return query_win_working_set_bytes(self.impl_->process);
#elif defined(__linux__)
            pid_t pid = -1;
            {
                std::scoped_lock lk(self.impl_->state_mu);
                if (self.impl_->stopping) return 0;
                pid = self.impl_->pid;
            }
            if (pid <= 0) return 0;
            char smaps_path[64]{};
            auto smaps_res = std::format_to_n(smaps_path, sizeof(smaps_path) - 1, "/proc/{}/smaps_rollup", static_cast<long>(pid));
            *smaps_res.out = '\0';
            char statm_path[64]{};
            auto statm_res = std::format_to_n(statm_path, sizeof(statm_path) - 1, "/proc/{}/statm", static_cast<long>(pid));
            *statm_res.out = '\0';
            return read_proc_memory_bytes(smaps_path, statm_path);
#else
            return 0;
#endif
        } catch (...) {
            return 0;
        }
    }

    auto CoreSupervisor::start(this CoreSupervisor& self, std::filesystem::path const& config_path) -> bool {
        std::unique_lock lifecycle_lock(self.impl_->lifecycle_mu);
        if (self.running()) return true;

        auto set_error = [&](std::string msg) {
            std::scoped_lock lk(self.impl_->state_mu);
            self.impl_->last_error = std::move(msg);
        };
        std::error_code file_ec;
        if (!std::filesystem::is_regular_file(self.binary_, file_ec)) {
            set_error("未找到 nexus 核心二进制: " + self.binary_.string());
            return false;
        }
        if (!std::filesystem::is_regular_file(config_path, file_ec)) {
            set_error("配置文件不存在: " + config_path.string());
            return false;
        }

        auto workdir = config_path.parent_path();
        std::error_code dir_ec;
        bool has_dir = !workdir.empty() && std::filesystem::is_directory(workdir, dir_ec);
        std::filesystem::path log_path;
        if (has_dir) {
            log_path = workdir / ".core-run.log";
        } else {
            std::error_code tmp_ec;
            auto tmp = std::filesystem::temp_directory_path(tmp_ec);
#ifdef _WIN32
            if (tmp_ec || tmp.empty()) tmp = ".";
#else
            if (tmp_ec || tmp.empty()) tmp = "/tmp";
#endif
            log_path = tmp / "nexus-core-run.log";
        }

#ifdef _WIN32
        std::vector<std::wstring> args{self.binary_.wstring()};
        if (has_dir) {
            args.push_back(L"-D");
            args.push_back(workdir.wstring());
        }
        args.push_back(L"run");
        args.push_back(L"--config");
        args.push_back(config_path.wstring());

        SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
        HANDLE log_handle = ::CreateFileW(log_path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                          &sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        if (log_handle != INVALID_HANDLE_VALUE) {
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdInput = INVALID_HANDLE_VALUE;
            si.hStdOutput = log_handle;
            si.hStdError = log_handle;
        }
        auto cmd = build_win_cmdline(args);
        PROCESS_INFORMATION pi{};
        BOOL created = ::CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, log_handle != INVALID_HANDLE_VALUE ? TRUE : FALSE,
                                        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, nullptr, nullptr, &si, &pi);
        if (log_handle != INVALID_HANDLE_VALUE) ::CloseHandle(log_handle);
        if (!created) {
            set_error(std::format("CreateProcessW failed ({})", ::GetLastError()));
            return false;
        }
        ::CloseHandle(pi.hThread);
        HANDLE job_h = ::CreateJobObjectW(nullptr, nullptr);
        if (job_h) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
            jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if (!::SetInformationJobObject(job_h, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli)) ||
                !::AssignProcessToJobObject(job_h, pi.hProcess)) {
                ::CloseHandle(job_h);
                job_h = nullptr;
            }
        }
        if (::WaitForSingleObject(pi.hProcess, 200) == WAIT_OBJECT_0) {
            DWORD code = 1;
            ::GetExitCodeProcess(pi.hProcess, &code);
            ::CloseHandle(pi.hProcess);
            if (job_h) ::CloseHandle(job_h);
            set_error(format_win_exit_error(log_path, code));
            return false;
        }
        {
            std::scoped_lock lk(self.impl_->state_mu);
            self.impl_->process = pi.hProcess;
            self.impl_->job = job_h;
            self.impl_->stopping = false;
            self.impl_->startup_log = std::move(log_path);
            self.impl_->last_error.clear();
        }
        return true;
#else
        std::vector<std::string> args{self.binary_.string()};
        if (has_dir) { args.push_back("-D"); args.push_back(workdir.string()); }
        args.push_back("run"); args.push_back("--config"); args.push_back(config_path.string());
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
            set_error(std::string("fork failed: ") + std::strerror(errno));
            return false;
        }
        if (child == 0) {
#ifdef __linux__
            (void)::prctl(PR_SET_PDEATHSIG, SIGTERM);
#endif
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

        // Give the core 200ms to fail fast on invalid config or bound port collisions before declaring startup ok.
        int status = 0;
        pid_t res = 0;
        for (int i = 0; i < 8; ++i) {
            res = ::waitpid(child, &status, WNOHANG);
            if (res != 0) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
        if (res == child) {
            set_error(format_posix_exit_error(log_path, status));
            return false;
        }
        if (res < 0 && errno != EINTR) {
            set_error(std::string("waitpid failed: ") + std::strerror(errno));
            return false;
        }
        {
            std::scoped_lock lk(self.impl_->state_mu);
            self.impl_->pid = child;
            self.impl_->stopping = false;
            self.impl_->startup_log = std::move(log_path);
            self.impl_->last_error.clear();
        }
        return true;
#endif
    }

    auto CoreSupervisor::stop(this CoreSupervisor& self) -> void {
        std::unique_lock lifecycle_lock(self.impl_->lifecycle_mu);
#ifdef _WIN32
        HANDLE target = nullptr;
        HANDLE job_h = nullptr;
        {
            std::scoped_lock lk(self.impl_->state_mu);
            target = self.impl_->process;
            job_h = self.impl_->job;
            if (!target && !job_h) return;
            if (!target) {
                self.impl_->job = nullptr;
            } else {
                self.impl_->stopping = true;
            }
        }
        if (!target) {
            ::CloseHandle(job_h);
            return;
        }
        auto ev_name = L"Local\\nexus-stop-" + std::to_wstring(::GetProcessId(target));
        if (HANDLE ev = ::OpenEventW(EVENT_MODIFY_STATE, FALSE, ev_name.c_str())) {
            ::SetEvent(ev); ::CloseHandle(ev);
        }
        if (::WaitForSingleObject(target, 1500) == WAIT_TIMEOUT) {
            ::TerminateProcess(target, 0);
            ::WaitForSingleObject(target, 1000);
        }
        ::CloseHandle(target);
        if (job_h) ::CloseHandle(job_h);
        {
            std::scoped_lock lk(self.impl_->state_mu);
            self.impl_->process = nullptr;
            self.impl_->job = nullptr;
            self.impl_->stopping = false;
        }
#else
        pid_t target_pid = -1;
        {
            std::scoped_lock lk(self.impl_->state_mu);
            target_pid = self.impl_->pid;
            if (target_pid <= 0) return;
            self.impl_->stopping = true;
        }
        ::kill(target_pid, SIGTERM);
        for (int i = 0; i < 30; ++i) {
            int status = 0;
            pid_t res = ::waitpid(target_pid, &status, WNOHANG);
            if (res == target_pid || (res < 0 && errno == ECHILD)) {
                std::scoped_lock lk(self.impl_->state_mu);
                self.impl_->pid = -1;
                self.impl_->stopping = false;
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        ::kill(target_pid, SIGKILL);
        int status = 0;
        while (::waitpid(target_pid, &status, 0) < 0 && errno == EINTR) {}
        {
            std::scoped_lock lk(self.impl_->state_mu);
            self.impl_->pid = -1;
            self.impl_->stopping = false;
        }
#endif
    }

    auto CoreSupervisor::validate_config(
        this CoreSupervisor const& self,
        std::filesystem::path const& config_path) -> ValidationResult {
        std::error_code ec;
        if (!std::filesystem::is_regular_file(self.binary_, ec)) {
            return {false, "未找到 nexus 核心二进制: " + self.binary_.string()};
        }
        auto workdir = config_path.parent_path();
        bool has_dir = !workdir.empty() && std::filesystem::is_directory(workdir, ec);
#ifdef _WIN32
        std::vector<std::wstring> args{self.binary_.wstring()};
        if (has_dir) { args.push_back(L"-D"); args.push_back(workdir.wstring()); }
        args.push_back(L"check"); args.push_back(L"--config"); args.push_back(config_path.wstring());
        return run_capture_win(args, "配置校验通过", "配置校验失败");
#else
        std::vector<std::string> args{self.binary_.string()};
        if (has_dir) { args.push_back("-D"); args.push_back(workdir.string()); }
        args.push_back("check"); args.push_back("--config"); args.push_back(config_path.string());
        return run_capture_posix(std::move(args), "配置校验通过", "配置校验失败");
#endif
    }

    auto CoreSupervisor::explain_rule(
        this CoreSupervisor const& self,
        std::filesystem::path const& config_path,
        std::string_view inbound,
        std::string_view network,
        std::string_view target,
        std::string_view extra_options) -> ValidationResult {
        std::error_code ec;
        if (!std::filesystem::is_regular_file(self.binary_, ec))
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
        std::vector<std::wstring> args{
            self.binary_.wstring(), L"rule", L"explain", config_path.wstring(),
            utf8_to_wide(inbound), utf8_to_wide(network), utf8_to_wide(target), L"--oneline"
        };
        for (auto const& e : extras) args.push_back(utf8_to_wide(e));
        return run_capture_win(args, "规则测试通过", "规则测试失败");
#else
        std::vector<std::string> args{self.binary_.string(), "rule", "explain",
            config_path.string(), std::string(inbound), std::string(network), std::string(target), "--oneline"};
        for (auto& e : extras) args.push_back(std::move(e));
        return run_capture_posix(std::move(args), "ok", "rule explain failed");
#endif
    }
}
