module;

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <aclapi.h>
#include <psapi.h>
#include <sddl.h>
#include <shellapi.h>
#else
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#ifdef __APPLE__
#include <libproc.h>
#include <mach-o/dyld.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#endif
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

module desktop.core_supervisor;

import std;
import desktop.tun_helper_protocol;
import desktop.tun_privilege;

#include "core_supervisor_detail.hpp"
#include "tun_helper_client.hpp"
#include "core_supervisor_elevated.hpp"

namespace desktop {
    using namespace detail;

    struct CoreSupervisor::Impl {
        std::mutex lifecycle_mu;
        mutable std::mutex state_mu;
        bool stopping = false;
        bool elevated_session = false;
        bool persistent_helper_active = false;
        bool helper_cached_running = false;
        std::chrono::steady_clock::time_point helper_last_checked{};
        bool last_start_cancelled = false;
        std::string last_error;
        std::filesystem::path startup_log;
#ifdef _WIN32
        HANDLE process = nullptr;
        HANDLE job = nullptr;
#else
        pid_t pid = -1;
        pid_t signal_pid = -1;
        uid_t elevated_uid = 0;
        std::filesystem::path elevated_canon_bin;
        std::string elevated_config_path;
#endif
    };

    CoreSupervisor::CoreSupervisor(std::filesystem::path binary)
        : impl_(std::make_unique<Impl>()), binary_(std::move(binary)) {}

    CoreSupervisor::~CoreSupervisor() { stop(); }

    auto CoreSupervisor::last_error(this CoreSupervisor const& self) -> std::string {
        std::scoped_lock lk(self.impl_->state_mu);
        return self.impl_->last_error;
    }

    auto CoreSupervisor::elevated_session(this CoreSupervisor const& self) noexcept -> bool {
        if (!self.impl_) return false;
        std::scoped_lock lk(self.impl_->state_mu);
        return self.impl_->elevated_session;
    }

    auto CoreSupervisor::using_persistent_helper(this CoreSupervisor const& self) noexcept -> bool {
        if (!self.impl_) return false;
        std::scoped_lock lk(self.impl_->state_mu);
        return self.impl_->persistent_helper_active;
    }

    auto CoreSupervisor::last_start_cancelled(this CoreSupervisor const& self) noexcept -> bool {
        if (!self.impl_) return false;
        std::scoped_lock lk(self.impl_->state_mu);
        return self.impl_->last_start_cancelled;
    }

    auto CoreSupervisor::binary_path(this CoreSupervisor const& self) noexcept -> std::filesystem::path const& {
        return self.binary_;
    }

    auto CoreSupervisor::running(this CoreSupervisor const& self) noexcept -> bool {
        bool check_helper = false;
        auto const now = std::chrono::steady_clock::now();
        {
            std::scoped_lock lk(self.impl_->state_mu);
            if (self.impl_->stopping) return false;
            if (self.impl_->persistent_helper_active) {
                if ((now - self.impl_->helper_last_checked) < std::chrono::milliseconds(750)) {
                    return self.impl_->helper_cached_running;
                }
                check_helper = true;
            }
        }
        if (check_helper) {
            auto r = tun_helper_rpc(TunHelperCommand::status, 1500);
            std::scoped_lock lk(self.impl_->state_mu);
            if (!self.impl_->persistent_helper_active) return false;
            self.impl_->helper_last_checked = std::chrono::steady_clock::now();
            if (r.ok && r.running) {
                self.impl_->helper_cached_running = true;
                return true;
            }
            self.impl_->helper_cached_running = false;
            self.impl_->persistent_helper_active = false;
            if (!r.ok && !r.detail.empty()) self.impl_->last_error = r.detail;
            return false;
        }
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
        self.impl_->elevated_session = false;
        self.impl_->last_error = format_win_exit_error(self.impl_->startup_log, code);
        return false;
#else
        if (self.impl_->pid <= 0) return false;
#ifdef __APPLE__
        if (self.impl_->elevated_session) {
            if (macos_pid_matches_binary(self.impl_->pid, self.impl_->elevated_canon_bin)) return true;
            self.impl_->pid = -1;
            self.impl_->signal_pid = -1;
            self.impl_->elevated_canon_bin.clear();
            self.impl_->elevated_session = false;
            return false;
        }
#endif
        int status = 0;
        pid_t res = ::waitpid(self.impl_->pid, &status, WNOHANG);
        if (res == self.impl_->pid) {
            self.impl_->pid = -1;
            self.impl_->signal_pid = -1;
            self.impl_->elevated_session = false;
            self.impl_->last_error = format_posix_exit_error(self.impl_->startup_log, status);
            return false;
        }
        if (res < 0) {
            if (errno == EINTR) return true;
            self.impl_->pid = -1;
            self.impl_->signal_pid = -1;
            self.impl_->elevated_session = false;
            return false;
        }
        return res == 0;
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
                pid = self.impl_->signal_pid > 0 ? self.impl_->signal_pid : self.impl_->pid;
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

    auto CoreSupervisor::start(this CoreSupervisor& self, std::filesystem::path const& config_path, CoreStartOptions opts) -> bool {
        std::unique_lock lifecycle_lock(self.impl_->lifecycle_mu);
        if (self.running()) return true;

        auto set_error = [&](std::string msg, bool cancelled = false) {
            std::scoped_lock lk(self.impl_->state_mu);
            self.impl_->last_error = std::move(msg);
            self.impl_->last_start_cancelled = cancelled;
        };
        {
            std::scoped_lock lk(self.impl_->state_mu);
            self.impl_->last_start_cancelled = false;
        }
        if (opts.use_persistent_helper) {
            auto r = tun_helper_rpc(TunHelperCommand::start, 8000);
            if (!r.ok) { set_error(r.detail.empty() ? "Persistent TUN helper start failed" : r.detail); return false; }
            std::scoped_lock lk(self.impl_->state_mu);
            self.impl_->persistent_helper_active = true;
            self.impl_->helper_cached_running = true;
            self.impl_->helper_last_checked = std::chrono::steady_clock::now();
            self.impl_->elevated_session = false;
            self.impl_->stopping = false;
            self.impl_->last_error.clear();
            return true;
        }
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
        if (opts.elevate_session) {
            auto res = start_elevated_win(self.binary_, config_path, workdir, has_dir, log_path);
            if (!res.ok) { set_error(std::move(res.error), res.cancelled); return false; }
            std::scoped_lock lk(self.impl_->state_mu);
            self.impl_->process = res.process;
            self.impl_->job = nullptr;
            self.impl_->elevated_session = true;
            self.impl_->stopping = false;
            self.impl_->startup_log = std::move(log_path);
            self.impl_->last_error.clear();
            return true;
        }
        auto res = spawn_unprivileged_win(self.binary_, config_path, workdir, has_dir, log_path);
        if (!res.ok) { set_error(std::move(res.error)); return false; }
        {
            std::scoped_lock lk(self.impl_->state_mu);
            self.impl_->process = res.process;
            self.impl_->job = res.job;
            self.impl_->elevated_session = false;
            self.impl_->stopping = false;
            self.impl_->startup_log = std::move(log_path);
            self.impl_->last_error.clear();
        }
        return true;
#else
        if (opts.elevate_session) {
#ifdef __linux__
            auto res = start_elevated_linux(self.binary_, config_path, workdir, has_dir, log_path);
            if (!res.ok) { set_error(std::move(res.error), res.cancelled); return false; }
            std::scoped_lock lk(self.impl_->state_mu);
            self.impl_->pid = res.wait_pid;
            self.impl_->signal_pid = res.signal_pid;
            self.impl_->elevated_uid = res.expected_uid;
            self.impl_->elevated_canon_bin = std::move(res.canonical_bin);
            self.impl_->elevated_config_path = std::move(res.config_path);
            self.impl_->elevated_session = true;
            self.impl_->stopping = false;
            self.impl_->startup_log = std::move(log_path);
            self.impl_->last_error.clear();
            return true;
#elif defined(__APPLE__)
            auto res = start_elevated_macos(self.binary_, config_path, workdir, has_dir);
            if (!res.ok) { set_error(std::move(res.error), res.cancelled); return false; }
            std::scoped_lock lk(self.impl_->state_mu);
            self.impl_->pid = res.pid;
            self.impl_->signal_pid = res.pid;
            self.impl_->elevated_canon_bin = std::move(res.canonical_bin);
            self.impl_->elevated_session = true;
            self.impl_->stopping = false;
            self.impl_->startup_log = std::move(log_path);
            self.impl_->last_error.clear();
            return true;
#else
            set_error("Session-only elevation unsupported on this platform");
            return false;
#endif
        }
        auto res = spawn_unprivileged_posix(self.binary_, config_path, workdir, has_dir, log_path);
        if (!res.ok) { set_error(std::move(res.error)); return false; }
        {
            std::scoped_lock lk(self.impl_->state_mu);
            self.impl_->pid = res.pid;
            self.impl_->signal_pid = -1;
            self.impl_->elevated_session = false;
            self.impl_->stopping = false;
            self.impl_->startup_log = std::move(log_path);
            self.impl_->last_error.clear();
        }
        return true;
#endif
    }

    auto CoreSupervisor::stop(this CoreSupervisor& self) -> void {
        std::unique_lock lifecycle_lock(self.impl_->lifecycle_mu);
        bool stop_helper = false;
        {
            std::scoped_lock lk(self.impl_->state_mu);
            if (self.impl_->persistent_helper_active) {
                stop_helper = true;
                self.impl_->stopping = true;
            }
        }
        if (stop_helper) {
            auto r = tun_helper_rpc(TunHelperCommand::stop, 5000);
            std::scoped_lock lk(self.impl_->state_mu);
            self.impl_->persistent_helper_active = false;
            self.impl_->helper_cached_running = false;
            self.impl_->stopping = false;
            if (!r.ok && !r.detail.empty()) self.impl_->last_error = std::move(r.detail);
            return;
        }
#ifdef _WIN32
        HANDLE target = nullptr;
        HANDLE job_h = nullptr;
        bool is_elev = false;
        {
            std::scoped_lock lk(self.impl_->state_mu);
            target = self.impl_->process;
            job_h = self.impl_->job;
            is_elev = self.impl_->elevated_session;
            if (!target && !job_h) return;
            if (!target) self.impl_->job = nullptr;
            else self.impl_->stopping = true;
        }
        if (!target) { ::CloseHandle(job_h); return; }
        auto stop_err = stop_win_process(target, job_h, is_elev);
        {
            std::scoped_lock lk(self.impl_->state_mu);
            self.impl_->process = nullptr;
            self.impl_->job = nullptr;
            self.impl_->elevated_session = false;
            self.impl_->stopping = false;
            if (!stop_err.empty()) self.impl_->last_error = std::move(stop_err);
        }
#else
        pid_t wait_pid = -1;
        pid_t sig_pid = -1;
        uid_t elev_uid = 0;
        bool is_elev_sess = false;
        std::filesystem::path elev_bin;
        std::string elev_cfg;
        {
            std::scoped_lock lk(self.impl_->state_mu);
            wait_pid = self.impl_->pid;
            sig_pid = self.impl_->signal_pid > 0 ? self.impl_->signal_pid : self.impl_->pid;
            elev_uid = self.impl_->elevated_uid;
            is_elev_sess = self.impl_->elevated_session;
            elev_bin = self.impl_->elevated_canon_bin;
            elev_cfg = self.impl_->elevated_config_path;
            if (wait_pid <= 0) return;
            self.impl_->stopping = true;
        }
#ifdef __APPLE__
        if (is_elev_sess) stop_elevated_macos(wait_pid, elev_bin);
        else stop_posix_process(wait_pid, sig_pid, elev_uid, elev_bin, elev_cfg);
#else
        (void)is_elev_sess;
        stop_posix_process(wait_pid, sig_pid, elev_uid, elev_bin, elev_cfg);
#endif
        {
            std::scoped_lock lk(self.impl_->state_mu);
            self.impl_->pid = -1;
            self.impl_->signal_pid = -1;
            self.impl_->elevated_uid = 0;
            self.impl_->elevated_canon_bin.clear();
            self.impl_->elevated_config_path.clear();
            self.impl_->elevated_session = false;
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
