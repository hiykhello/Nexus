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
#include <sddl.h>
#include <shellapi.h>
#include <winsvc.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/statvfs.h>
#include <sys/xattr.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#endif
#endif

module desktop.tun_privilege;

import std;
import desktop.service_installer;
import desktop.tun_helper_protocol;

#include "tun_helper_client.hpp"

namespace desktop {
    namespace {
        constexpr std::uint64_t kCapNetAdminBit = 1ULL << 12;

        auto is_ws(char c) noexcept -> bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

        auto trim_sv(std::string_view sv) noexcept -> std::string_view {
            while (!sv.empty() && is_ws(sv.front())) sv.remove_prefix(1);
            while (!sv.empty() && is_ws(sv.back())) sv.remove_suffix(1);
            return sv;
        }

        auto ascii_lower(char c) noexcept -> char {
            return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
        }

        auto ieq_ascii(std::string_view a, std::string_view b) noexcept -> bool {
            if (a.size() != b.size()) return false;
            for (std::size_t i = 0; i < a.size(); ++i) {
                if (ascii_lower(a[i]) != ascii_lower(b[i])) return false;
            }
            return true;
        }

        auto icontains_ascii(std::string_view sv, char lower_ch) noexcept -> bool {
            for (char c : sv) if (ascii_lower(c) == lower_ch) return true;
            return false;
        }

        auto canonicalize_binary(std::filesystem::path const& p) -> std::filesystem::path {
            if (p.empty()) return {};
            std::error_code ec;
            auto canon = std::filesystem::weakly_canonical(p, ec);
            return (!ec && !canon.empty()) ? canon : p;
        }

        auto is_executable_file(std::filesystem::path const& p) -> bool {
            std::error_code ec;
            if (!std::filesystem::is_regular_file(p, ec)) return false;
#ifdef _WIN32
            return true;
#else
            return ::access(p.c_str(), X_OK) == 0;
#endif
        }

        auto tr_msg(bool is_en, std::string_view zh, std::string_view en) -> std::string { return std::string(is_en ? en : zh); }

#ifdef __linux__
        constexpr std::uint32_t kVfsCapFlagsEffective = 0x000001u;
        constexpr std::uint32_t kVfsCapRevisionMask = 0xFF000000u;
        constexpr std::uint32_t kVfsCapRevision2 = 0x02000000u;
        constexpr std::uint32_t kVfsCapRevision3 = 0x03000000u;

        auto read_le_u32(unsigned char const* p) noexcept -> std::uint32_t {
            return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8)
                | (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
        }

        auto fs_has_nosuid(std::filesystem::path const& p) noexcept -> bool {
            struct statvfs sv{};
            return ::statvfs(p.c_str(), &sv) == 0 && (sv.f_flag & ST_NOSUID) != 0;
        }

        auto binary_has_net_admin_file_cap(std::filesystem::path const& canonical_bin) -> bool {
            if (canonical_bin.empty() || fs_has_nosuid(canonical_bin)) return false;
            unsigned char buf[64]{};
            auto const n = ::getxattr(canonical_bin.c_str(), "security.capability", buf, sizeof(buf));
            if (n >= 20) {
                auto const magic = read_le_u32(buf);
                auto const rev = magic & kVfsCapRevisionMask;
                bool const rev_ok = (rev == kVfsCapRevision2) || (rev == kVfsCapRevision3 && n >= 24 && read_le_u32(buf + 20) == 0);
                return rev_ok && (magic & kVfsCapFlagsEffective) != 0 && (read_le_u32(buf + 4) & (1u << 12)) != 0;
            }
            if (n < 0 && (errno == ENODATA || errno == ENOENT)) return false;
            if (auto getcap = resolve_executable_path("getcap")) {
                auto out = detail::run_posix_execv_capture({getcap->string(), canonical_bin.string()});
                if (out.launched && out.exit_code == 0) return parse_getcap_has_net_admin(out.output);
            }
            return false;
        }

        auto process_has_net_admin_cap() -> bool {
            std::ifstream in("/proc/self/status");
            if (!in) return ::geteuid() == 0;
            std::ostringstream ss;
            ss << in.rdbuf();
            return parse_linux_cap_eff_has_net_admin(ss.str());
        }
#elif defined(_WIN32)
        auto is_win_process_elevated() noexcept -> bool {
            HANDLE tok = nullptr;
            if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
            TOKEN_ELEVATION elev{};
            DWORD ret = 0;
            bool ok = ::GetTokenInformation(tok, TokenElevation, &elev, sizeof(elev), &ret) != FALSE && elev.TokenIsElevated != 0;
            ::CloseHandle(tok);
            return ok;
        }

        auto win_tun_helper_service_exists() noexcept -> bool {
            SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
            if (!scm) return false;
            auto name_w = detail::utf8_to_wide_helper(kWinTunHelperServiceName);
            SC_HANDLE svc = ::OpenServiceW(scm, name_w.c_str(), SERVICE_QUERY_STATUS);
            bool exists = svc != nullptr;
            if (svc) ::CloseServiceHandle(svc);
            ::CloseServiceHandle(scm);
            return exists;
        }
#endif
    }

    auto parse_linux_cap_eff_has_net_admin(std::string_view proc_status_text) noexcept -> bool {
        while (!proc_status_text.empty()) {
            auto nl = proc_status_text.find('\n');
            auto line = nl == std::string_view::npos ? proc_status_text : proc_status_text.substr(0, nl);
            proc_status_text = nl == std::string_view::npos ? std::string_view{} : proc_status_text.substr(nl + 1);
            if (!line.starts_with("CapEff:")) continue;
            auto val = trim_sv(line.substr(7));
            if (val.starts_with("0x") || val.starts_with("0X")) val.remove_prefix(2);
            if (val.empty()) return false;
            std::uint64_t mask = 0;
            auto [ptr, ec] = std::from_chars(val.data(), val.data() + val.size(), mask, 16);
            return ec == std::errc{} && ptr == val.data() + val.size() && (mask & kCapNetAdminBit) != 0;
        }
        return false;
    }

    auto parse_getcap_has_net_admin(std::string_view getcap_output) noexcept -> bool {
        std::string_view rem(getcap_output);
        while (!rem.empty()) {
            while (!rem.empty() && is_ws(rem.front())) rem.remove_prefix(1);
            if (rem.empty()) break;
            auto end = rem.find_first_of(" \t\r\n");
            auto tok = end == std::string_view::npos ? rem : rem.substr(0, end);
            rem = end == std::string_view::npos ? std::string_view{} : rem.substr(end);
            auto op = tok.find_first_of("=+");
            if (op == std::string_view::npos || op == 0 || op + 1 >= tok.size()) continue;
            auto caps_part = tok.substr(0, op);
            auto flags_part = tok.substr(op + 1);
            if (auto minus = flags_part.find('-'); minus != std::string_view::npos) flags_part = flags_part.substr(0, minus);
            if (!icontains_ascii(flags_part, 'e') || !icontains_ascii(flags_part, 'p')) continue;
            while (!caps_part.empty()) {
                auto comma = caps_part.find(',');
                auto cap = comma == std::string_view::npos ? caps_part : caps_part.substr(0, comma);
                caps_part = comma == std::string_view::npos ? std::string_view{} : caps_part.substr(comma + 1);
                if (ieq_ascii(cap, "cap_net_admin")) return true;
            }
        }
        return false;
    }

    auto match_linux_cmdline_for_core(
        std::string_view proc_cmdline_nul_bytes,
        std::string_view expected_binary,
        std::string_view expected_config) noexcept -> bool {
        if (proc_cmdline_nul_bytes.empty() || expected_binary.empty() || expected_config.empty()) return false;
        auto next_tok = [&]() -> std::optional<std::string_view> {
            if (proc_cmdline_nul_bytes.empty()) return std::nullopt;
            auto nul = proc_cmdline_nul_bytes.find('\0');
            if (nul == std::string_view::npos) {
                auto tok = proc_cmdline_nul_bytes;
                proc_cmdline_nul_bytes = {};
                return tok;
            }
            auto tok = proc_cmdline_nul_bytes.substr(0, nul);
            proc_cmdline_nul_bytes.remove_prefix(nul + 1);
            return tok;
        };
        auto argv0 = next_tok();
        if (!argv0 || *argv0 != expected_binary) return false;
        bool expect_cfg = false;
        while (auto tok = next_tok()) {
            if (expect_cfg) return *tok == expected_config;
            if (*tok == "--config") expect_cfg = true;
        }
        return false;
    }

    auto build_linux_setcap_grant_argv(
        std::filesystem::path const& core_binary, std::string_view pkexec_bin, std::string_view setcap_bin) -> std::vector<std::string> {
        if (core_binary.empty() || pkexec_bin.empty() || setcap_bin.empty()) return {};
        return {std::string(pkexec_bin), std::string(setcap_bin), "cap_net_admin,cap_net_bind_service=+ep", canonicalize_binary(core_binary).string()};
    }

    auto build_linux_setcap_revoke_argv(
        std::filesystem::path const& core_binary, std::string_view pkexec_bin, std::string_view setcap_bin) -> std::vector<std::string> {
        if (core_binary.empty() || pkexec_bin.empty() || setcap_bin.empty()) return {};
        return {std::string(pkexec_bin), std::string(setcap_bin), "-r", canonicalize_binary(core_binary).string()};
    }

    auto build_linux_session_elevated_argv(
        std::filesystem::path const& core_binary, std::filesystem::path const& config_path, std::filesystem::path const& workdir,
        std::uint32_t uid, std::uint32_t gid, std::string_view pkexec_bin, std::string_view setpriv_bin) -> std::vector<std::string> {
        if (core_binary.empty() || config_path.empty() || pkexec_bin.empty() || setpriv_bin.empty()) return {};
        std::vector<std::string> argv{
            std::string(pkexec_bin), std::string(setpriv_bin),
            std::format("--reuid={}", uid), std::format("--regid={}", gid), "--init-groups",
            "--inh-caps=+net_admin,+net_bind_service", "--ambient-caps=+net_admin,+net_bind_service",
            "--", canonicalize_binary(core_binary).string(),
        };
        if (!workdir.empty()) { argv.push_back("-D"); argv.push_back(workdir.string()); }
        argv.push_back("run"); argv.push_back("--config"); argv.push_back(config_path.string());
        return argv;
    }

    auto resolve_executable_path(std::string_view name, std::span<std::string_view const> fallback_dirs) -> std::optional<std::filesystem::path> {
        if (name.empty()) return std::nullopt;
        if (name.contains('/') || name.contains('\\')) {
            std::filesystem::path direct(name);
            return is_executable_file(direct) ? std::optional<std::filesystem::path>(std::move(direct)) : std::nullopt;
        }
        auto try_dir = [&](std::string_view dir) -> std::optional<std::filesystem::path> {
            if (dir.empty()) return std::nullopt;
            auto candidate = std::filesystem::path(dir) / std::filesystem::path(name);
            return is_executable_file(candidate) ? std::optional<std::filesystem::path>(std::move(candidate)) : std::nullopt;
        };
        if (char const* path_env = std::getenv("PATH"); path_env && *path_env) {
            std::string_view rem(path_env);
#ifdef _WIN32
            constexpr char kSep = ';';
#else
            constexpr char kSep = ':';
#endif
            while (!rem.empty()) {
                auto pos = rem.find(kSep);
                auto dir = pos == std::string_view::npos ? rem : rem.substr(0, pos);
                rem = pos == std::string_view::npos ? std::string_view{} : rem.substr(pos + 1);
                if (auto found = try_dir(dir)) return found;
            }
        }
        for (auto dir : fallback_dirs) if (auto found = try_dir(dir)) return found;
#ifndef _WIN32
        for (std::string_view sys_dir : {"/usr/bin", "/usr/sbin", "/sbin"}) if (auto found = try_dir(sys_dir)) return found;
#endif
        return std::nullopt;
    }

    auto probe_tun_privilege(std::filesystem::path const& core_binary) -> TunPrivilegeProbe {
        TunPrivilegeProbe out{};
#ifdef __linux__
        auto const canon = canonicalize_binary(core_binary);
        auto const pkexec = resolve_executable_path("pkexec");
        auto const setcap = resolve_executable_path("setcap");
        auto const setpriv = resolve_executable_path("setpriv");
        out.supports_persistent = pkexec.has_value() && setcap.has_value() && !fs_has_nosuid(canon);
        out.supports_session_only = pkexec.has_value() && setpriv.has_value();
        if (process_has_net_admin_cap()) {
            out.status = TunPrivilegeStatus::ready_root_or_admin;
            out.has_persistent_grant = binary_has_net_admin_file_cap(canon);
            out.detail = "CAP_NET_ADMIN already active";
            return out;
        }
        if (binary_has_net_admin_file_cap(canon)) {
            out.status = TunPrivilegeStatus::ready_persistent_cap;
            out.has_persistent_grant = true;
            out.detail = "cap_net_admin,cap_net_bind_service=+ep";
            return out;
        }
        if (out.supports_persistent || out.supports_session_only) {
            out.status = TunPrivilegeStatus::needs_elevation;
            out.detail = out.supports_persistent ? "Requires Polkit authorization for TUN" : "Requires per-session pkexec authorization";
            return out;
        }
        out.status = TunPrivilegeStatus::unavailable;
        out.detail = "pkexec / setcap / setpriv unavailable on host";
        return out;
#elif defined(_WIN32)
        auto const search_dir = core_binary.parent_path();
        if (!search_dir.empty() && !detect_wintun_dll(search_dir).has_value()) {
            out.status = TunPrivilegeStatus::unavailable; out.detail = "wintun.dll not found next to nexus.exe"; return out;
        }
        out.supports_persistent = detail::resolve_tun_helper_binary(core_binary).has_value();
        out.supports_session_only = true;
        out.has_persistent_grant = win_tun_helper_service_exists();
        if (is_win_process_elevated()) { out.status = TunPrivilegeStatus::ready_root_or_admin; out.detail = "Administrator token active"; return out; }
        auto const canon = canonicalize_binary(core_binary);
        auto const cur_sha = sha256_file(canon);
        if (auto pinned = detail::win_read_pinned_helper_config(); pinned && cur_sha && *cur_sha == pinned->sha256 &&
            canonicalize_binary(std::filesystem::path(detail::utf8_to_wide_helper(pinned->binary))) == canon &&
            detail::tun_helper_rpc(TunHelperCommand::ping, 1500).ok) {
            out.status = TunPrivilegeStatus::ready_persistent_cap;
            out.has_persistent_grant = true;
            out.helper_required_for_persistent = true;
            out.detail = "NexusTunHelper Windows service active";
            return out;
        }
        out.status = TunPrivilegeStatus::needs_elevation;
        out.detail = out.supports_persistent ? "Requires one-time UAC for NexusTunHelper service" : "Requires per-session UAC elevation for Wintun";
        return out;
#elif defined(__APPLE__)
        auto const osascript = resolve_executable_path("osascript");
        out.supports_session_only = osascript.has_value();
        out.supports_persistent = osascript.has_value() && detail::resolve_tun_helper_binary(core_binary).has_value();
        auto const pinned = detail::macos_read_verified_pinned_config();
        out.has_persistent_grant = pinned.has_value();
        if (::geteuid() == 0) { out.status = TunPrivilegeStatus::ready_root_or_admin; out.detail = "Root privileges active"; return out; }
        auto const canon = canonicalize_binary(core_binary);
        auto const cur_sha = sha256_file(canon);
        if (pinned && !pinned->staged_binary.empty() && cur_sha && *cur_sha == pinned->sha256 &&
            canonicalize_binary(pinned->binary) == canon &&
            detail::tun_helper_rpc(TunHelperCommand::ping, 1500).ok) {
            out.status = TunPrivilegeStatus::ready_persistent_cap;
            out.has_persistent_grant = true;
            out.helper_required_for_persistent = true;
            out.detail = "io.nexus.tun-helper LaunchDaemon active";
            return out;
        }
        if (out.supports_persistent || out.supports_session_only) {
            out.status = TunPrivilegeStatus::needs_elevation;
            out.detail = out.supports_persistent ? "Requires one-time admin authorization for LaunchDaemon" : "Requires per-session macOS admin authorization";
            return out;
        }
        out.status = TunPrivilegeStatus::unavailable; out.detail = "osascript unavailable on host";
        return out;
#else
        if (::geteuid() == 0) { out.status = TunPrivilegeStatus::ready_root_or_admin; out.detail = "Root privileges active"; return out; }
        out.status = TunPrivilegeStatus::unavailable; out.detail = "TUN requires elevated privileges on this platform";
        return out;
#endif
    }

#ifdef __linux__
    namespace {
        auto run_linux_setcap_op(std::filesystem::path const& core_binary, bool grant, bool is_en) -> ElevationResult {
            std::error_code ec;
            auto const canon = canonicalize_binary(core_binary);
            if (!std::filesystem::is_regular_file(canon, ec)) return {false, false, tr_msg(is_en, "未找到 nexus 核心二进制文件", "Core binary not found")};
            auto const pkexec = resolve_executable_path("pkexec");
            auto const setcap = resolve_executable_path("setcap");
            if (!pkexec || !setcap) return {false, false, tr_msg(is_en, "系统缺少 pkexec 或 setcap 工具", "pkexec or setcap not found")};
            auto const argv = grant ? build_linux_setcap_grant_argv(canon, pkexec->string(), setcap->string())
                                    : build_linux_setcap_revoke_argv(canon, pkexec->string(), setcap->string());
            auto const exec = detail::run_posix_execv_capture(argv);
            if (!exec.launched) return {false, false, tr_msg(is_en, "无法启动提权程序 pkexec", "Failed to launch pkexec")};
            if (exec.exit_code == 126 || exec.exit_code == 127) {
                return {false, true, grant ? tr_msg(is_en, "已取消权限授权", "Authorization cancelled") : tr_msg(is_en, "已取消撤销授权", "Revocation cancelled")};
            }
            if (exec.exit_code != 0) {
                return {false, false, !exec.output.empty() ? exec.output
                    : (grant ? tr_msg(is_en, "持久授权失败", "Persistent authorization failed") : tr_msg(is_en, "撤销持久授权失败", "Failed to revoke persistent capability"))};
            }
            if (grant) {
                if (fs_has_nosuid(canon) || !binary_has_net_admin_file_cap(canon)) {
                    return {false, false, tr_msg(is_en,
                        "文件系统不支持持久能力 (nosuid/FUSE)，请关闭持久授权改用按次提权",
                        "Filesystem ignores file capabilities (nosuid/FUSE); switch to Session-Only elevation")};
                }
                return {true, false, tr_msg(is_en, "已授予 TUN 持久权限 (setcap)", "Persistent TUN capability granted")};
            }
            if (binary_has_net_admin_file_cap(canon)) return {false, false, tr_msg(is_en, "撤销后仍检测到文件能力", "File capability still present after revoke")};
            return {true, false, tr_msg(is_en, "已撤销 TUN 持久授权", "Persistent TUN grant revoked")};
        }
    }
#endif

    auto grant_persistent_tun_privilege(
        std::filesystem::path const& core_binary, bool is_en,
        std::filesystem::path const& config_path, std::filesystem::path const& workdir) -> ElevationResult {
#ifdef __linux__
        (void)config_path; (void)workdir;
        return run_linux_setcap_op(core_binary, true, is_en);
#elif defined(_WIN32)
        auto const helper = detail::resolve_tun_helper_binary(core_binary);
        if (!helper) return {false, false, tr_msg(is_en, "未找到 nexus-tun-helper.exe，暂不支持持久服务授权", "nexus-tun-helper.exe not found")};
        if (config_path.empty()) return {false, false, tr_msg(is_en, "缺少有效配置文件路径", "Config path required for persistent helper")};
        auto const sid = detail::win_current_user_sid_string();
        if (!sid) return {false, false, tr_msg(is_en, "无法获取当前用户 SID", "Failed to resolve current Windows user SID")};
        auto const canon_bin = canonicalize_binary(core_binary);
        auto const wd = workdir.empty() ? config_path.parent_path() : workdir;
        std::wstring params = L"--install --binary " + detail::quote_win_param_helper(canon_bin.wstring())
            + L" --config " + detail::quote_win_param_helper(config_path.wstring())
            + L" --workdir " + detail::quote_win_param_helper(wd.wstring())
            + L" --owner-sid " + detail::quote_win_param_helper(detail::utf8_to_wide_helper(*sid));
        auto [launched, code] = detail::run_win_uac_process(helper->wstring(), params, 30000);
        if (!launched) return {false, code == ERROR_CANCELLED, code == ERROR_CANCELLED ? tr_msg(is_en, "已取消权限授权", "Authorization cancelled") : std::format("ShellExecuteExW failed ({})", code)};
        if (code != 0) return {false, false, tr_msg(is_en, "安装 Nexus TUN 服务失败", "Failed to install NexusTunHelper service")};
        if (!detail::tun_helper_rpc(TunHelperCommand::ping, 3000).ok) return {false, false, tr_msg(is_en, "服务已安装但未响应管道检测", "NexusTunHelper installed but pipe ping failed")};
        return {true, false, tr_msg(is_en, "已安装并启动 Nexus TUN 持久服务", "NexusTunHelper persistent service active")};
#elif defined(__APPLE__)
        auto const helper = detail::resolve_tun_helper_binary(core_binary);
        auto const osascript = resolve_executable_path("osascript");
        if (!helper || !osascript) return {false, false, tr_msg(is_en, "未找到 nexus-tun-helper 或 osascript", "nexus-tun-helper or osascript not found")};
        if (config_path.empty()) return {false, false, tr_msg(is_en, "缺少有效配置文件路径", "Config path required for LaunchDaemon helper")};
        auto const canon_bin = canonicalize_binary(core_binary);
        auto const wd = workdir.empty() ? config_path.parent_path() : workdir;
        auto [ok, cancelled, out_msg] = detail::run_macos_osascript_argv({
            helper->string(), "--install", "--binary", canon_bin.string(), "--config", config_path.string(),
            "--workdir", wd.string(), "--owner-uid", std::to_string(static_cast<unsigned long>(::getuid())),
        }, osascript->string());
        if (!ok) return {false, cancelled, cancelled ? tr_msg(is_en, "已取消权限授权", "Authorization cancelled") : (!out_msg.empty() ? out_msg : tr_msg(is_en, "macOS 提权安装失败", "macOS helper install failed"))};
        for (int i = 0; i < 15; ++i) {
            if (detail::tun_helper_rpc(TunHelperCommand::ping, 1000).ok) return {true, false, tr_msg(is_en, "已安装并启动 LaunchDaemon 持久授权", "macOS LaunchDaemon persistent helper active")};
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
        return {false, false, tr_msg(is_en, "LaunchDaemon 已注册但未响应本地套接字", "LaunchDaemon registered but socket ping failed")};
#else
        (void)core_binary; (void)config_path; (void)workdir;
        return {false, false, tr_msg(is_en, "当前平台暂不支持持久授权", "Persistent elevation unsupported on this platform")};
#endif
    }

    auto revoke_persistent_tun_privilege(std::filesystem::path const& core_binary, bool is_en) -> ElevationResult {
#ifdef __linux__
        return run_linux_setcap_op(core_binary, false, is_en);
#elif defined(_WIN32)
        if (auto const helper = detail::resolve_tun_helper_binary(core_binary)) {
            auto [launched, code] = detail::run_win_uac_process(helper->wstring(), L"--uninstall", 30000);
            if (!launched) return {false, code == ERROR_CANCELLED, code == ERROR_CANCELLED ? tr_msg(is_en, "已取消撤销授权", "Revocation cancelled") : std::format("ShellExecuteExW failed ({})", code)};
            return {code == 0, false, code == 0 ? tr_msg(is_en, "已移除 Nexus TUN 持久服务", "NexusTunHelper service removed") : tr_msg(is_en, "移除 Nexus TUN 服务失败", "Failed to remove NexusTunHelper service")};
        }
        auto [launched, code] = detail::run_win_uac_process(L"sc.exe", L"delete NexusTunHelper", 30000);
        if (!launched && code == ERROR_CANCELLED) return {false, true, tr_msg(is_en, "已取消撤销授权", "Revocation cancelled")};
        if (launched && (code == 0 || code == ERROR_SERVICE_DOES_NOT_EXIST)) return {true, false, tr_msg(is_en, "已移除 Nexus TUN 持久服务", "NexusTunHelper service removed")};
        return {false, false, tr_msg(is_en, "移除 Windows 服务失败", "Failed to remove Windows service")};
#elif defined(__APPLE__)
        auto const helper = detail::resolve_tun_helper_binary(core_binary);
        auto const osascript = resolve_executable_path("osascript");
        if (!helper || !osascript) return {false, false, tr_msg(is_en, "未找到 nexus-tun-helper 或 osascript", "nexus-tun-helper or osascript not found")};
        auto [ok, cancelled, out_msg] = detail::run_macos_osascript_argv({helper->string(), "--uninstall"}, osascript->string());
        if (!ok) return {false, cancelled, cancelled ? tr_msg(is_en, "已取消撤销授权", "Revocation cancelled") : (!out_msg.empty() ? out_msg : tr_msg(is_en, "卸载 LaunchDaemon 失败", "Failed to remove LaunchDaemon"))};
        return {true, false, tr_msg(is_en, "已卸载 macOS LaunchDaemon 持久授权", "macOS LaunchDaemon persistent helper removed")};
#else
        (void)core_binary;
        return {false, false, tr_msg(is_en, "当前平台不支持撤销持久授权", "Revocation unsupported on this platform")};
#endif
    }
}
