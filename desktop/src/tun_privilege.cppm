export module desktop.tun_privilege;

import std;

export namespace desktop {
    enum class TunPrivilegeStatus {
        ready_root_or_admin,
        ready_persistent_cap,
        needs_elevation,
        unavailable,
    };

    struct TunPrivilegeProbe {
        TunPrivilegeStatus status = TunPrivilegeStatus::unavailable;
        bool has_persistent_grant = false;
        bool supports_persistent = false;
        bool supports_session_only = false;
        bool helper_required_for_persistent = false;
        std::string detail;
    };

    struct ElevationResult {
        bool ok = false;
        bool cancelled = false;
        std::string message;
    };

    [[nodiscard]] auto parse_linux_cap_eff_has_net_admin(std::string_view proc_status_text) noexcept -> bool;

    [[nodiscard]] auto parse_getcap_has_net_admin(std::string_view getcap_output) noexcept -> bool;

    [[nodiscard]] auto match_linux_cmdline_for_core(
        std::string_view proc_cmdline_nul_bytes,
        std::string_view expected_binary,
        std::string_view expected_config) noexcept -> bool;

    [[nodiscard]] auto build_linux_setcap_grant_argv(
        std::filesystem::path const& core_binary,
        std::string_view pkexec_bin,
        std::string_view setcap_bin) -> std::vector<std::string>;

    [[nodiscard]] auto build_linux_setcap_revoke_argv(
        std::filesystem::path const& core_binary,
        std::string_view pkexec_bin,
        std::string_view setcap_bin) -> std::vector<std::string>;

    [[nodiscard]] auto build_linux_session_elevated_argv(
        std::filesystem::path const& core_binary,
        std::filesystem::path const& config_path,
        std::filesystem::path const& workdir,
        std::uint32_t uid,
        std::uint32_t gid,
        std::string_view pkexec_bin,
        std::string_view setpriv_bin) -> std::vector<std::string>;

    [[nodiscard]] auto resolve_executable_path(
        std::string_view name,
        std::span<std::string_view const> fallback_dirs = {}) -> std::optional<std::filesystem::path>;

    [[nodiscard]] auto probe_tun_privilege(std::filesystem::path const& core_binary) -> TunPrivilegeProbe;

    [[nodiscard]] auto grant_persistent_tun_privilege(
        std::filesystem::path const& core_binary,
        bool is_en = false,
        std::filesystem::path const& config_path = {},
        std::filesystem::path const& workdir = {}) -> ElevationResult;

    [[nodiscard]] auto revoke_persistent_tun_privilege(
        std::filesystem::path const& core_binary,
        bool is_en = false) -> ElevationResult;
}
