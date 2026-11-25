export module desktop.workspace_composer;

import std;
import desktop.workspace_models;

export namespace desktop {
    struct WorkspaceComposeResult {
        bool ok = false;
        std::string active_tag;
        std::string selector_tag = "proxy";
        std::vector<std::string> selector_members;
        std::vector<std::string> warnings;
        std::vector<std::string> errors;
        std::vector<std::string> secret_files;
        std::string kdl;
    };

    struct TunLiveSwitchDecision {
        bool can_live_switch = false;
        std::string selector_tag;
        std::string target_tag;
    };

    // Mirrors Core provider::ws_detail::sanitize_tag exactly.
    [[nodiscard]] auto sanitize_core_tag(std::string_view raw, std::string_view fallback = "node") -> std::string;

    // Resolves unambiguous Core outbound tag for live TUN selector switching (empty if non-node, sub-chained, or ambiguous).
    [[nodiscard]] auto resolve_live_switch_tag(WorkspaceDocument const& doc, std::string_view profile_id) -> std::string;

    [[nodiscard]] auto parse_workspace_compose_json(std::string_view json_text) -> WorkspaceComposeResult;

    [[nodiscard]] auto decide_tun_live_switch(
        bool core_running,
        bool tun_enabled,
        std::string_view running_selector_tag,
        std::span<std::string const> running_selector_members,
        std::string_view target_tag) -> TunLiveSwitchDecision;

    [[nodiscard]] auto build_workspace_compose_argv(
        std::filesystem::path const& core_binary,
        std::filesystem::path const& workspace_file,
        std::filesystem::path const& host_file,
        std::filesystem::path const& secrets_dir,
        std::string_view active_profile_id = {},
        std::filesystem::path const& emit_kdl_file = {}) -> std::vector<std::string>;

    [[nodiscard]] auto compose_workspace_via_core(
        std::filesystem::path const& core_binary,
        std::filesystem::path const& workspace_file,
        std::filesystem::path const& host_file,
        std::filesystem::path const& secrets_dir,
        std::string_view active_profile_id = {},
        std::filesystem::path const& emit_kdl_file = {}) -> WorkspaceComposeResult;
}
