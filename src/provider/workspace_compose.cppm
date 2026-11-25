// Unified single-source Nexus workspace compiler public interface.
export module provider.workspace_compose;
import std;
export import provider.workspace_types;

export namespace provider {
    /// Compiles canonical Layer 1 workspace JSON + Layer 3 host adapter JSON into validated KDL 2.0.
    [[nodiscard]] auto compose_workspace(
        std::string_view workspace_json,
        std::string_view host_json,
        WorkspaceComposeOptions const& opts = {}) -> WorkspaceComposeResult;

    /// Serializes a WorkspaceComposeResult as strict RFC 8259 UTF-8 JSON.
    [[nodiscard]] auto serialize_compose_result_json(WorkspaceComposeResult const& result) -> std::string;
}
