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

    /// Exports selected profiles (and transitive deps, rejecting full_custom_kdl) as nexus://share/v1/...
    [[nodiscard]] auto export_workspace_share(
        std::string_view workspace_json,
        std::vector<std::string> const& profile_ids) -> WorkspaceShareExportResult;

    /// Imports a nexus://share/v1/... bundle into workspace_json with fresh collision-free IDs.
    [[nodiscard]] auto import_workspace_share(
        std::string_view workspace_json,
        std::string_view share_uri,
        std::string_view target_subscription_id = {}) -> WorkspaceShareImportResult;

    /// Encrypts canonical Layer 1 workspace JSON into a nexus-sync-v1 E2EE envelope (scrypt + XChaCha20-Poly1305).
    [[nodiscard]] auto seal_workspace_sync(
        std::string_view workspace_json,
        std::string_view passphrase,
        std::string_view device_label = {}) -> WorkspaceSyncSealResult;

    /// Decrypts and verifies a nexus-sync-v1 E2EE envelope back into canonical Layer 1 workspace JSON.
    [[nodiscard]] auto open_workspace_sync(
        std::string_view envelope_json,
        std::string_view passphrase) -> WorkspaceSyncOpenResult;

    [[nodiscard]] auto serialize_share_export_result_json(WorkspaceShareExportResult const& result) -> std::string;
    [[nodiscard]] auto serialize_share_import_result_json(WorkspaceShareImportResult const& result) -> std::string;
    [[nodiscard]] auto serialize_sync_seal_result_json(WorkspaceSyncSealResult const& result) -> std::string;
    [[nodiscard]] auto serialize_sync_open_result_json(WorkspaceSyncOpenResult const& result) -> std::string;
}
