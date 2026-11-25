export module desktop.workspace_store;

import std;
import desktop.workspace_models;

export namespace desktop {
    struct SubscriptionReplaceResult {
        bool ok = false;
        std::size_t matched_count = 0;
        std::size_t added_count = 0;
        std::size_t removed_count = 0;
        std::size_t secrets_pruned = 0;
        std::string message;
    };

    [[nodiscard]] auto make_default_workspace() -> WorkspaceDocument;

    [[nodiscard]] auto workspace_to_json(WorkspaceDocument const& doc) -> std::string;
    [[nodiscard]] auto workspace_from_json(std::string_view text) -> std::expected<WorkspaceDocument, std::string>;

    [[nodiscard]] auto load_workspace(std::filesystem::path const& path) -> std::expected<WorkspaceDocument, std::string>;
    [[nodiscard]] auto save_workspace_atomic(std::filesystem::path const& path, WorkspaceDocument const& doc) -> bool;

    // One-shot idempotent migration of legacy profiles/*.kdl (and config.kdl fallback) into full_custom_kdl entries.
    // Returns number of newly migrated profiles.
    auto migrate_legacy_profiles_into_workspace(
        WorkspaceDocument& doc,
        std::filesystem::path const& cfg_dir,
        std::string& active_profile_id) -> std::size_t;

    // Parses Subscription-Userinfo, Profile-Title (base64:/percent-encoded), Profile-Web-Page-Url, Support-Url.
    // Rejects unsafe URL schemes (only http://, https://, tg:// allowed).
    [[nodiscard]] auto parse_subscription_headers(
        std::span<std::pair<std::string, std::string> const> headers) -> SubscriptionUsage;

    [[nodiscard]] auto is_safe_subscription_link(std::string_view url) noexcept -> bool;

    // 5-tier identity-preserving subscription replacement + kept manual groups + fail-closed orphan GC.
    // Orphan secret GC (.secret/.pem/.ech) only runs when allow_secret_gc=true AND fails closed if
    // referenced_secret_paths is empty while credentialed nodes remain.
    auto replace_subscription_profiles(
        WorkspaceDocument& doc,
        std::string_view subscription_id,
        std::vector<WorkspaceProfileItem> incoming,
        std::string& active_profile_id,
        std::filesystem::path const& secrets_dir = {},
        std::unordered_set<std::string> const& referenced_secret_paths = {},
        bool allow_secret_gc = false) -> SubscriptionReplaceResult;

    [[nodiscard]] auto sanitize_workspace_id(std::string_view raw) -> std::string;
}
