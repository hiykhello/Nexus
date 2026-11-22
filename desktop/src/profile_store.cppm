export module desktop.profile_store;

import std;

export namespace desktop {
    struct ProfileEntry {
        std::string id;
        std::string name;
        std::filesystem::path kdl_path;
        std::int64_t updated_epoch_s = 0;
    };

    // Multi-profile manager with atomic KDL persistence and strict 0600 secret isolation.
    class ProfileStore {
        std::filesystem::path root_;
        std::filesystem::path profiles_dir_;
        std::filesystem::path secrets_dir_;

    public:
        explicit ProfileStore(std::filesystem::path root);

        [[nodiscard]] auto list(this ProfileStore const& self) -> std::vector<ProfileEntry>;
        [[nodiscard]] auto active_id(this ProfileStore const& self) -> std::string;
        auto set_active(this ProfileStore const& self, std::string_view id) -> bool;

        [[nodiscard]] auto save_profile(this ProfileStore const& self,
                                        std::string_view name,
                                        std::string_view kdl_content) -> std::optional<ProfileEntry>;
        [[nodiscard]] auto remove_profile(this ProfileStore const& self, std::string_view id) -> bool;

        // Writes credential material to a 0600 private file and returns its absolute path.
        [[nodiscard]] auto write_secret(this ProfileStore const& self,
                                        std::string_view tag,
                                        std::string_view secret) -> std::optional<std::filesystem::path>;

        [[nodiscard]] static auto sanitize_id(std::string_view raw) -> std::string;
    };
}
