export module desktop.ui_prefs;

import std;

export namespace desktop {
    struct UiPrefs {
        std::string theme_preference = "system";
        std::string accent_preset = "ocean";
        float window_opacity = 0.88f;
        bool blur_enabled = true;
        std::string language = "system";
        std::string outbound_mode = "rule";
        float sidebar_width = 196.0f;
        bool sidebar_collapsed = true;
        bool close_to_tray = true;
        bool start_minimized = false;
        bool tray_show_nodes = true;
        bool tray_show_speed = true;
        std::string tray_click_action = "toggle";
        bool tun_elevate_persistent = true;
    };

    [[nodiscard]] auto detect_system_locale() -> std::string;

    [[nodiscard]] auto ui_prefs_to_json(UiPrefs const& prefs) -> std::string;
    [[nodiscard]] auto ui_prefs_from_json(std::string_view text) -> std::expected<UiPrefs, std::string>;

    [[nodiscard]] auto load_ui_prefs(std::filesystem::path const& path) -> UiPrefs;

    [[nodiscard]] auto save_ui_prefs(std::filesystem::path const& path, UiPrefs const& prefs) -> bool;
}
