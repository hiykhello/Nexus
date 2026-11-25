export module desktop.ui_prefs;

import std;

export namespace desktop {
    struct UiPrefs {
        std::string theme_preference = "system";
        std::string accent_preset = "ocean";
        std::string material_preset = "frosted";
        float window_opacity = 0.88f;
        float surface_opacity = 0.90f;
        bool blur_enabled = true;
        bool ambient_glow = true;
        bool reduced_motion = false;
        std::string language = "system";
        std::string outbound_mode = "rule";
        float sidebar_width = 196.0f;
        bool sidebar_collapsed = false;
        bool close_to_tray = true;
        bool start_minimized = false;
        bool tray_show_nodes = true;
        bool tray_show_speed = true;
        std::string tray_click_action = "toggle";
        bool dash_show_speed = true;
        bool dash_show_quick_nodes = true;
        bool dash_show_network = true;
        bool dash_show_ports = true;
        bool dash_show_traffic = true;
        bool dash_show_memory = true;
        std::array<int, 4> dash_section_order = {0, 1, 2, 3};
        std::array<int, 4> dash_info_order = {0, 1, 2, 3};
        bool dash_deck_swapped = false;
        bool tun_elevate_persistent = true;
    };

    [[nodiscard]] auto sanitize_dash_order(std::array<int, 4> order) -> std::array<int, 4>;

    auto reorder_dash_slots(std::array<int, 4>& order, int from_id, int to_id) -> bool;

    [[nodiscard]] auto detect_system_locale() -> std::string;

    [[nodiscard]] auto load_ui_prefs(std::filesystem::path const& path) -> UiPrefs;

    [[nodiscard]] auto save_ui_prefs(std::filesystem::path const& path, UiPrefs const& prefs) -> bool;
}
