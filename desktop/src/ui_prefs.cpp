module;
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
module desktop.ui_prefs;

import std;

namespace desktop {
    namespace {
        auto trim_str(std::string_view sv) -> std::string_view {
            while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.front()))) sv.remove_prefix(1);
            while (!sv.empty() && std::isspace(static_cast<unsigned char>(sv.back()))) sv.remove_suffix(1);
            return sv;
        }

        auto parse_float_val(std::string_view sv, float fallback, float lo, float hi) -> float {
            float val = fallback;
            auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), val);
            if (ec != std::errc{} || ptr != sv.data() + sv.size() || !std::isfinite(val)) return fallback;
            return std::clamp(val, lo, hi);
        }

        auto normalize_locale_tag(std::string_view raw) -> std::string {
            auto dot = raw.find('.');
            if (dot != std::string_view::npos) raw = raw.substr(0, dot);
            auto at = raw.find('@');
            if (at != std::string_view::npos) raw = raw.substr(0, at);
            std::string low;
            for (unsigned char ch : trim_str(raw)) {
                low.push_back(ch == '_' ? '-' : static_cast<char>(std::tolower(ch)));
            }
            if (low.starts_with("en")) return "en-US";
            if (low.starts_with("zh")) return "zh-CN";
            return "en-US";
        }

        auto parse_dash_order(std::string_view sv) -> std::array<int, 4> {
            std::array<int, 4> out{0, 1, 2, 3};
            std::size_t idx = 0;
            std::size_t pos = 0;
            while (pos <= sv.size() && idx < 4) {
                auto comma = sv.find(',', pos);
                auto tok = trim_str(comma == std::string_view::npos ? sv.substr(pos) : sv.substr(pos, comma - pos));
                int v = -1;
                auto [ptr, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), v);
                if (ec != std::errc{} || ptr != tok.data() + tok.size() || v < 0 || v > 3) return {0, 1, 2, 3};
                out[idx++] = v;
                if (comma == std::string_view::npos) { pos = sv.size() + 1; break; }
                pos = comma + 1;
            }
            if (idx != 4 || pos <= sv.size()) return {0, 1, 2, 3};
            return sanitize_dash_order(out);
        }
    }

    auto sanitize_dash_order(std::array<int, 4> order) -> std::array<int, 4> {
        unsigned mask = 0;
        for (int v : order) {
            if (v < 0 || v > 3) return {0, 1, 2, 3};
            mask |= (1u << static_cast<unsigned>(v));
        }
        return mask == 0xFu ? order : std::array<int, 4>{0, 1, 2, 3};
    }

    auto reorder_dash_slots(std::array<int, 4>& order, int from_id, int to_id) -> bool {
        order = sanitize_dash_order(order);
        if (from_id == to_id || from_id < 0 || from_id > 3 || to_id < 0 || to_id > 3) return false;
        auto src_it = std::find(order.begin(), order.end(), from_id);
        auto dst_it = std::find(order.begin(), order.end(), to_id);
        if (src_it == order.end() || dst_it == order.end() || src_it == dst_it) return false;
        if (src_it < dst_it) {
            std::rotate(src_it, src_it + 1, dst_it + 1);
        } else {
            std::rotate(dst_it, src_it, src_it + 1);
        }
        return true;
    }

    auto detect_system_locale() -> std::string {
#ifdef _WIN32
        wchar_t buf[LOCALE_NAME_MAX_LENGTH]{};
        if (::GetUserDefaultLocaleName(buf, LOCALE_NAME_MAX_LENGTH) > 0) {
            int len = ::WideCharToMultiByte(CP_UTF8, 0, buf, -1, nullptr, 0, nullptr, nullptr);
            if (len > 1) {
                std::string utf8(static_cast<std::size_t>(len - 1), '\0');
                ::WideCharToMultiByte(CP_UTF8, 0, buf, -1, utf8.data(), len - 1, nullptr, nullptr);
                return normalize_locale_tag(utf8);
            }
        }
        return "en-US";
#else
        for (char const* var : {"LC_ALL", "LC_MESSAGES", "LANG"}) {
            if (char const* v = std::getenv(var); v && *v && std::string_view(v) != "C" && std::string_view(v) != "POSIX") {
                return normalize_locale_tag(v);
            }
        }
        return "en-US";
#endif
    }

    auto load_ui_prefs(std::filesystem::path const& path) -> UiPrefs {
        UiPrefs prefs{};
        std::ifstream in(path);
        if (!in) return prefs;
        std::string line;
        while (std::getline(in, line)) {
            auto sv = trim_str(line);
            if (sv.empty() || sv.front() == '#') continue;
            auto eq = sv.find('=');
            if (eq == std::string_view::npos) continue;
            auto key = trim_str(sv.substr(0, eq));
            auto val = trim_str(sv.substr(eq + 1));
            if (key == "theme" && (val == "system" || val == "light" || val == "dark")) prefs.theme_preference = val;
            else if (key == "accent" && (val == "ocean" || val == "emerald" || val == "violet" || val == "amber" || val == "rose")) prefs.accent_preset = val;
            else if (key == "material" && (val == "solid" || val == "frosted" || val == "crystal")) prefs.material_preset = val;
            else if (key == "window_opacity") prefs.window_opacity = parse_float_val(val, prefs.window_opacity, 0.15f, 1.0f);
            else if (key == "surface_opacity") prefs.surface_opacity = parse_float_val(val, prefs.surface_opacity, 0.15f, 1.0f);
            else if (key == "blur_enabled") prefs.blur_enabled = (val == "1" || val == "true");
            else if (key == "blur_radius") prefs.blur_enabled = parse_float_val(val, 20.0f, 0.0f, 40.0f) > 0.5f;
            else if (key == "ambient_glow") prefs.ambient_glow = (val == "1" || val == "true");
            else if (key == "reduced_motion") prefs.reduced_motion = (val == "1" || val == "true");
            else if (key == "language" && (val == "system" || val == "zh-cn" || val == "en-us")) prefs.language = val;
            else if (key == "outbound_mode" && (val == "rule" || val == "global" || val == "direct")) prefs.outbound_mode = val;
            else if (key == "sidebar_width") prefs.sidebar_width = parse_float_val(val, prefs.sidebar_width, 148.0f, 240.0f);
            else if (key == "sidebar_collapsed") prefs.sidebar_collapsed = (val == "1" || val == "true");
            else if (key == "close_to_tray") prefs.close_to_tray = (val == "1" || val == "true");
            else if (key == "start_minimized") prefs.start_minimized = (val == "1" || val == "true");
            else if (key == "tray_show_nodes") prefs.tray_show_nodes = (val == "1" || val == "true");
            else if (key == "tray_show_speed") prefs.tray_show_speed = (val == "1" || val == "true");
            else if (key == "tray_click_action") {
                prefs.tray_click_action = (val == "toggle" || val == "show" || val == "toggle_proxy")
                    ? std::string(val) : std::string("toggle");
            }
            else if (key == "dash_show_speed") prefs.dash_show_speed = (val == "1" || val == "true");
            else if (key == "dash_show_quick_nodes") prefs.dash_show_quick_nodes = (val == "1" || val == "true");
            else if (key == "dash_show_network") prefs.dash_show_network = (val == "1" || val == "true");
            else if (key == "dash_show_ports") prefs.dash_show_ports = (val == "1" || val == "true");
            else if (key == "dash_show_traffic") prefs.dash_show_traffic = (val == "1" || val == "true");
            else if (key == "dash_show_memory") prefs.dash_show_memory = (val == "1" || val == "true");
            else if (key == "dash_section_order") prefs.dash_section_order = parse_dash_order(val);
            else if (key == "dash_info_order") prefs.dash_info_order = parse_dash_order(val);
            else if (key == "dash_deck_swapped") prefs.dash_deck_swapped = (val == "1" || val == "true");
        }
        return prefs;
    }

    auto save_ui_prefs(std::filesystem::path const& path, UiPrefs const& prefs) -> bool {
        std::error_code ec;
        if (!path.parent_path().empty()) std::filesystem::create_directories(path.parent_path(), ec);
        auto tmp = path;
        tmp += ".tmp";
        std::string_view click_action = (prefs.tray_click_action == "toggle" ||
            prefs.tray_click_action == "show" || prefs.tray_click_action == "toggle_proxy")
            ? std::string_view(prefs.tray_click_action) : std::string_view("toggle");
        auto sec = sanitize_dash_order(prefs.dash_section_order);
        auto info = sanitize_dash_order(prefs.dash_info_order);
        std::string payload = std::format(
            "theme={}\n"
            "accent={}\n"
            "material={}\n"
            "window_opacity={:.2f}\n"
            "surface_opacity={:.2f}\n"
            "blur_enabled={}\n"
            "ambient_glow={}\n"
            "reduced_motion={}\n"
            "language={}\n"
            "outbound_mode={}\n"
            "sidebar_width={:.1f}\n"
            "sidebar_collapsed={}\n"
            "close_to_tray={}\n"
            "start_minimized={}\n"
            "tray_show_nodes={}\n"
            "tray_show_speed={}\n"
            "tray_click_action={}\n"
            "dash_show_speed={}\n"
            "dash_show_quick_nodes={}\n"
            "dash_show_network={}\n"
            "dash_show_ports={}\n"
            "dash_show_traffic={}\n"
            "dash_show_memory={}\n"
            "dash_section_order={},{},{},{}\n"
            "dash_info_order={},{},{},{}\n"
            "dash_deck_swapped={}\n",
            prefs.theme_preference, prefs.accent_preset, prefs.material_preset,
            std::clamp(prefs.window_opacity, 0.15f, 1.0f),
            std::clamp(prefs.surface_opacity, 0.15f, 1.0f),
            prefs.blur_enabled ? "true" : "false",
            prefs.ambient_glow ? "true" : "false",
            prefs.reduced_motion ? "true" : "false",
            prefs.language, prefs.outbound_mode,
            std::clamp(prefs.sidebar_width, 148.0f, 240.0f),
            prefs.sidebar_collapsed ? "true" : "false",
            prefs.close_to_tray ? "true" : "false",
            prefs.start_minimized ? "true" : "false",
            prefs.tray_show_nodes ? "true" : "false",
            prefs.tray_show_speed ? "true" : "false",
            click_action,
            prefs.dash_show_speed ? "true" : "false",
            prefs.dash_show_quick_nodes ? "true" : "false",
            prefs.dash_show_network ? "true" : "false",
            prefs.dash_show_ports ? "true" : "false",
            prefs.dash_show_traffic ? "true" : "false",
            prefs.dash_show_memory ? "true" : "false",
            sec[0], sec[1], sec[2], sec[3],
            info[0], info[1], info[2], info[3],
            prefs.dash_deck_swapped ? "true" : "false");
        {
            std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
            if (!out) return false;
            out.write(payload.data(), static_cast<std::streamsize>(payload.size()));
            if (!out.good()) return false;
        }
        std::filesystem::rename(tmp, path, ec);
        if (ec) {
            std::filesystem::remove(tmp, ec);
            return false;
        }
        return true;
    }
}
