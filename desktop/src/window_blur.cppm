export module desktop.window_blur;

import std;

export namespace desktop {
    struct BlurRegionSize {
        int width = 0;
        int height = 0;
    };

    /// Converts physical surface dimensions to rounded logical Wayland coordinates.
    [[nodiscard]] auto compute_logical_blur_size(std::uint32_t physical_width,
                                                 std::uint32_t physical_height,
                                                 float scale_factor) noexcept -> BlurRegionSize {
        if (physical_width == 0 || physical_height == 0) return {};
        float safe_scale = std::isfinite(scale_factor) && scale_factor > 0.25f ? scale_factor : 1.0f;
        int w = std::max(1, static_cast<int>(std::lround(static_cast<double>(physical_width) / safe_scale)));
        int h = std::max(1, static_cast<int>(std::lround(static_cast<double>(physical_height) / safe_scale)));
        return {w, h};
    }

    /// Native compositor blur activates when blur is enabled and the window background is translucent.
    [[nodiscard]] auto should_enable_native_blur(bool blur_enabled, float window_opacity) noexcept -> bool {
        return blur_enabled && std::isfinite(window_opacity) && window_opacity < 0.995f;
    }

    /// Coordinates platform compositor backdrop blur (Wayland ext_background_effect_v1 / KWin, Win32 DWM).
    class WindowBlurController {
    public:
        WindowBlurController();
        ~WindowBlurController();

        WindowBlurController(WindowBlurController const&) = delete;
        auto operator=(WindowBlurController const&) -> WindowBlurController& = delete;
        WindowBlurController(WindowBlurController&&) noexcept;
        auto operator=(WindowBlurController&&) noexcept -> WindowBlurController&;

        auto attach_wayland(void* wl_display_ptr, void* wl_surface_ptr) -> bool;
        auto attach_win32(void* hwnd_ptr) -> bool;
        auto sync(bool enabled, int logical_width, int logical_height, bool dark_mode) -> void;
        auto detach() -> void;

        [[nodiscard]] auto active() const noexcept -> bool;
        [[nodiscard]] auto backend_name() const noexcept -> std::string_view;

    private:
        struct Impl;
        std::unique_ptr<Impl> impl_;
    };
}
