export module desktop.tray_controller;

import std;

export namespace desktop {
    enum class TrayState : std::uint8_t {
        offline,
        running,
        tun_active,
    };

    struct TrayCallbacks {
        std::function<void()> on_show;
        std::function<void()> on_reload;
        std::function<void()> on_quit;
    };

    // Lightweight cross-platform system tray & shutdown coordinator for Nexus Desktop.
    class TrayController {
        struct Impl;
        std::unique_ptr<Impl> impl_;
    public:
        explicit TrayController(TrayCallbacks callbacks = {});
        ~TrayController();
        TrayController(TrayController const&) = delete;
        auto operator=(TrayController const&) -> TrayController& = delete;
        TrayController(TrayController&&) noexcept;
        auto operator=(TrayController&&) noexcept -> TrayController&;

        auto set_status(this TrayController& self, TrayState state, std::string_view summary = {}) -> void;
        [[nodiscard]] auto state(this TrayController const& self) noexcept -> TrayState;
        [[nodiscard]] auto tooltip(this TrayController const& self) -> std::string;
        [[nodiscard]] auto quit_requested(this TrayController const& self) noexcept -> bool;

        auto trigger_show(this TrayController& self) -> void;
        auto trigger_reload(this TrayController& self) -> void;
        auto trigger_quit(this TrayController& self) -> void;
        auto stop(this TrayController& self) noexcept -> void;
    };
}
