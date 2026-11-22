export module desktop.single_instance;

import std;

export namespace desktop {
    // Ensures only one desktop shell instance runs per user session and wakes the
    // existing window when launched a second time (Windows Mutex / Linux XDG UDS).
    class SingleInstanceGuard {
        struct Impl;
        std::unique_ptr<Impl> impl_;
        explicit SingleInstanceGuard(std::unique_ptr<Impl> impl);
    public:
        ~SingleInstanceGuard();
        SingleInstanceGuard(SingleInstanceGuard&&) noexcept;
        auto operator=(SingleInstanceGuard&&) noexcept -> SingleInstanceGuard&;
        SingleInstanceGuard(SingleInstanceGuard const&) = delete;
        auto operator=(SingleInstanceGuard const&) -> SingleInstanceGuard& = delete;

        // Returns nullptr when another instance is already running (after signalling wakeup).
        [[nodiscard]] static auto acquire(std::string const& app_id, std::function<void()> on_wakeup)
            -> std::unique_ptr<SingleInstanceGuard>;
    };
}
