export module desktop.core_supervisor;

import std;

export namespace desktop {
    struct ValidationResult {
        bool ok = false;
        std::string message;
    };

    // Supervises a local unprivileged Nexus core child process (user mode)
    // and executes offline `nexus check --config` validation before hot reload.
    class CoreSupervisor {
        struct Impl;
        std::unique_ptr<Impl> impl_;
        std::filesystem::path binary_;
    public:
        explicit CoreSupervisor(std::filesystem::path binary);
        ~CoreSupervisor();
        CoreSupervisor(CoreSupervisor const&) = delete;
        auto operator=(CoreSupervisor const&) -> CoreSupervisor& = delete;

        [[nodiscard]] auto running(this CoreSupervisor const& self) noexcept -> bool;
        [[nodiscard]] auto start(this CoreSupervisor& self, std::filesystem::path const& config_path) -> bool;
        auto stop(this CoreSupervisor& self) -> void;

        [[nodiscard]] auto validate_config(
            this CoreSupervisor const& self,
            std::filesystem::path const& config_path) -> ValidationResult;

        [[nodiscard]] auto explain_rule(
            this CoreSupervisor const& self,
            std::filesystem::path const& config_path,
            std::string_view inbound,
            std::string_view network,
            std::string_view target,
            std::string_view extra_options = {}) -> ValidationResult;
    };
}
