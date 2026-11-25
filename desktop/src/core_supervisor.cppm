export module desktop.core_supervisor;

import std;

export namespace desktop {
    struct ValidationResult {
        bool ok = false;
        std::string message;
    };

    struct CoreStartOptions {
        bool elevate_session = false;
        bool use_persistent_helper = false;
    };

    [[nodiscard]] auto current_process_memory_bytes() noexcept -> std::uint64_t;

    // Supervises a local Nexus core child process (unprivileged or session-elevated)
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
        [[nodiscard]] auto memory_bytes(this CoreSupervisor const& self) noexcept -> std::uint64_t;
        [[nodiscard]] auto elevated_session(this CoreSupervisor const& self) noexcept -> bool;
        [[nodiscard]] auto using_persistent_helper(this CoreSupervisor const& self) noexcept -> bool;
        [[nodiscard]] auto last_start_cancelled(this CoreSupervisor const& self) noexcept -> bool;
        [[nodiscard]] auto binary_path(this CoreSupervisor const& self) noexcept -> std::filesystem::path const&;
        [[nodiscard]] auto start(
            this CoreSupervisor& self,
            std::filesystem::path const& config_path,
            CoreStartOptions opts = {}) -> bool;
        auto stop(this CoreSupervisor& self) -> void;
        [[nodiscard]] auto last_error(this CoreSupervisor const& self) -> std::string;

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
