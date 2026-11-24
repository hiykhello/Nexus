export module control_api;

import std;
import functional;
import config;
import control_api.types;
import relay;

export namespace control_api {
    using CommandHandler = functional::function_ref<std::expected<std::string, std::string>(std::span<std::string_view const>)>;
    using SnapshotBuilder = functional::function_ref<ControlSnapshot()>;
    using ScopedSnapshotBuilder = functional::function_ref<ControlSnapshot(SnapshotFields, std::optional<std::uint64_t>)>;

    // Non-blocking bounded HTTP/1.1 /v1 control plane & optional OpenMetrics /metrics server.
    // Runs on the host control poll loop with strict connection/memory/deadline caps so slow
    // consumers can never stall the proxy data plane.
    class HttpControlServer {
        struct Impl;
        std::unique_ptr<Impl> impl_;
    public:
        HttpControlServer();
        ~HttpControlServer();
        HttpControlServer(HttpControlServer&&) noexcept;
        auto operator=(HttpControlServer&&) noexcept -> HttpControlServer&;
        HttpControlServer(HttpControlServer const&) = delete;
        auto operator=(HttpControlServer const&) -> HttpControlServer& = delete;

        [[nodiscard]] auto active(this HttpControlServer const& self) noexcept -> bool;
        [[nodiscard]] auto start(this HttpControlServer& self, config::ControlHttpConfig const& cfg)
            -> std::expected<void, std::string>;
        [[nodiscard]] auto configure_ssmapi(this HttpControlServer& self, bool enabled,
            std::string prefix = "/ssmapi") -> std::expected<void, std::string>;
        auto attach_ssmapi_users(this HttpControlServer& self, std::shared_ptr<relay::ShadowsocksUserDirectory> users) noexcept -> void;
        [[nodiscard]] auto handle_direct_http_for_test(this HttpControlServer& self, std::string_view raw,
            SnapshotBuilder snapshot, CommandHandler command) -> std::string;
        [[nodiscard]] auto handle_direct_http_for_test(this HttpControlServer& self, std::string_view raw,
            ScopedSnapshotBuilder snapshot, CommandHandler command) -> std::string;
        auto poll(this HttpControlServer& self, SnapshotBuilder snapshot, CommandHandler command) -> void;
        auto poll(this HttpControlServer& self, ScopedSnapshotBuilder snapshot, CommandHandler command) -> void;
        [[nodiscard]] auto listen_native_fd(this HttpControlServer const& self) noexcept -> int;
        [[nodiscard]] auto next_poll_delay(this HttpControlServer const& self) noexcept
            -> std::optional<std::chrono::milliseconds>;
        auto stop(this HttpControlServer& self) noexcept -> void;
    };
}
