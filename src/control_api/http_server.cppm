export module control_api;

import std;
import config;
import control_api.types;

export namespace control_api {
    using CommandHandler = std::function_ref<std::expected<std::string, std::string>(std::span<std::string_view const>)>;
    using SnapshotBuilder = std::function_ref<ControlSnapshot()>;

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
        auto poll(this HttpControlServer& self, SnapshotBuilder snapshot, CommandHandler command) -> void;
        auto stop(this HttpControlServer& self) noexcept -> void;
    };
}
