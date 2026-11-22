export module control_api;

import std;
import config;
import control_api.types;

export namespace control_api {
    using CommandHandler = std::function_ref<std::expected<std::string, std::string>(std::span<std::string_view const>)>;
    using SnapshotBuilder = std::function_ref<ControlSnapshot()>;

    class HttpControlServer {
    public:
        [[nodiscard]] auto active(this HttpControlServer const&) noexcept -> bool { return false; }
        [[nodiscard]] auto start(this HttpControlServer&, config::ControlHttpConfig const&)
            -> std::expected<void, std::string> {
            return std::unexpected("control-http feature is not enabled in this build");
        }
        auto poll(this HttpControlServer&, SnapshotBuilder, CommandHandler) -> void {}
        auto stop(this HttpControlServer&) noexcept -> void {}
    };
}
