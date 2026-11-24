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

    class HttpControlServer {
    public:
        [[nodiscard]] auto active(this HttpControlServer const&) noexcept -> bool { return false; }
        [[nodiscard]] auto start(this HttpControlServer&, config::ControlHttpConfig const&)
            -> std::expected<void, std::string> {
            return std::unexpected("control-http feature is not enabled in this build");
        }
        [[nodiscard]] auto configure_ssmapi(this HttpControlServer&, bool enabled,
            std::string = "/ssmapi") -> std::expected<void, std::string> {
            if (enabled) return std::unexpected("control-http feature is not enabled in this build");
            return {};
        }
        auto attach_ssmapi_users(this HttpControlServer&, std::shared_ptr<relay::ShadowsocksUserDirectory>) noexcept -> void {}
        [[nodiscard]] auto handle_direct_http_for_test(this HttpControlServer&, std::string_view,
            SnapshotBuilder, CommandHandler) -> std::string { return {}; }
        [[nodiscard]] auto handle_direct_http_for_test(this HttpControlServer&, std::string_view,
            ScopedSnapshotBuilder, CommandHandler) -> std::string { return {}; }
        auto poll(this HttpControlServer&, SnapshotBuilder, CommandHandler) -> void {}
        auto poll(this HttpControlServer&, ScopedSnapshotBuilder, CommandHandler) -> void {}
        [[nodiscard]] auto listen_native_fd(this HttpControlServer const&) noexcept -> int { return -1; }
        [[nodiscard]] auto next_poll_delay(this HttpControlServer const&) noexcept
            -> std::optional<std::chrono::milliseconds> { return std::nullopt; }
        auto stop(this HttpControlServer&) noexcept -> void {}
    };
}
