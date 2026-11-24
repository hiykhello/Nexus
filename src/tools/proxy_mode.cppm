// Runtime route mode controller (rule / global / direct) for Nexus core.
export module cli.proxy_mode;
import std;
import cli.control;
import cli.proxy_run_state;
import config;
import rules;

export namespace cli::run_detail {
    struct RuntimeRouteModeController {
        std::shared_ptr<rules::RuntimeRouteMode> shared = std::make_shared<rules::RuntimeRouteMode>();
        std::string global_outbound_name;

        auto sync(config::Config const& cfg) -> void {
            auto target = global_outbound_name.empty() ? std::string_view(cfg.default_outbound_name)
                                                       : std::string_view(global_outbound_name);
            if (auto idx = config::distributed_outbound_index(cfg, target); idx && *idx != 1) {
                shared->global_outbound.store(*idx, std::memory_order_release);
                if (global_outbound_name.empty()) global_outbound_name = cfg.default_outbound_name;
                return;
            }
            if (auto idx = config::distributed_outbound_index(cfg, cfg.default_outbound_name); idx && *idx != 1) {
                shared->global_outbound.store(*idx, std::memory_order_release);
                global_outbound_name = cfg.default_outbound_name;
            } else {
                shared->global_outbound.store(0, std::memory_order_release);
                global_outbound_name = cfg.direct_outbound_name;
            }
        }
        auto sync(std::optional<config::Config> const& running) -> void { if (running) sync(*running); }

        auto attach(auto const& listeners) const -> void {
            for (auto const& listener : listeners)
                listener.server->set_runtime_mode(shared);
        }

        [[nodiscard]] auto mode_name() const noexcept -> std::string_view {
            return rules::route_mode_name(shared->mode.load(std::memory_order_acquire));
        }

        template<class ControlOps>
        auto handle_command(std::optional<config::Config> const& running,
                            cli::ControlRole role,
                            std::span<std::string_view const> args,
                            ControlOps& operations) -> std::expected<std::string, std::string> {
            if (args.size() == 1) {
                return std::format("mode={} outbound={}\n", mode_name(), control_name(global_outbound_name));
            }
            if (role != cli::ControlRole::administrator) return std::unexpected("permission-denied");
            if (args.size() > 3) return std::unexpected("invalid-command-or-arguments");
            auto parsed = rules::parse_route_mode(args[1]);
            if (!parsed) return std::unexpected("invalid-mode");
            if (args.size() == 3) {
                if (!running) return std::unexpected("unknown-outbound");
                auto idx = config::distributed_outbound_index(*running, args[2]);
                if (!idx || *idx == 1) return std::unexpected("unknown-outbound");
                global_outbound_name = std::string(args[2]);
                shared->global_outbound.store(*idx, std::memory_order_release);
            } else if (*parsed == rules::RouteMode::global && running) {
                sync(running);
            }
            shared->mode.store(*parsed, std::memory_order_release);
            operations.published();
            operations.record(ControlOps::EventKind::mode_changed);
            return std::format("mode={} outbound={}\n", mode_name(), control_name(global_outbound_name));
        }
    };
}
