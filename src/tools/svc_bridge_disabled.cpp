module cli.proxy_services;
import std;
import config;
import logging.cli;

namespace cli {
    auto init_bridge_service(config::BridgeServiceConfig const&, logging::Runtime&)
        -> std::expected<ServiceHandle, std::string> {
        return std::unexpected("bridge requires the bridge build feature");
    }
    auto init_bridge_service_with_fds(config::BridgeServiceConfig const&, int, int, logging::Runtime&)
        -> std::expected<ServiceHandle, std::string> {
        return std::unexpected("bridge requires the bridge build feature");
    }
    auto bridge_stats(ServiceHandle const&) noexcept -> BridgeStatsSnapshot { return {}; }
}
