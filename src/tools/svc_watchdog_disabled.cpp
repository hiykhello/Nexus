module cli.proxy_services;
import std;
import config;
import logging.cli;

namespace cli {
    auto init_watchdog_service(config::MemoryWatchdogConfig const&, logging::Runtime&, WatchdogHooks)
        -> std::expected<ServiceHandle, std::string> {
        return std::unexpected("memory-watchdog requires the memory-budget build feature");
    }
}
