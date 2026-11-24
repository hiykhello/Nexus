module cli.proxy_services;
import std;
import config;
import logging.cli;

namespace cli {
    auto init_tor_service(config::TorServiceConfig const&, logging::Runtime&, TorHooks)
        -> std::expected<ServiceHandle, std::string> {
        return std::unexpected("tor service requires the tor build feature");
    }
    auto tor_signal_newnym(ServiceHandle&) -> std::expected<void, std::string> {
        return std::unexpected("tor service requires the tor build feature");
    }
    auto tor_query_bootstrap(ServiceHandle&) -> std::expected<int, std::string> {
        return std::unexpected("tor service requires the tor build feature");
    }
}
