module cli.proxy_services;
import std;
import config;
import logging.cli;

namespace cli {
    auto init_derp_server_service(config::DerpServerServiceConfig const&, logging::Runtime&)
        -> std::expected<ServiceHandle, std::string> {
        return std::unexpected("derp-server requires the derp-server build feature");
    }
    auto derp_bound_port(ServiceHandle const&) noexcept -> std::uint16_t { return 0; }
    auto derp_public_key(ServiceHandle const&) noexcept -> std::array<std::uint8_t, 32> { return {}; }
}
