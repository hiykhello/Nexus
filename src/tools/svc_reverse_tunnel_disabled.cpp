module cli.proxy_services;
import std;
import config;
import logging.cli;

namespace cli {
    auto init_reverse_tunnel_service(config::ReverseTunnelServiceConfig const&, logging::Runtime&)
        -> std::expected<ServiceHandle, std::string> {
        return std::unexpected("reverse-tunnel requires the reverse-tunnel build feature");
    }
    auto reverse_tunnel_control_port(ServiceHandle const&) noexcept -> std::uint16_t { return 0; }
    auto reverse_tunnel_expose_port(ServiceHandle const&) noexcept -> std::uint16_t { return 0; }
}
