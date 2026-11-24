module cli.proxy_services;
import std;
import config;
import logging.cli;

namespace cli {
    auto init_sni_demux_service(config::SniDemuxConfig const&, logging::Runtime&)
        -> std::expected<ServiceHandle, std::string> {
        return std::unexpected("sni-demux requires the sni-demux build feature");
    }
    auto sni_demux_bound_port(ServiceHandle const&) noexcept -> std::uint16_t { return 0; }
}
