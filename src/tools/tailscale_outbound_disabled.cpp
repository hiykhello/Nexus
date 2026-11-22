module cli.tailscale_outbound;
import std;
import config;
import proxy;

namespace cli::tailscale_outbound {
    auto prepare(proxy::Server&,std::span<config::NamedTailscaleOutbound const> routes) -> std::expected<void,std::string> {
        if(!routes.empty())return std::unexpected("Tailscale outbound is unavailable in this build");
        return {};
    }
}
