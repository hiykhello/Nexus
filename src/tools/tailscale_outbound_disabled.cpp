module cli.tailscale_outbound;
import std;
import config;
import relay;

namespace cli::tailscale_outbound {
    auto prepare(relay::Server&,std::span<config::NamedTailscaleOutbound const> routes) -> std::expected<void,std::string> {
        if(!routes.empty())return std::unexpected("Tailscale outbound is unavailable in this build");
        return {};
    }
}
