export module cli.tailscale_outbound;
import std;
import config;
import proxy;

export namespace cli::tailscale_outbound {
    auto prepare(proxy::Server&,std::span<config::NamedTailscaleOutbound const>) -> std::expected<void,std::string>;
}
