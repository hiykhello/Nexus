export module cli.tailscale_outbound;
import std;
import config;
import relay;

export namespace cli::tailscale_outbound {
    auto prepare(relay::Server&,std::span<config::NamedTailscaleOutbound const>) -> std::expected<void,std::string>;
}
