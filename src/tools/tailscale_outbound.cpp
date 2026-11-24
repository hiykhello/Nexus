module cli.tailscale_outbound;
import std;
import config;
import relay;
import cli.tailscale_endpoint;
import rulefile;

namespace cli::tailscale_outbound {
    auto prepare(relay::Server& server,std::span<config::NamedTailscaleOutbound const> routes) -> std::expected<void,std::string> {
        for(auto const& route:routes) {
            auto text=rulefile::read_regular_file(route.endpoint_file);
            if(!text)return std::unexpected(text.error());
            auto parsed=tailscale_endpoint::parse(*text);
            if(!parsed)return std::unexpected(parsed.error());
            if(!*parsed)return std::unexpected("endpoint-file must contain a Tailscale endpoint");
            auto& options=**parsed;
            auto mtu=options.mtu;
            if(auto added=server.add_mesh(tailscale_endpoint::make_userspace(std::move(options)),mtu);!added)
                return std::unexpected(added.error());
        }
        return {};
    }
}
