module cli.masque_ip_server;
import std;

namespace cli::masque_enabled {
    auto make_ip_server_port(config::MasqueIpInbound const&, config::MasqueInbound const&) ->
        std::expected<masque::IpServerPort, std::string> {
        return std::unexpected("MASQUE CONNECT-IP server is unavailable in this build");
    }
}
