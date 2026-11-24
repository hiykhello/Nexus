export module cli.masque_ip_server;
import std;
import config;
import masque.ip_server;

export namespace cli::masque_enabled {
    auto make_ip_server_port(config::MasqueIpInbound const&, config::MasqueInbound const&) ->
        std::expected<masque::IpServerPort, std::string>;
}
