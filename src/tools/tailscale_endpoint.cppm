export module cli.tailscale_endpoint;
import std;
import net.udp_socket;
import proxy;

export namespace cli::tailscale_endpoint {
    struct RelayConfig {
        std::string authority, server_name, ca_file;
        net::UdpEndpoint server;
        std::array<std::uint8_t,32> pin{};
        std::uint16_t region = 0;
    };
    struct Config {
        std::string name, interface, authority, server_name, ca_file, auth_key_file, state_dir;
        net::UdpEndpoint control;
        net::UdpEndpoint listen;
        std::array<std::uint8_t,32> pin{};
        std::uint16_t mtu = 1280;
        bool ephemeral = false, accept_routes = false, discover_paths = false;
        std::optional<net::UdpEndpoint> stun_server;
        std::optional<RelayConfig> relay;
        std::vector<RelayConfig> relay_candidates;
    };

    // A missing value identifies the WireGuard endpoint document.
    auto parse(std::string_view input) -> std::expected<std::optional<Config>,std::string>;
    auto run(Config const& config, bool check, bool resolve) -> int;
    auto make_userspace(Config) -> std::shared_ptr<proxy::MeshLink>;
}
