export module endpoint.config;
import std;
import endpoint.host_dns_types;
import net.udp_socket;
import wireguard.routing;
import wireguard;
import packet.tun_network_types;
import platform.socket_options;

export namespace endpoint {
    enum class AddressStrategy { prefer_ipv4,prefer_ipv6,ipv4_only,ipv6_only };
    struct Server {
        std::string host;
        std::uint16_t port=0;
        std::optional<net::UdpEndpoint> numeric;
    };
    struct Peer {
        std::string name,public_key_file;
        std::optional<std::string> preshared_key_file;
        std::optional<Server> server;
        bool local_bootstrap=false;
        std::optional<AddressStrategy> strategy;
        std::vector<wireguard::routing::Prefix> allowed_ips;
        std::uint16_t persistent_keepalive_seconds=0;
    };
    struct Wireguard {
        std::string name,private_key_file,device;
        net::UdpEndpoint listen;
        packet::TunNetworkOptions network;
        platform::SocketBinding binding;
        std::uint32_t startup_timeout_ms=10000;
        std::size_t queue_packets=64,queue_bytes=1024*1024;
        bool require_cookie=false,default_route=false,auto_cookie=false;
        wireguard::Provider provider_profile=wireguard::Provider::standard;
        std::array<std::uint8_t,3> reserved{};
        HostDnsOptions host_dns;
        std::vector<Peer> peers;
    };
    struct Document {
        // Deployment label only. Both roles own the same bidirectional endpoint.
        bool server=false;
        Wireguard wireguard;
    };
    [[nodiscard]] auto parse_kdl(std::string_view) -> std::expected<Document,std::string>;
    [[nodiscard]] auto outer_allowed(Wireguard const&,net::UdpEndpoint const&) noexcept -> bool;
}
namespace endpoint::config_detail {
    auto address(std::string_view,bool route,bool allow_default=false) -> std::optional<packet::TunAddress>;
    auto hostname(std::string_view) -> bool;
    auto validate(Document const&) -> std::expected<void,std::string>;
}
