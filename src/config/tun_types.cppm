// TUN inbound configuration types for config module.
export module config.tun_types;
import std;
import platform.socket_options;

export namespace config {
    struct TunUidRange {
        std::uint32_t min = 0, max = 0;
        auto operator==(TunUidRange const&) const -> bool = default;
    };

    struct TunInboundExtra {
        std::optional<std::uint32_t> auto_redirect_input_mark, auto_redirect_output_mark, auto_redirect_reset_mark;
        std::optional<std::uint32_t> auto_redirect_tproxy_mark;
        std::optional<std::uint16_t> auto_redirect_tproxy_port;
        std::vector<TunUidRange> include_uids, exclude_uids;
        std::vector<std::uint32_t> include_android_users;
        std::vector<std::string> include_interfaces, exclude_interfaces;
        std::vector<std::array<std::uint8_t, 6>> include_mac_addresses, exclude_mac_addresses;
        bool device_fd_skip_ioctl = false, bridge_mode = false;
    };

    enum class TunUdpFiltering { address_port_dependent, address_dependent, endpoint_independent };

    struct TunInbound {
        struct DeviceFd {
            int number;
            bool adopt;
        };
        std::string interface_name = "nexus0";
        std::optional<DeviceFd> device_fd;
        std::optional<std::string> connect_ip_outbound;
        std::vector<std::string> connect_ip_routes;
        std::vector<std::string> route_excludes;
        std::optional<platform::RoutingMarkFilter> include_routing_mark, exclude_routing_mark;
        bool route_exclude_private = false;
        std::optional<std::string> inet4_address, inet6_address;
        std::uint16_t mtu = 1500;
        bool auto_route = false, strict_route = false, auto_redirect = false;
        bool host_dns_resolved = false;
        std::string host_dns_server;
        std::string stack = "system";
        std::size_t tcp_flows = 256, tcp_buffer = 262144;
        std::uint32_t udp_idle_ms = 60000;
        std::optional<std::uint32_t> socket_mark;
        bool endpoint_independent_nat = true;
        TunUdpFiltering udp_filtering = TunUdpFiltering::address_port_dependent;
        bool udp_reject_icmp = false, dns_hijack_tcp = false, udp_reply_fragment = false, exclude_mptcp = false, multi_queue = false, gso = false;
        std::vector<std::string> include_packages, exclude_packages, route_address_sets, route_exclude_address_sets, route_includes;
        TunInboundExtra extra{};
    };
}
