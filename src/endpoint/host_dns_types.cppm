export module endpoint.host_dns_types;
import std;
import dns.local_config;
import packet.tun_network_types;
export namespace endpoint {
    enum class HostDnsBackend { disabled,resolved };
    struct HostDnsOptions {
        HostDnsBackend backend=HostDnsBackend::disabled;
        std::array<dns::LocalServer,3> servers{};
        std::uint8_t server_count=0;
        [[nodiscard]] auto enabled() const noexcept -> bool {return backend!=HostDnsBackend::disabled;}
        [[nodiscard]] auto valid() const noexcept -> bool {
            if(backend==HostDnsBackend::disabled)return server_count==0;
            if(backend!=HostDnsBackend::resolved || !server_count || server_count>servers.size())return false;
            for(std::size_t i=0;i<server_count;++i) {
                auto const& server=servers[i];packet::TunAddress address{server.ipv6 ? std::uint8_t{6} : std::uint8_t{4},server.address,server.ipv6 ? std::uint8_t{128} : std::uint8_t{32}};
                if(server.port!=53 || !packet::tun_network_detail::valid(address,false))return false;
                for(std::size_t j=0;j<i;++j)if(server==servers[j])return false;
            }
            return true;
        }
    };
    struct NoHostDns {static constexpr bool enabled=false;};
}
