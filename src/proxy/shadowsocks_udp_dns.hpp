// Private adapter; import nexus.proxy and the UDP listener dependencies first.
#pragma once
#include "../shadowsocks/corosio_udp_listener.hpp"

namespace nexus::proxy::detail {
    struct UdpDnsConfig {
        shadowsocks::detail::UdpDnsRouting routing;
        shadowsocks::detail::UdpResolveOptions options;
    };
    // The listener validates the copied routing before opening any socket.
    inline auto udp_dns_config(DnsRouting const& source) -> std::expected<UdpDnsConfig,std::error_code> {
        UdpDnsConfig result;
        using dns::detail::AddressStrategy;
        switch (source.strategy) {
        case DnsStrategy::automatic:
        case DnsStrategy::prefer_ipv4: result.options.strategy=AddressStrategy::prefer_ipv4; break;
        case DnsStrategy::prefer_ipv6: result.options.strategy=AddressStrategy::prefer_ipv6; break;
        case DnsStrategy::ipv4_only: result.options.strategy=AddressStrategy::ipv4_only; break;
        case DnsStrategy::ipv6_only: result.options.strategy=AddressStrategy::ipv6_only; break;
        default: return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        }
        result.options.disable_cache=source.disable_cache; result.options.edns=source.edns;
        result.routing.fallback=source.final;
        for (auto const& server:source.servers) {
            boost::corosio::endpoint endpoint;
            if (server.ipv6) endpoint={boost::corosio::ipv6_address(server.address),server.port};
            else {
                boost::corosio::ipv4_address::bytes_type bytes{};
                std::copy_n(server.address.begin(),4,bytes.begin());
                endpoint={boost::corosio::ipv4_address(bytes),server.port};
            }
            // System resolution ignores transport settings in the TCP path too.
            result.routing.servers.push_back({endpoint,server.port!=0 && server.tcp,server.host,server.resolver});
        }
        for (auto const& rule:source.rules) result.routing.rules.push_back({rule.domain,rule.suffix,rule.server});
        return result;
    }
}
