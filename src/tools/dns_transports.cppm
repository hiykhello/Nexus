export module cli.dns_transports;
import std;
import config;
import dns.corosio_query;
import dns.input_budget;
import dns.message;
import platform.ip_address;

namespace cli {
    auto prepare_encrypted_dns_transport(config::DnsTls const& profile,config::TcpSocketOptions const&,
        std::optional<std::chrono::milliseconds> connect_timeout,std::optional<std::size_t> proxy_outbound,
        dns::detail::TransportSnapshotRef)
        -> std::expected<dns::detail::ProtectedQuery,std::string>;
    auto prepare_extra_dns_transport(config::DnsServer const&)
        -> std::expected<dns::detail::ProtectedQuery,std::string>;
    auto prepare_dhcp_dns_transport(config::DnsServer const&)
        -> std::expected<dns::detail::ProtectedQuery,std::string>;
    auto prepare_mdns_transport(config::DnsServer const&)
        -> std::expected<dns::detail::ProtectedQuery,std::string>;
    auto prepare_proxy_plain_dns(bool tcp,std::size_t outbound,dns::detail::TransportSnapshotRef)
        -> std::expected<dns::detail::ProtectedQuery,std::string>;
}

export namespace cli {
    using DnsProtection=dns::detail::Protection;

    [[nodiscard]] auto dns_system_trust_identity() -> std::expected<std::string, std::string>;
    [[nodiscard]] auto convert_mdns_response(dns::Question const& question, std::uint16_t id,
        std::span<std::uint8_t const> mdns_wire) -> std::expected<std::optional<dns::Response>, dns::detail::UdpError>;
    [[nodiscard]] auto resolve_dhcp_endpoint(platform::IpAddress const& ip, std::string_view scope,
        std::string_view fallback_iface = {}, std::uint16_t port = 53) noexcept -> std::optional<corosio::endpoint>;
    [[nodiscard]] auto query_dhcp_endpoints(corosio::io_context& context,
        std::span<corosio::endpoint const> endpoints, dns::QueryMessage const& query, std::uint16_t id,
        std::chrono::steady_clock::time_point deadline, dns::InputBudget& budget, std::stop_token stop)
        -> capy::task<std::expected<dns::Response, dns::detail::UdpError>>;

    [[nodiscard]] inline auto uses_dns_groups(std::optional<config::DnsRouting> const& dns) noexcept -> bool {
        return dns && std::ranges::any_of(dns->servers,[](auto const& entry) {
            return entry.upstream && entry.upstream->detour_group;
        });
    }

    [[nodiscard]] inline auto uses_proxy_dns(std::optional<config::DnsRouting> const& dns) noexcept -> bool {
        return dns && std::ranges::any_of(dns->servers,[](auto const& entry) {
            return entry.upstream && (entry.upstream->detour_index || entry.upstream->detour_group);
        });
    }
    [[nodiscard]] auto prepare_dns_transports(config::Config const& config,dns::detail::TransportSnapshotRef snapshot={})
        -> std::expected<std::vector<DnsProtection>,std::string> {
        std::vector<DnsProtection> result;
        if (!config.dns) return result;
        result.reserve(config.dns->servers.size());
        for (auto const& server : config.dns->servers) {
            if (server.kind != config::DnsServerKind::standard) {
                auto query=prepare_extra_dns_transport(server);
                if (!query) return std::unexpected("DNS "+server.name+": "+query.error());
                result.push_back(std::make_shared<dns::detail::ProtectedQuery const>(std::move(*query)));
                continue;
            }
            auto const& upstream=server.upstream;
            if (upstream && upstream->tls) {
                auto options=config.direct_tcp_options;
                std::optional<std::chrono::milliseconds> connect_timeout;
                if (upstream->detour && !upstream->detour_index) {
                    connect_timeout.emplace(config.direct_connect_timeout_ms);
                } else {
                    options.binding.network_namespace.clear();
                    options.binding.protect_path.clear();
                    options.tcp_fast_open.reset();
                }
                if (!upstream->binding.interface_name().empty()) {
                    options.binding.bind_interface=upstream->binding.bind_interface;
                    options.binding.interface_index=0;
                    options.binding.network.reset();
                }
                if (upstream->binding.routing_mark) options.binding.routing_mark=upstream->binding.routing_mark;
                auto loaded=prepare_encrypted_dns_transport(*upstream->tls,options,connect_timeout,upstream->detour_index,snapshot);
                if (!loaded) return std::unexpected("DNS "+server.name+": "+loaded.error());
                result.push_back(std::make_shared<dns::detail::ProtectedQuery const>(std::move(*loaded)));
            } else if (upstream && (upstream->detour_group || (upstream->detour_index && *upstream->detour_index>=2))) {
                auto proxy_outbound=upstream->detour_group ? result.size() : *upstream->detour_index;
                auto query=prepare_proxy_plain_dns(upstream->tcp,proxy_outbound,snapshot);
                if (!query) return std::unexpected("DNS "+server.name+": "+query.error());
                result.push_back(std::make_shared<dns::detail::ProtectedQuery const>(std::move(*query)));
            } else if (upstream && upstream->binding.configured()) {
                auto query=dns::detail::make_bound_query(upstream->binding,upstream->tcp);
                result.push_back(std::make_shared<dns::detail::ProtectedQuery const>(std::move(query)));
            } else {
                result.emplace_back();
            }
        }
        return result;
    }

    [[nodiscard]] auto prepare_dns_transport_snapshot(config::Config const& config,std::uint64_t generation,
        std::shared_ptr<dns::detail::TransportSnapshot const> const& running,bool rebuild)
        -> std::expected<std::shared_ptr<dns::detail::TransportSnapshot const>,std::string> {
        if (!uses_dns_groups(config.dns)) return std::shared_ptr<dns::detail::TransportSnapshot const>{};
        std::vector<std::optional<std::size_t>> outbounds;
        outbounds.reserve(config.dns->servers.size());
        for (auto const& server:config.dns->servers)
            outbounds.push_back(server.upstream ? server.upstream->detour_index : std::nullopt);
        if (!rebuild && running && running->outbounds==outbounds) return running;
        if (generation>=dns::detail::TransportSnapshot::generation_limit)
            return std::unexpected("DNS transport generation exhausted");

        auto snapshot=std::make_shared<dns::detail::TransportSnapshot>(generation,std::move(outbounds));
        auto prepared=prepare_dns_transports(config,snapshot);
        if (!prepared) return std::unexpected(std::move(prepared.error()));
        snapshot->queries=std::move(*prepared);
        return snapshot;
    }
}
