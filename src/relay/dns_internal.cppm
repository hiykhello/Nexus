// Internal DNS coordinator and response-program declarations shared across proxy DNS units.
module relay:dns_internal;
import std;
import capy;
import corosio;
import dns.address_sequence;
import dns.corosio_query;
import dns.corosio_resolver;
import dns.local_config;
import dns.local_response;
import dns.message;
import dns.policy;
import dns.response_race_walk;
import relay.dns_backend;
import relay.dns_routing;
import relay.dns_state;
import :types;
import :route_interface;
import :session_interface;

namespace relay::dns_detail {
    using LocalSnapshotRef = std::shared_ptr<dns::LocalSnapshot const> const*;

    [[nodiscard]] inline auto active_dns_routing(Session const& session) noexcept -> DnsRouting const* {
        if (session.route_snapshot) {
            if (session.route_snapshot->dns_disabled) return nullptr;
            if (session.route_snapshot->dns_runtime) return &session.route_snapshot->dns_runtime->routing;
        }
        return session.dns ? &session.dns->routing : nullptr;
    }

    [[nodiscard]] inline auto active_dns_endpoint(Session const& session, std::size_t index) -> corosio::endpoint {
        if (session.route_snapshot && session.route_snapshot->dns_runtime)
            return session.route_snapshot->dns_runtime->endpoint(index);
        return session.dns->endpoint(index);
    }

    [[nodiscard]] inline auto active_dns_protection(Session const& session, std::size_t index) noexcept
        -> std::shared_ptr<dns::detail::ProtectedQuery const> const& {
        if (auto* transports = session.dns_transports(); transports && index < transports->queries.size())
            return transports->queries[index];
        return active_dns_routing(session)->servers[index].protection;
    }

    [[nodiscard]] inline auto non_shared_dns_view(Session const& session, std::uint64_t base) noexcept -> std::uint64_t {
        if (auto* transports = session.dns_transports()) return transports->address_view(base);
        if (session.route_snapshot && session.route_snapshot->dns_runtime)
            return (session.route_snapshot->dns_runtime->generation << dns::detail::TransportSnapshot::view_bits) | base;
        return base;
    }

#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
    [[nodiscard]] inline auto active_dns_view(Session const& session, std::size_t server_index,
        corosio::endpoint upstream, std::optional<dns::ClientSubnet> subnet = {}, std::uint32_t rule_scope = 0)
        -> std::expected<std::uint64_t, dns_hp_experiment::ViewRegistry::Error> {
        auto* transports = session.dns_transports();
        if (session.route_snapshot && session.route_snapshot->dns_runtime) {
            auto const& rt = *session.route_snapshot->dns_runtime;
            if (!rt.view_registry || server_index >= rt.profiles.size())
                return std::unexpected(dns_hp_experiment::ViewRegistry::Error::invalid);
            auto id = rt.view_registry->view(rt.profiles[server_index], upstream, subnet, rule_scope);
            if (!id) return std::unexpected(id.error());
            if (transports) return transports->address_view(*id);
            return (rt.generation << dns::detail::TransportSnapshot::view_bits) | *id;
        }
        if (!session.dns || !session.dns->views)
            return std::unexpected(dns_hp_experiment::ViewRegistry::Error::invalid);
        auto id = session.dns->views->view(server_index, upstream, subnet, rule_scope);
        if (!id) return std::unexpected(id.error());
        return transports ? transports->address_view(*id) : *id;
    }
#endif

    auto strategy(Session const& session) -> dns::detail::AddressStrategy;
    auto endpoints(std::span<dns::Address const> addresses, std::uint16_t port) -> std::vector<corosio::endpoint>;

    [[nodiscard]] inline auto to_address_strategy(std::optional<rules::DnsRuleStrategy> value,
        dns::detail::AddressStrategy fallback) noexcept -> dns::detail::AddressStrategy {
        if (!value) return fallback;
        using S = rules::DnsRuleStrategy;
        using A = dns::detail::AddressStrategy;
        switch (*value) {
        case S::prefer_ipv4: return A::prefer_ipv4;
        case S::prefer_ipv6: return A::prefer_ipv6;
        case S::ipv4_only: return A::ipv4_only;
        case S::ipv6_only: return A::ipv6_only;
        }
        return fallback;
    }

    auto query_server_endpoints(Session& session, corosio::io_context& context, std::size_t server_index,
        std::span<corosio::endpoint const> servers, std::string const& name, std::uint16_t port,
        dns::detail::AddressStrategy family, Clock::time_point deadline,
        void*& dns_operation, void (*&cancel_dns)(void*) noexcept, LocalSnapshotRef retained)
        -> capy::task<std::expected<std::vector<corosio::endpoint>, dns::detail::ResolveError>>;

    auto resolve_dns_full(Session& session, corosio::io_context& context, std::size_t selected,
        std::string name, std::uint16_t port, dns::detail::AddressStrategy family, Clock::time_point deadline,
        void*& dns_operation, void (*&cancel_dns)(void*) noexcept, bool const* canceled,
        LocalSnapshotRef retained, dns::detail::FamilyCachePolicy cache_policy,
        std::optional<dns::ClientSubnet> subnet, std::uint32_t rule_scope = 0)
        -> capy::task<std::expected<dns::AddressAnswer, dns::detail::ResolveError>>;

#ifdef NEXUS_DNS_RESPONSE
    auto response_server(Session& session, corosio::io_context& context, std::size_t selected,
        std::string const& name, std::uint16_t type, Clock::time_point deadline, LocalSnapshotRef retained,
        bool disabled, void*& dns_operation, void (*&cancel_dns)(void*) noexcept, bool const& canceled,
        std::size_t* rotation_override = nullptr, std::optional<std::string_view> fixed_candidate = {},
        std::optional<dns::ClientSubnet> subnet = {})
        -> capy::task<std::expected<dns::detail::LocalResponseSelection, dns::detail::ResolveError>>;

    auto resolve_response_program(Session& session, corosio::io_context& context, std::string const& name,
        std::uint16_t port, dns::detail::AddressStrategy family, Clock::time_point deadline, policy::DnsContext input,
        void*& registered, void (*&cancel)(void*) noexcept, bool const* canceled = nullptr,
        std::optional<std::size_t> view_final = {}, std::span<dns::ResponseRaceMode const> modes = {})
        -> capy::task<std::expected<std::vector<corosio::endpoint>, dns::detail::ResolveError>>;
#endif
}
