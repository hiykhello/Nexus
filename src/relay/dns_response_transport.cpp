// Response-phase DNS transport lookups (local response & upstream coordinator).
module relay;
import :dns_internal;
import std;
import capy;
import corosio;
import relay.dns_backend;
import relay.dns_state;
import dns.corosio_query;
import dns.corosio_resolver;
import dns.local_config;
import dns.local_response;
import dns.message;
import dns.response_query;

namespace relay::dns_detail {
    using RawSelection = dns::detail::LocalResponseSelection;

    namespace {
        // Complete-message lookups such as HTTPS/SVCB do not use the address
        // response coordinator, whose singleflight keys admit only A/AAAA.
        auto message_response(dns::detail::MessageQuery& query, corosio::endpoint upstream,
            std::string const& name, std::uint16_t type, Clock::time_point deadline, bool edns)
            -> capy::task<std::expected<dns::Response, dns::detail::ResolveError>> {
            dns::QueryMessage request{0, 0x0100, {name, type}, {}};
            if (edns) request.edns.emplace(dns::QueryEdns{1232, 0, false, {}});
            auto wire = co_await query.run_borrowed(upstream, request, deadline);
            if (!wire) co_return std::unexpected(wire.error());
            auto response = dns::parse_owned_response(std::move(*wire), request.id, request.question);
            if (!response) co_return std::unexpected(dns::detail::ResolveError::protocol);
            co_return std::move(*response);
        }

        auto message_response_owned(corosio::io_context& context, corosio::endpoint upstream,
            std::string const& name, std::uint16_t type, Clock::time_point deadline, bool tcp, bool edns,
            void*& operation, void (*&cancel)(void*) noexcept,
            dns::detail::ProtectedQuery const* protection = nullptr)
            -> capy::task<std::expected<dns::Response, dns::detail::ResolveError>> {
            dns::detail::MessageQuery query(context, tcp, protection);
            struct Registration {
                void*& operation;
                void (*&cancel)(void*) noexcept;
                ~Registration() { cancel = nullptr; operation = nullptr; }
            } registration{operation, cancel};
            operation = &query;
            cancel = [](void* active) noexcept { static_cast<dns::detail::MessageQuery*>(active)->cancel(); };
            co_return co_await message_response(query, upstream, name, type, deadline, edns);
        }

        struct LocalResponseLookup {
            corosio::io_context& context;
            dns_hp_experiment::ResponseCoordinatorOwner* owner;
            dns_hp_experiment::LocalViewBinding* views;
            std::optional<dns::ClientSubnet> subnet;
            std::optional<dns_hp_experiment::ResponseCoordinatorQuery> active;
            std::optional<dns::detail::MessageQuery> message;
            auto cancel() noexcept -> void { if (active) active->cancel(); if (message) message->cancel(); }
            auto resolve(std::shared_ptr<dns::LocalSnapshot const> const& snapshot, corosio::endpoint upstream,
                std::string const& name, std::uint16_t type, Clock::time_point deadline, bool tcp, bool disabled)
                -> capy::task<std::expected<dns::Response, dns::detail::ResolveError>> {
                if (type != 1 && type != 28) {
                    message.emplace(context, tcp);
                    auto response = co_await message_response(*message, upstream, name, type, deadline, false);
                    message.reset();
                    co_return response;
                }
                if (!owner || !views) co_return std::unexpected(dns::detail::ResolveError::state);
                auto view = views->view(snapshot, upstream, subnet);
                if (!view) co_return std::unexpected(view.error());
                active.emplace(*owner);
                auto response = co_await active->resolve(upstream, *view, {name, type}, deadline, tcp, false, disabled, subnet);
                active.reset();
                co_return response;
            }
        };

        auto response_local(Session& session, corosio::io_context& context, std::string const& name, std::uint16_t type,
            Clock::time_point deadline, LocalSnapshotRef retained, bool disabled, void*& dns_operation, void (*&cancel_dns)(void*) noexcept,
            bool const& canceled, std::size_t* rotation_override = nullptr,
            std::optional<std::string_view> fixed_candidate = {}, std::optional<dns::ClientSubnet> subnet = {})
            -> capy::task<std::expected<RawSelection, dns::detail::ResolveError>> {
            using Error = dns::detail::ResolveError;
            if (session.closed || canceled) co_return std::unexpected(Error::canceled);
            if (!retained || !*retained || cancel_dns)
                co_return std::unexpected(Error::state);
            auto& state = *session.dns;
            LocalResponseLookup lookup{context, state.response_coordinator ? &*state.response_coordinator : nullptr,
                state.local_views ? &*state.local_views : nullptr, subnet};
            auto rotation = rotation_override ? *rotation_override : ((*retained)->config.rotate ? session.local_dns->rotation++ : 0);
            dns::detail::BasicLocalResponseResolver resolver(lookup, *retained, rotation, rotation_override, subnet);
            struct Registration { void*& operation; void (*&cancel)(void*) noexcept; ~Registration() { cancel = nullptr; operation = nullptr; } } registration{dns_operation, cancel_dns};
            dns_operation = &resolver;
            cancel_dns = [](void* value) noexcept {
                static_cast<dns::detail::BasicLocalResponseResolver<LocalResponseLookup>*>(value)->cancel();
            };
            auto result = co_await resolver.resolve(name, type, deadline, disabled, fixed_candidate);
            if (session.closed || canceled) co_return std::unexpected(Error::canceled);
            co_return result;
        }
    }

    auto response_server(Session& session, corosio::io_context& context, std::size_t selected,
        std::string const& name, std::uint16_t type, Clock::time_point deadline, LocalSnapshotRef retained, bool disabled,
        void*& dns_operation, void (*&cancel_dns)(void*) noexcept, bool const& canceled, std::size_t* rotation_override,
        std::optional<std::string_view> fixed_candidate, std::optional<dns::ClientSubnet> subnet)
        -> capy::task<std::expected<RawSelection, dns::detail::ResolveError>> {
        using Error = dns::detail::ResolveError;
        if (session.closed || canceled) co_return std::unexpected(Error::canceled);
        auto const* routing_ptr = active_dns_routing(session);
        if (!session.dns || !routing_ptr || selected >= routing_ptr->servers.size())
            co_return std::unexpected(Error::state);
        auto const& routing = *routing_ptr;
        std::vector<std::size_t> chain;
        auto current = selected;
        while (routing.servers[current].resolver) { chain.push_back(current); current = *routing.servers[current].resolver; }
        std::vector<corosio::endpoint> upstreams;
        if (routing.servers[current].port) upstreams.push_back(active_dns_endpoint(session, current));
        for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
            auto const& next = routing.servers[*it];
            auto resolved = co_await query_server_endpoints(session, context, current, upstreams, next.host, next.port,
                strategy(session), deadline, dns_operation, cancel_dns, retained);
            if (session.closed || canceled) co_return std::unexpected(Error::canceled);
            if (!resolved) co_return std::unexpected(resolved.error());
            upstreams = std::move(*resolved);
            current = *it;
        }
        if (upstreams.empty())
            co_return co_await response_local(session, context, name, type, deadline, retained, disabled,
                dns_operation, cancel_dns, canceled, rotation_override, fixed_candidate, subnet);
        auto const& server = routing.servers[current];
        auto const& protection = active_dns_protection(session, current);
        for (auto const& upstream : upstreams) {
            if (!valid_destination(upstream)) continue;
            if (session.closed || canceled) co_return std::unexpected(Error::canceled);
            if (type != 1 && type != 28) {
                if (subnet || cancel_dns) co_return std::unexpected(Error::state);
                auto response = co_await message_response_owned(context, upstream, name, type, deadline, server.tcp, routing.edns, dns_operation, cancel_dns, protection.get());
                if (session.closed || canceled) co_return std::unexpected(Error::canceled);
                if (response) co_return RawSelection{std::move(*response), upstream, server.tcp, name, false, protection};
                if (response.error() != Error::transport) co_return std::unexpected(response.error());
                continue;
            }
            if (!session.dns->response_coordinator || cancel_dns)
                co_return std::unexpected(Error::state);
            auto view = active_dns_view(session, current, upstream, subnet);
            if (!view) co_return std::unexpected(Error::limit);
            dns_hp_experiment::ResponseCoordinatorQuery operation(*session.dns->response_coordinator);
            struct Registration { void*& operation; void (*&cancel)(void*) noexcept; ~Registration() { cancel = nullptr; operation = nullptr; } } registration{dns_operation, cancel_dns};
            dns_operation = &operation;
            cancel_dns = [](void* value) noexcept { static_cast<dns_hp_experiment::ResponseCoordinatorQuery*>(value)->cancel(); };
            auto response = co_await operation.resolve(upstream, *view, {name, type}, deadline, server.tcp, routing.edns, disabled, subnet, protection);
            if (session.closed || canceled) co_return std::unexpected(Error::canceled);
            if (response) co_return RawSelection{std::move(*response), upstream, server.tcp, name, false, protection};
            if (response.error() != Error::transport) co_return std::unexpected(response.error());
        }
        co_return std::unexpected(Error::transport);
    }
}
