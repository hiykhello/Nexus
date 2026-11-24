// Response-stage resolution types & helpers for SS UDP resolve operations.
export module ss_udp.response_resolve;
import std;
import corosio;
import capy;
import dns.address_race_program;
import dns.corosio_local;
import dns.local_response;
import dns.policy;
import dns.predefined;
import dns.response_program;
import dns.response_query;
import dns.response_race_walk;
import rules;
import shadowsocks.udp_dispatch;

export namespace shadowsocks::detail {
    namespace udp_io = ::corosio;
    namespace udp_capy = ::capy;

    struct UdpResolveHop { std::string host; std::uint16_t port; std::uint64_t view; bool tcp_only; };
    struct UdpResolvePlan {
        udp_io::endpoint upstream;
        std::uint64_t view = 0;
        bool tcp = false;
        std::vector<UdpResolveHop> hops;
    };
    struct UdpResponseServer {
        udp_io::endpoint endpoint; bool tcp_only = false;
        std::string host; std::optional<std::size_t> resolver;
        std::shared_ptr<dns::detail::ProtectedQuery const> protection{};
    };
    struct UdpResponseRouting {
        std::vector<UdpResponseServer> servers;
        std::vector<policy::DnsRule> rules;
        std::size_t fallback = 0;
    };
    struct UdpResponseContext {
        std::array<std::uint8_t, 16> source{};
        std::uint8_t size = 0;
        std::uint16_t port = 0;
        std::optional<std::string_view> inbound;
        std::optional<std::string_view> auth_user{};
        auto view() const noexcept -> policy::DnsContext {
            return {.network = rules::Network::udp, .source_port = port,
                .source_ip_bytes = std::span(source).first(size), .inbound = inbound, .auth_user = auth_user};
        }
    };
    enum class UdpResolveError { state, invalid_target, dns, dispatch, canceled };
    enum class UdpResolvedAction { complete, resolve_again };
    // Runs synchronously on the listener executor while the operation owns
    // the token. A complete result consumes or transfers it; resolve_again
    // performs another lookup under the same owner budget. The handler may
    // shorten the deadline for subsequent I/O.
    // On failure or exception the operation cancels the token.
    using UdpResolvedHandler = std::function<std::expected<UdpResolvedAction, UdpResolveError>(
        std::uint64_t, std::span<UdpPeer const>, std::chrono::steady_clock::time_point&)>;

#ifdef NEXUS_DNS_RESPONSE
    struct ResponseResolveOps {
        using ResponseSelection = dns::detail::LocalResponseSelection;

        template<class Lookup>
        struct LocalResponseLookup {
            Lookup& lookup;
            std::optional<dns::ClientSubnet> subnet;
            auto cancel() noexcept -> void { lookup.cancel(); }
            auto resolve(std::shared_ptr<dns::LocalSnapshot const> const& snapshot, udp_io::endpoint upstream,
                std::string const& name, std::uint16_t type, std::chrono::steady_clock::time_point deadline, bool tcp, bool disabled)
                -> udp_capy::task<std::expected<dns::Response, dns::detail::ResolveError>> {
                auto view = lookup.raw_local_prepare(snapshot, upstream, subnet);
                if (!view) co_return std::unexpected(view.error());
                auto response = co_await lookup.raw_run(upstream, *view, name, type, deadline, tcp, false, disabled, subnet);
                lookup.raw_finish();
                co_return response;
            }
        };

        template<class Lookup>
        static auto select_local_response(Lookup& lookup, bool const& canceled, std::size_t& response_rotation,
            std::shared_ptr<dns::LocalSnapshot const> const& snapshot, std::string const& name, std::uint16_t type,
            std::chrono::steady_clock::time_point deadline, bool disabled,
            std::optional<std::string_view> fixed_candidate = {}, std::optional<dns::ClientSubnet> subnet = {})
            -> udp_capy::task<std::expected<ResponseSelection, dns::detail::ResolveError>> {
            using Error = dns::detail::ResolveError;
            if constexpr (!requires(Lookup& l, udp_io::endpoint endpoint) { l.raw_local_prepare(snapshot, endpoint); }) {
                co_return std::unexpected(Error::state);
            } else {
                if (canceled) co_return std::unexpected(Error::canceled);
                if (!snapshot) co_return std::unexpected(Error::state);
                auto rotation = response_rotation;
                LocalResponseLookup<Lookup> adapter{lookup, subnet};
                dns::detail::BasicLocalResponseResolver resolver(adapter, snapshot, rotation, &response_rotation, subnet);
                co_return co_await resolver.resolve(name, type, deadline, disabled, fixed_candidate);
            }
        }

        template<class Operation, class Lookup>
        static auto select_response_server(Operation& owner, Lookup& lookup,
            std::unique_ptr<dns::detail::LocalAddressResolver>& local_resolver,
            bool const& canceled, std::size_t& response_rotation,
            std::shared_ptr<dns::LocalSnapshot const> const& snapshot,
            std::size_t selected, std::string const& name, std::uint16_t type,
            std::chrono::steady_clock::time_point deadline, bool disabled,
            std::optional<std::string_view> fixed_candidate = {}, std::optional<dns::ClientSubnet> subnet = {})
            -> udp_capy::task<std::expected<ResponseSelection, dns::detail::ResolveError>> {
            using Error = dns::detail::ResolveError;
            if constexpr (!requires(Lookup& l, udp_io::endpoint endpoint, std::uint64_t view) { l.raw_prepare(endpoint, view); }) {
                co_return std::unexpected(Error::state);
            } else {
                if (canceled) co_return std::unexpected(Error::canceled);
                auto const& routing = *owner.response_routing_;
                std::vector<std::size_t> chain;
                auto current = selected;
                while (routing.servers[current].resolver) {
                    chain.push_back(current);
                    current = *routing.servers[current].resolver;
                }
                std::vector<udp_io::endpoint> upstreams{routing.servers[current].endpoint};
                for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
                    auto const& next = routing.servers[*it];
                    auto resolved = co_await owner.template query_owned<false>(lookup, local_resolver, canceled, response_rotation,
                        upstreams, current + 1, routing.servers[current].tcp_only, next.host, owner.strategy_, deadline, {}, {}, &snapshot);
                    if (canceled) co_return std::unexpected(Error::canceled);
                    if (!resolved) co_return std::unexpected(resolved.error());
                    upstreams.clear();
                    for (auto const& address : *resolved) {
                        if (address.size == 4) {
                            udp_io::ipv4_address::bytes_type bytes{};
                            std::copy_n(address.bytes.begin(), 4, bytes.begin());
                            upstreams.emplace_back(udp_io::ipv4_address(bytes), next.endpoint.port());
                        } else if (address.size == 16) {
                            upstreams.emplace_back(udp_io::ipv6_address(address.bytes), next.endpoint.port());
                        }
                    }
                    current = *it;
                }
                for (auto const& upstream : upstreams) {
                    if (!upstream.port())
                        co_return co_await select_local_response(lookup, canceled, response_rotation, snapshot,
                            name, type, deadline, disabled, fixed_candidate, subnet);
                    auto bound = lookup.raw_prepare(upstream, current + 1, subnet);
                    if (!bound) co_return std::unexpected(bound.error());
                    auto response = co_await lookup.raw_run(upstream, *bound, name, type, deadline,
                        routing.servers[current].tcp_only, owner.edns_, disabled, subnet);
                    lookup.raw_finish();
                    if (canceled) co_return std::unexpected(Error::canceled);
                    if (response) co_return ResponseSelection{
                        std::move(*response), upstream, routing.servers[current].tcp_only, name, false, routing.servers[current].protection};
                    if (response.error() != Error::transport) co_return std::unexpected(response.error());
                }
                co_return std::unexpected(Error::transport);
            }
        }

        template<class Operation, class Lookup>
        class ResponseOperation {
            Operation& owner_;
            Lookup lookup_;
            std::unique_ptr<dns::detail::LocalAddressResolver> local_resolver_;
            std::shared_ptr<dns::LocalSnapshot const> snapshot_;
            std::size_t selected_, rotation_;
            std::string name_;
            std::uint16_t type_;
            std::chrono::steady_clock::time_point deadline_;
            bool disabled_, canceled_ = false, started_ = false;
            std::optional<std::string> candidate_;
            std::optional<dns::ClientSubnet> subnet_;
        public:
            ResponseOperation(Operation& owner, Lookup const& prototype, std::size_t selected,
                std::string const& name, std::uint16_t type, std::chrono::steady_clock::time_point deadline,
                bool disabled, std::optional<std::string_view> candidate, std::optional<dns::ClientSubnet> subnet)
                : owner_(owner), lookup_(prototype.fork()), snapshot_(owner.local_snapshot_), selected_(selected),
                  rotation_(owner.response_rotation_), name_(name), type_(type), deadline_(deadline), disabled_(disabled),
                  candidate_(candidate ? std::optional<std::string>(*candidate) : std::nullopt), subnet_(subnet) {}
            ResponseOperation(ResponseOperation const&) = delete;
            auto operator=(ResponseOperation const&) -> ResponseOperation& = delete;
            auto cancel() noexcept -> void { canceled_ = true; lookup_.cancel(); if (local_resolver_) local_resolver_->cancel(); }
            auto run() -> udp_capy::task<std::expected<ResponseSelection, dns::detail::ResolveError>> {
                if (std::exchange(started_, true)) co_return std::unexpected(dns::detail::ResolveError::state);
                if (canceled_) co_return std::unexpected(dns::detail::ResolveError::canceled);
                auto candidate = candidate_ ? std::optional<std::string_view>(*candidate_) : std::nullopt;
                auto result = co_await select_response_server(owner_, lookup_, local_resolver_, canceled_, rotation_, snapshot_,
                    selected_, name_, type_, deadline_, disabled_, candidate, subnet_);
                if (canceled_) co_return std::unexpected(dns::detail::ResolveError::canceled);
                co_return result;
            }
        };

        template<class Operation, class Lookup>
        static auto route_response_server_owned(Operation& owner, Lookup& lookup,
            std::unique_ptr<dns::detail::LocalAddressResolver>& local_resolver,
            bool const& canceled, std::size_t& rotation, std::shared_ptr<dns::LocalSnapshot const> const& snapshot,
            std::size_t selected, std::string const& name, std::uint16_t type, std::chrono::steady_clock::time_point deadline,
            bool disabled, std::optional<dns::ClientSubnet> subnet = {})
            -> udp_capy::task<std::expected<dns::AddressAnswer, dns::detail::ResolveError>> {
            auto const& routing = *owner.response_routing_;
            std::vector<std::size_t> chain;
            auto current = selected;
            while (routing.servers[current].resolver) {
                chain.push_back(current);
                current = *routing.servers[current].resolver;
            }
            std::vector<udp_io::endpoint> upstreams{routing.servers[current].endpoint};
            for (auto it = chain.rbegin(); it != chain.rend(); ++it) {
                auto const& next = routing.servers[*it];
                auto resolved = co_await owner.template query_owned<false>(lookup, local_resolver, canceled, rotation, upstreams,
                    current + 1, routing.servers[current].tcp_only, next.host, owner.strategy_, deadline, {}, {}, &snapshot);
                if (!resolved) co_return std::unexpected(resolved.error());
                upstreams.clear();
                for (auto const& address : *resolved) {
                    if (address.size == 4) {
                        udp_io::ipv4_address::bytes_type bytes{};
                        std::copy_n(address.bytes.begin(), 4, bytes.begin());
                        upstreams.emplace_back(udp_io::ipv4_address(bytes), next.endpoint.port());
                    } else if (address.size == 16) {
                        upstreams.emplace_back(udp_io::ipv6_address(address.bytes), next.endpoint.port());
                    }
                }
                current = *it;
            }
            dns::detail::FamilyCachePolicy cache{};
            cache[type == 1 ? 0 : 1] = disabled;
            auto family = type == 1 ? dns::detail::AddressStrategy::ipv4_only : dns::detail::AddressStrategy::ipv6_only;
            co_return co_await owner.template query_owned<true>(lookup, local_resolver, canceled, rotation, upstreams,
                current + 1, routing.servers[current].tcp_only, name, family, deadline, cache, subnet, &snapshot);
        }

        template<class Operation, class Lookup>
        class AddressRaceOperation {
            Operation& owner_;
            Lookup lookup_;
            std::unique_ptr<dns::detail::LocalAddressResolver> local_resolver_;
            std::shared_ptr<dns::LocalSnapshot const> snapshot_;
            dns::ResponseStep step_;
            std::size_t rotation_;
            std::string name_;
            std::uint16_t type_;
            std::chrono::steady_clock::time_point deadline_;
            bool rewrite_possible_, canceled_ = false;
            std::optional<std::string> candidate_;
        public:
            AddressRaceOperation(Operation& owner, dns::ResponseStep step, std::string const& name, std::uint16_t type,
                std::chrono::steady_clock::time_point deadline, bool rewrite_possible, std::optional<std::string_view> candidate)
                : owner_(owner), lookup_(owner.lookup_.fork()), snapshot_(owner.local_snapshot_), step_(step),
                  rotation_(owner.response_rotation_), name_(name), type_(type), deadline_(deadline),
                  rewrite_possible_(rewrite_possible), candidate_(candidate ? std::optional<std::string>(*candidate) : std::nullopt) {}
            auto cancel() noexcept -> void { canceled_ = true; lookup_.cancel(); if (local_resolver_) local_resolver_->cancel(); }
            auto run() -> udp_capy::task<dns::AddressRaceResult> {
                using Error = dns::detail::ResolveError;
                if (canceled_) co_return std::unexpected(Error::canceled);
                auto candidate = candidate_ ? std::optional<std::string_view>(*candidate_) : std::nullopt;
                if (step_.action == policy::DnsAction::evaluate) {
                    auto response = co_await select_response_server(owner_, lookup_, local_resolver_, canceled_, rotation_,
                        snapshot_, step_.server, name_, type_, deadline_, step_.disable_cache || rewrite_possible_,
                        candidate, step_.subnet.value_or(std::nullopt));
                    if (canceled_) co_return std::unexpected(Error::canceled);
                    if (!response) co_return std::unexpected(response.error());
                    co_return dns::AddressRaceValue{std::move(*response)};
                }
                if (step_.action != policy::DnsAction::route || step_.server >= owner_.response_routing_->servers.size())
                    co_return std::unexpected(Error::state);
                auto local = !owner_.response_routing_->servers[step_.server].endpoint.port();
                auto name = local && candidate_ ? *candidate_ + "." : name_;
                auto answer = co_await route_response_server_owned(owner_, lookup_, local_resolver_, canceled_, rotation_,
                    snapshot_, step_.server, name, type_, deadline_, step_.disable_cache || rewrite_possible_,
                    step_.subnet.value_or(std::nullopt));
                if (canceled_) co_return std::unexpected(Error::canceled);
                if (!answer) co_return std::unexpected(answer.error());
                co_return dns::AddressRaceValue{std::move(*answer)};
            }
        };

        template<class Operation, class Lookup>
        struct AddressRaceFactory {
            Operation& owner;
            std::string const& name;
            std::uint16_t type;
            bool rewrite_possible;
            std::optional<std::string_view> candidate;
            auto operator()(dns::ResponseStep step, std::chrono::steady_clock::time_point until)
                -> std::unique_ptr<AddressRaceOperation<Operation, Lookup>> {
                auto fixed = candidate ? candidate : owner.local_candidate_ && owner.local_candidate_->first == step.server ?
                    std::optional<std::string_view>{owner.local_candidate_->second} : std::nullopt;
                return std::make_unique<AddressRaceOperation<Operation, Lookup>>(owner, step, name, type, until, rewrite_possible, fixed);
            }
            auto completed(dns::ResponseStep const& step, dns::detail::EvaluatedResponseMeta const& meta) -> void {
                dns::AddressRaceLocalCandidate{owner.local_candidate_}.completed(step, meta);
            }
        };

        template<class Operation>
        static auto response_address(Operation& owner, std::string const& name, std::uint16_t type,
            std::chrono::steady_clock::time_point deadline, std::optional<std::string_view> candidate, bool& local)
            -> udp_capy::task<std::expected<dns::AddressAnswer, dns::detail::ResolveError>> {
            using Error = dns::detail::ResolveError;
            using Lookup = typename std::remove_reference_t<Operation>::LookupType;
            auto route_server = [&](std::size_t selected, std::string const& qname,
                std::chrono::steady_clock::time_point until, bool disabled, std::optional<dns::ClientSubnet> subnet) {
                return route_response_server_owned(owner, owner.lookup_, owner.local_resolver_, owner.canceled_,
                    owner.response_rotation_, owner.local_snapshot_, selected, qname, type, until, disabled, subnet);
            };
            auto rewrite_possible = std::ranges::any_of(owner.response_routing_->rules,
                [](auto const& rule) { return rule.rewrite_ttl.has_value(); });
            if (!owner.response_modes_.empty() || policy::dns_has_concurrent_rules(owner.response_routing_->rules)) {
                if constexpr (requires(Lookup const& l) { l.fork(); }) {
                    using Op = AddressRaceOperation<Operation, Lookup>;
                    using Program = dns::AddressRaceProgram<Op>;
                    if (!owner.response_modes_.empty() && owner.response_modes_.size() != owner.response_routing_->rules.size())
                        co_return std::unexpected(Error::state);
                    Program program(owner.context_, owner.response_routing_->rules, owner.response_modes_,
                        owner.response_routing_->fallback, owner.disable_cache_);
                    struct Registration {
                        Operation& owner;
                        ~Registration() { owner.cancel_response_operation_ = nullptr; owner.response_operation_ = nullptr; }
                    } registration{owner};
                    owner.response_operation_ = &program;
                    owner.cancel_response_operation_ = [](void* value) noexcept { static_cast<Program*>(value)->cancel(); };
                    AddressRaceFactory<Operation, Lookup> factory{owner, name, type, rewrite_possible, candidate};
                    auto decision = co_await program.run(factory, name, type, owner.response_context_.view(), deadline);
                    owner.response_operation_ = nullptr;
                    owner.cancel_response_operation_ = nullptr;
                    if (owner.canceled_) co_return std::unexpected(Error::canceled);
                    if (!decision) co_return std::unexpected(decision.error());
                    auto const& step = decision->step;
                    if (step.action == policy::DnsAction::reject) co_return std::unexpected(Error::policy_rejected);
                    if (step.action == policy::DnsAction::predefined) {
                        if (step.rule >= owner.response_routing_->rules.size() || !owner.response_routing_->rules[step.rule].predefined)
                            co_return std::unexpected(Error::state);
                        co_return dns::predefined_addresses(*owner.response_routing_->rules[step.rule].predefined, {name, type});
                    }
                    if (step.action == policy::DnsAction::route) {
                        if (step.server >= owner.response_routing_->servers.size()) co_return std::unexpected(Error::state);
                        local = !owner.response_routing_->servers[step.server].endpoint.port();
                        if (decision->route) {
                            if (!*decision->route) co_return std::unexpected(decision->route->error());
                            auto* answer = std::get_if<dns::AddressAnswer>(&**decision->route);
                            if (!answer) co_return std::unexpected(Error::state);
                            co_return std::move(*answer);
                        }
                        auto route_name = local && candidate ? std::string(*candidate) + "." : name;
                        auto until = step.timeout_ms ? std::min(deadline, std::chrono::steady_clock::now() + std::chrono::milliseconds(*step.timeout_ms)) : deadline;
                        co_return co_await route_server(step.server, route_name, until,
                            step.disable_cache || rewrite_possible, step.subnet.value_or(std::nullopt));
                    }
                    if (step.action != policy::DnsAction::respond || !decision->response || !decision->metadata)
                        co_return std::unexpected(Error::state);
                    auto& selected = *decision->metadata;
                    local = selected.local;
                    if (selected.local && !selected.upstream.port() && selected.empty)
                        co_return std::unexpected(Error::no_data);
                    owner.response_address_resolver_.emplace(owner.context_, selected.tcp, owner.edns_,
                        selected.subnet, selected.protection.get());
                    auto generator = [] { return dns::detail::random_id(); };
                    auto answer = co_await owner.response_address_resolver_->resolve(
                        selected.upstream, {selected.question, type}, selected.deadline, generator, &decision->response);
                    owner.response_address_resolver_.reset();
                    if (owner.canceled_) co_return std::unexpected(Error::canceled);
                    co_return answer;
                } else co_return std::unexpected(Error::state);
            }
            dns::ResponseWalk walk(owner.response_routing_->rules, owner.response_routing_->fallback, owner.disable_cache_);
            std::optional<dns::detail::EvaluatedResponseMeta> evaluated;
            std::vector<std::pair<std::string_view, dns::detail::EvaluatedResponseMeta>> named_evaluations;
            for (;;) {
                if (owner.canceled_) co_return std::unexpected(Error::canceled);
                if (std::chrono::steady_clock::now() >= deadline) co_return std::unexpected(Error::timeout);
                auto step = walk.next(name, type, owner.response_context_.view());
                if (!step) co_return std::unexpected(step.error() == dns::ResponseProgramError::resource_limit ? Error::limit : Error::state);
                auto action_deadline = step->timeout_ms ?
                    std::min(deadline, std::chrono::steady_clock::now() + std::chrono::milliseconds(*step->timeout_ms)) : deadline;
                if (step->action == policy::DnsAction::reject) co_return std::unexpected(Error::policy_rejected);
                if (step->action == policy::DnsAction::predefined) {
                    auto answer = dns::predefined_addresses(*owner.response_routing_->rules[step->rule].predefined, {name, type});
                    co_return answer;
                }
                if (step->action == policy::DnsAction::route) {
                    local = !owner.response_routing_->servers[step->server].endpoint.port();
                    auto route_name = local && candidate ? std::string(*candidate) + "." : name;
                    auto answer = co_await route_server(step->server, route_name, action_deadline,
                        step->disable_cache || rewrite_possible, step->subnet.value_or(std::nullopt));
                    co_return answer;
                }
                if (step->action == policy::DnsAction::evaluate) {
                    auto fixed = candidate ? candidate : owner.local_candidate_ && owner.local_candidate_->first == step->server ?
                        std::optional<std::string_view>{owner.local_candidate_->second} : std::nullopt;
                    auto evaluation_subnet = step->subnet.value_or(std::nullopt);
                    std::expected<ResponseSelection, Error> result = std::unexpected(Error::state);
                    if constexpr (requires(Lookup& l) { l.fork(); }) {
                        ResponseOperation<Operation, Lookup> operation(owner, owner.lookup_, step->server, name, type,
                            action_deadline, step->disable_cache || rewrite_possible, fixed, evaluation_subnet);
                        struct Registration {
                            Operation& owner;
                            ~Registration() { owner.cancel_response_operation_ = nullptr; owner.response_operation_ = nullptr; }
                        } registration{owner};
                        owner.response_operation_ = &operation;
                        owner.cancel_response_operation_ = [](void* value) noexcept {
                            static_cast<ResponseOperation<Operation, Lookup>*>(value)->cancel();
                        };
                        result = co_await operation.run();
                    } else {
                        result = co_await select_response_server(owner, owner.lookup_, owner.local_resolver_, owner.canceled_,
                            owner.response_rotation_, owner.local_snapshot_, step->server, name, type, action_deadline,
                            step->disable_cache || rewrite_possible, fixed, evaluation_subnet);
                    }
                    if (!result) {
                        if (result.error() == Error::canceled || owner.canceled_) co_return std::unexpected(Error::canceled);
                        if (result.error() == Error::budget_exhausted) co_return std::unexpected(Error::limit);
                        if (!walk.failed()) co_return std::unexpected(Error::state);
                        continue;
                    }
                    auto selected = std::move(*result);
                    if (selected.local && !owner.local_candidate_) owner.local_candidate_.emplace(step->server, selected.question);
                    if (step->rewrite_ttl) {
                        auto const& raw = selected.response.wire;
                        if (raw.size() < 2) co_return std::unexpected(Error::protocol);
                        auto id = static_cast<std::uint16_t>((std::uint16_t(raw[0]) << 8) | raw[1]);
                        if (!dns::rewrite_response(selected.response, id, step->rewrite_ttl)) co_return std::unexpected(Error::protocol);
                    }
                    dns::detail::EvaluatedResponseMeta meta{selected.upstream, selected.tcp, std::move(selected.question),
                        selected.local, selected.response.records.empty(), action_deadline, evaluation_subnet, selected.protection};
                    auto saved = walk.evaluated(std::move(selected.response));
                    if (!saved) co_return std::unexpected(saved.error() == dns::ResponseProgramError::resource_limit ? Error::limit : Error::state);
                    if (step->response_tag) named_evaluations.emplace_back(*step->response_tag, std::move(meta));
                    else evaluated = std::move(meta);
                    continue;
                }
                if (step->action != policy::DnsAction::respond) co_return std::unexpected(Error::state);
                auto* selected = evaluated ? &*evaluated : nullptr;
                if (step->response_tag) {
                    auto found = std::ranges::find(named_evaluations, *step->response_tag,
                        &std::pair<std::string_view, dns::detail::EvaluatedResponseMeta>::first);
                    selected = found == named_evaluations.end() ? nullptr : &found->second;
                }
                if (!selected) co_return std::unexpected(Error::state);
                if (selected->local && !selected->upstream.port() && selected->empty) {
                    local = true;
                    co_return std::unexpected(Error::no_data);
                }
                auto first = walk.take_response();
                if (!first) co_return std::unexpected(Error::state);
                local = selected->local;
                owner.response_address_resolver_.emplace(owner.context_, selected->tcp, owner.edns_,
                    selected->subnet, selected->protection.get());
                auto generator = [] { return dns::detail::random_id(); };
                auto answer = co_await owner.response_address_resolver_->resolve(
                    selected->upstream, {selected->question, type}, selected->deadline, generator, &first);
                owner.response_address_resolver_.reset();
                if (owner.canceled_) co_return std::unexpected(Error::canceled);
                co_return answer;
            }
        }
    };
#endif
}
