// Response-phase DNS program execution, race orchestration, and owned evaluate operation.
module relay;
import :dns_internal;
import std;
import capy;
import corosio;
import relay.dns_backend;
import relay.dns_state;
import dns.address_race_program;
import dns.address_sequence;
import dns.corosio_local;
import dns.corosio_resolver;
import dns.local_config;
import dns.local_response;
import dns.message;
import dns.policy;
import dns.predefined;
import dns.response_program;
import dns.response_query;
import dns.response_race_walk;

namespace relay {
    namespace dns_detail {
        using RawSelection = dns::detail::LocalResponseSelection;

        // A response query owns its cancellation registration independently
        // of the enclosing session; a future concurrent owner can hold one
        // instance per evaluate without sharing a mutable resolver pointer.
        class ResponseOperation {
            Session& session_;
            corosio::io_context& context_;
            std::size_t selected_;
            std::string name_;
            std::uint16_t type_;
            Clock::time_point deadline_;
            std::shared_ptr<dns::LocalSnapshot const> snapshot_;
            bool disabled_, canceled_ = false, started_ = false;
            std::size_t* rotation_;
            std::optional<std::string> candidate_;
            std::optional<dns::ClientSubnet> subnet_;
            void* active_ = nullptr;
            void (*cancel_active_)(void*) noexcept = nullptr;
        public:
            ResponseOperation(Session& session, corosio::io_context& context, std::size_t selected,
                std::string const& name, std::uint16_t type, Clock::time_point deadline, LocalSnapshotRef snapshot,
                bool disabled, std::size_t* rotation, std::optional<std::string_view> candidate, std::optional<dns::ClientSubnet> subnet)
                : session_(session), context_(context), selected_(selected), name_(name), type_(type), deadline_(deadline),
                  snapshot_(snapshot ? *snapshot : nullptr), disabled_(disabled), rotation_(rotation),
                  candidate_(candidate ? std::optional<std::string>(*candidate) : std::nullopt), subnet_(subnet) {}
            ResponseOperation(ResponseOperation const&) = delete;
            auto operator=(ResponseOperation const&) -> ResponseOperation& = delete;
            auto cancel() noexcept -> void { canceled_ = true; if (cancel_active_) cancel_active_(active_); }
            auto run() -> capy::task<std::expected<RawSelection, dns::detail::ResolveError>> {
                if (std::exchange(started_, true)) co_return std::unexpected(dns::detail::ResolveError::state);
                if (canceled_ || session_.closed) co_return std::unexpected(dns::detail::ResolveError::canceled);
                auto candidate = candidate_ ? std::optional<std::string_view>(*candidate_) : std::nullopt;
                co_return co_await response_server(session_, context_, selected_, name_, type_, deadline_,
                    snapshot_ ? &snapshot_ : nullptr, disabled_, active_, cancel_active_, canceled_, rotation_, candidate, subnet_);
            }
        };

        namespace {
            class AddressRaceOperation {
                Session& session_;
                corosio::io_context& context_;
                dns::ResponseStep step_;
                Clock::time_point deadline_;
                std::string name_;
                std::uint16_t type_, port_;
                std::shared_ptr<dns::LocalSnapshot const> snapshot_;
                bool rewrite_possible_, canceled_ = false;
                std::size_t* rotation_;
                std::optional<std::string> candidate_;
                DnsSlot slot_;
            public:
                AddressRaceOperation(Session& session, corosio::io_context& context, dns::ResponseStep step, Clock::time_point deadline,
                    std::string const& name, std::uint16_t type, std::uint16_t port, std::shared_ptr<dns::LocalSnapshot const> snapshot,
                    bool rewrite_possible, std::size_t* rotation, std::optional<std::string_view> candidate)
                    : session_(session), context_(context), step_(step), deadline_(deadline), name_(name), type_(type), port_(port),
                      snapshot_(std::move(snapshot)), rewrite_possible_(rewrite_possible), rotation_(rotation),
                      candidate_(candidate ? std::optional<std::string>(*candidate) : std::nullopt) {}
                auto cancel() noexcept -> void { canceled_ = true; slot_.cancel(); }
                auto run() -> capy::task<dns::AddressRaceResult> {
                    using Error = dns::detail::ResolveError;
                    if (canceled_ || session_.closed) co_return std::unexpected(Error::canceled);
                    if (step_.action == policy::DnsAction::evaluate) {
                        auto result = co_await resolve_response_owned(session_, context_, slot_, step_.server, name_, type_, deadline_, snapshot_,
                            step_.disable_cache || rewrite_possible_, rotation_, candidate_, step_.subnet.value_or(std::nullopt));
                        if (!result) co_return std::unexpected(result.error());
                        co_return dns::AddressRaceValue{std::move(*result)};
                    }
                    auto const* routing = active_dns_routing(session_);
                    if (step_.action != policy::DnsAction::route || !routing || step_.server >= routing->servers.size())
                        co_return std::unexpected(Error::state);
                    if ((step_.strategy == rules::DnsRuleStrategy::ipv4_only && type_ == 28) ||
                        (step_.strategy == rules::DnsRuleStrategy::ipv6_only && type_ == 1))
                        co_return std::unexpected(Error::no_data);
                    auto local = !routing->servers[step_.server].port;
                    auto name = local && candidate_ ? *candidate_ + "." : name_;
                    auto family = type_ == 1 ? dns::detail::AddressStrategy::ipv4_only : dns::detail::AddressStrategy::ipv6_only;
                    dns::detail::FamilyCachePolicy cache{};
                    cache[type_ == 1 ? 0 : 1] = step_.disable_cache || rewrite_possible_;
                    auto sc = routing->independent_cache ? static_cast<std::uint32_t>(step_.rule + 1) : 0u;
                    auto result = co_await resolve_dns_full(session_, context_, step_.server, std::move(name), port_, family, deadline_,
                        slot_.operation, slot_.cancel_operation, &slot_.canceled, snapshot_ ? &snapshot_ : nullptr, cache, step_.subnet.value_or(std::nullopt), sc);
                    if (canceled_ || session_.closed) co_return std::unexpected(Error::canceled);
                    if (!result) co_return std::unexpected(result.error());
                    co_return dns::AddressRaceValue{std::move(*result)};
                }
            };

            struct AddressRaceFactory {
                Session& session;
                corosio::io_context& context;
                std::string const& name;
                std::uint16_t type, port;
                std::shared_ptr<dns::LocalSnapshot const> snapshot;
                bool rewrite_possible;
                std::size_t& rotation;
                std::string const& candidate;
                std::optional<std::pair<std::size_t, std::string>>& local_candidate;
                auto operator()(dns::ResponseStep step, Clock::time_point until) -> std::unique_ptr<AddressRaceOperation> {
                    auto fixed = !candidate.empty() ? std::optional<std::string_view>{candidate} :
                        local_candidate && local_candidate->first == step.server ? std::optional<std::string_view>{local_candidate->second} : std::nullopt;
                    return std::make_unique<AddressRaceOperation>(session, context, step, until, name, type, port, snapshot, rewrite_possible, &rotation, fixed);
                }
                auto completed(dns::ResponseStep const& step, dns::detail::EvaluatedResponseMeta const& meta) -> void {
                    dns::AddressRaceLocalCandidate{local_candidate}.completed(step, meta);
                }
            };

            struct AddressPolicyRegistration {
                void*& operation;
                void (*&cancel)(void*) noexcept;
                ~AddressPolicyRegistration() { cancel = nullptr; operation = nullptr; }
            };
        }

        auto resolve_response_program(Session& session, corosio::io_context& context, std::string const& name,
            std::uint16_t port, dns::detail::AddressStrategy family, Clock::time_point deadline, policy::DnsContext input,
            void*& registered, void (*&cancel)(void*) noexcept, bool const* canceled,
            std::optional<std::size_t> view_final, std::span<dns::ResponseRaceMode const> modes)
            -> capy::task<std::expected<std::vector<corosio::endpoint>, dns::detail::ResolveError>> {
            using Error = dns::detail::ResolveError;
            auto const* routing_ptr = active_dns_routing(session);
            if (!session.dns || !routing_ptr) co_return std::unexpected(Error::state);
            auto const& routing = *routing_ptr;
            // A later response-dependent option can change the effective TTL
            // after an evaluate, so its earlier cache lookup must also bypass.
            auto rewrite_possible = std::ranges::any_of(session.dns_rules(), [](auto const& rule) { return rule.rewrite_ttl.has_value(); });
            std::shared_ptr<dns::LocalSnapshot const> snapshot;
            if (session.local_dns) snapshot = session.local_dns->source.acquire();
            std::size_t rotation = (snapshot && snapshot->config.rotate && session.local_dns) ? session.local_dns->rotation++ : 0;
            auto types = dns::detail::address_types(family);
            auto count = dns::detail::address_type_count(family);
            std::vector<std::string> candidates;
            if (snapshot && count == 2 && std::ranges::any_of(routing.servers, [](auto const& server) { return !server.port; })) {
                auto host = dns::detail::local_hosts_response(*snapshot, name, types[0]);
                if (!host) co_return std::unexpected(host.error());
                if (host->response) candidates.push_back(host->question);
                else {
                    auto generated = dns::detail::local_response_candidates(snapshot->config, name, host->question);
                    if (!generated) co_return std::unexpected(generated.error());
                    candidates = std::move(*generated);
                }
            } else candidates.emplace_back();
            for (auto const& candidate : candidates) {
                dns::detail::AddressAnswers<false> answers;
                bool local_used = false;
                std::optional<std::pair<std::size_t, std::string>> local_candidate;
                bool next_candidate = false;
                for (unsigned i = 0; i < count; ++i) {
                    if (!modes.empty() || policy::dns_has_concurrent_rules(session.dns_rules())) {
                        using Program = dns::AddressRaceProgram<AddressRaceOperation>;
                        if (cancel || (!modes.empty() && modes.size() != session.dns_rules().size()))
                            co_return std::unexpected(Error::state);
                        Program program(context, session.dns_rules(), modes, view_final.value_or(routing.final), routing.disable_cache);
                        AddressPolicyRegistration registration{registered, cancel};
                        registered = &program;
                        cancel = [](void* value) noexcept { static_cast<Program*>(value)->cancel(); };
                        AddressRaceFactory factory{session, context, name, types[i], port, snapshot, rewrite_possible, rotation, candidate, local_candidate};
                        auto decision = co_await program.run(factory, name, types[i], input, deadline);
                        cancel = nullptr;
                        registered = nullptr;
                        if (session.closed || (canceled && *canceled)) co_return std::unexpected(Error::canceled);
                        if (!decision) co_return std::unexpected(decision.error());
                        auto const& step = decision->step;
                        if (step.action == policy::DnsAction::reject) co_return std::unexpected(Error::policy_rejected);
                        if (step.action == policy::DnsAction::predefined) {
                            if (step.rule >= session.dns_rules().size() || !session.dns_rules()[step.rule].predefined)
                                co_return std::unexpected(Error::state);
                            auto added = answers.add(dns::predefined_addresses(*session.dns_rules()[step.rule].predefined, {name, types[i]}));
                            if (!added) co_return std::unexpected(added.error());
                        } else if (step.action == policy::DnsAction::route) {
                            if (step.server >= routing.servers.size()) co_return std::unexpected(Error::state);
                            auto local = !routing.servers[step.server].port;
                            local_used |= local;
                            std::expected<dns::AddressAnswer, Error> answer = std::unexpected(Error::state);
                            if (decision->route) {
                                if (!*decision->route) answer = std::unexpected(decision->route->error());
                                else if (auto* selected = std::get_if<dns::AddressAnswer>(&**decision->route)) answer = std::move(*selected);
                            } else {
                                if ((step.strategy == rules::DnsRuleStrategy::ipv4_only && types[i] == 28) ||
                                    (step.strategy == rules::DnsRuleStrategy::ipv6_only && types[i] == 1)) {
                                    answer = std::unexpected(Error::no_data);
                                } else {
                                    auto one = types[i] == 1 ? dns::detail::AddressStrategy::ipv4_only : dns::detail::AddressStrategy::ipv6_only;
                                    dns::detail::FamilyCachePolicy cache{};
                                    cache[types[i] == 1 ? 0 : 1] = step.disable_cache || rewrite_possible;
                                    auto route_name = local && !candidate.empty() ? candidate + "." : name;
                                    auto until = step.timeout_ms ? std::min(deadline, Clock::now() + std::chrono::milliseconds(*step.timeout_ms)) : deadline;
                                    auto sc = routing.independent_cache ? static_cast<std::uint32_t>(step.rule + 1) : 0u;
                                    answer = co_await resolve_dns_full(session, context, step.server, route_name, port, one, until,
                                        registered, cancel, canceled, snapshot ? &snapshot : nullptr, cache, step.subnet.value_or(std::nullopt), sc);
                                }
                            }
                            auto added = answers.add(std::move(answer));
                            if (!added) { if (local && added.error() == Error::name_not_found) { next_candidate = true; break; } co_return std::unexpected(added.error()); }
                        } else if (step.action == policy::DnsAction::respond) {
                            if (!decision->response || !decision->metadata) co_return std::unexpected(Error::state);
                            auto& selected = *decision->metadata;
                            local_used |= selected.local;
                            if (selected.local && !selected.upstream.port() && selected.empty) {
                                auto added = answers.add(std::unexpected(Error::no_data));
                                if (!added) co_return std::unexpected(added.error());
                            } else {
                                dns::detail::AddressResolver resolver(context, selected.tcp, routing.edns, selected.subnet, selected.protection.get());
                                AddressPolicyRegistration active{registered, cancel};
                                registered = &resolver;
                                cancel = [](void* value) noexcept { static_cast<dns::detail::AddressResolver*>(value)->cancel(); };
                                auto generator = [] { return dns::detail::random_id(); };
                                auto answer = co_await resolver.resolve(selected.upstream, {selected.question, types[i]}, selected.deadline, generator, &decision->response);
                                if (session.closed || (canceled && *canceled)) co_return std::unexpected(Error::canceled);
                                auto added = answers.add(std::move(answer));
                                if (!added) { if (selected.local && added.error() == Error::name_not_found) { next_candidate = true; break; } co_return std::unexpected(added.error()); }
                            }
                        } else co_return std::unexpected(Error::state);
                        continue;
                    }
                    dns::ResponseWalk walk(session.dns_rules(), view_final.value_or(routing.final), routing.disable_cache);
                    std::optional<dns::detail::EvaluatedResponseMeta> evaluation;
                    std::vector<std::pair<std::string_view, dns::detail::EvaluatedResponseMeta>> named_evaluations;
                    for (;;) {
                        if (session.closed || (canceled && *canceled)) co_return std::unexpected(Error::canceled);
                        if (Clock::now() >= deadline) co_return std::unexpected(Error::timeout);
                        auto step = walk.next(name, types[i], input);
                        if (!step) co_return std::unexpected(step.error() == dns::ResponseProgramError::resource_limit ? Error::limit : Error::state);
                        auto action_deadline = step->timeout_ms ? std::min(deadline, Clock::now() + std::chrono::milliseconds(*step->timeout_ms)) : deadline;
                        if (step->action == policy::DnsAction::reject) co_return std::unexpected(Error::policy_rejected);
                        if (step->action == policy::DnsAction::predefined) {
                            auto const& definition = *session.dns_rules()[step->rule].predefined;
                            auto answer = dns::predefined_addresses(definition, {name, types[i]});
                            auto added = answers.add(std::move(answer));
                            if (!added) co_return std::unexpected(added.error());
                            break;
                        }
                        auto one = types[i] == 1 ? dns::detail::AddressStrategy::ipv4_only : dns::detail::AddressStrategy::ipv6_only;
                        if (step->action == policy::DnsAction::route) {
                            if ((step->strategy == rules::DnsRuleStrategy::ipv4_only && types[i] == 28) ||
                                (step->strategy == rules::DnsRuleStrategy::ipv6_only && types[i] == 1)) {
                                auto added = answers.add(std::unexpected(Error::no_data));
                                if (!added) co_return std::unexpected(added.error());
                                break;
                            }
                            dns::detail::FamilyCachePolicy cache{};
                            cache[types[i] == 1 ? 0 : 1] = step->disable_cache || rewrite_possible;
                            auto local = !routing.servers[step->server].port;
                            local_used |= local;
                            auto route_name = local && !candidate.empty() ? candidate + "." : name;
                            auto sc = routing.independent_cache ? static_cast<std::uint32_t>(step->rule + 1) : 0u;
                            auto answer = co_await resolve_dns_full(session, context, step->server, route_name, port, one, action_deadline,
                                registered, cancel, canceled, snapshot ? &snapshot : nullptr, cache, step->subnet.value_or(std::nullopt), sc);
                            auto added = answers.add(std::move(answer));
                            if (!added) {
                                if (local && added.error() == Error::name_not_found) { next_candidate = true; break; }
                                co_return std::unexpected(added.error());
                            }
                            break;
                        }
                        if (step->action == policy::DnsAction::evaluate) {
                            auto fixed = !candidate.empty() ? std::optional<std::string_view>{candidate} :
                                local_candidate && local_candidate->first == step->server ? std::optional<std::string_view>{local_candidate->second} : std::nullopt;
                            auto evaluation_subnet = step->subnet.value_or(std::nullopt);
                            if (cancel) co_return std::unexpected(Error::state);
                            ResponseOperation operation(session, context, step->server, name, types[i], action_deadline, snapshot ? &snapshot : nullptr,
                                step->disable_cache || rewrite_possible, &rotation, fixed, evaluation_subnet);
                            AddressPolicyRegistration registration{registered, cancel};
                            registered = &operation;
                            cancel = [](void* value) noexcept { static_cast<ResponseOperation*>(value)->cancel(); };
                            auto result = co_await operation.run();
                            if (!result) {
                                if (result.error() == Error::canceled || session.closed) co_return std::unexpected(Error::canceled);
                                if (result.error() == Error::budget_exhausted) co_return std::unexpected(Error::limit);
                                if (!walk.failed()) co_return std::unexpected(Error::state);
                                continue;
                            }
                            auto selected = std::move(*result);
                            if (selected.local && !local_candidate) local_candidate.emplace(step->server, selected.question);
                            if (step->rewrite_ttl) {
                                auto const& raw = selected.response.wire;
                                if (raw.size() < 2) co_return std::unexpected(Error::protocol);
                                auto id = static_cast<std::uint16_t>((std::uint16_t(raw[0]) << 8) | raw[1]);
                                if (!dns::rewrite_response(selected.response, id, step->rewrite_ttl)) co_return std::unexpected(Error::protocol);
                            }
                            dns::detail::EvaluatedResponseMeta meta{selected.upstream, selected.tcp, std::move(selected.question), selected.local,
                                selected.response.records.empty(), action_deadline, evaluation_subnet, selected.protection};
                            auto saved = walk.evaluated(std::move(selected.response));
                            if (!saved) co_return std::unexpected(saved.error() == dns::ResponseProgramError::resource_limit ? Error::limit : Error::state);
                            if (step->response_tag) named_evaluations.emplace_back(*step->response_tag, std::move(meta));
                            else evaluation = std::move(meta);
                            continue;
                        }
                        if (step->action == policy::DnsAction::respond) {
                            auto* selected = evaluation ? &*evaluation : nullptr;
                            if (step->response_tag) {
                                auto found = std::ranges::find(named_evaluations, *step->response_tag, &std::pair<std::string_view, dns::detail::EvaluatedResponseMeta>::first);
                                selected = found == named_evaluations.end() ? nullptr : &found->second;
                            }
                            if (!selected || cancel) co_return std::unexpected(Error::state);
                            local_used |= selected->local;
                            if (selected->local && !selected->upstream.port() && selected->empty) {
                                auto added = answers.add(std::unexpected(Error::no_data));
                                if (!added) co_return std::unexpected(added.error());
                                break;
                            }
                            auto first = walk.take_response();
                            if (!first) co_return std::unexpected(Error::state);
                            dns::detail::AddressResolver resolver(context, selected->tcp, routing.edns, selected->subnet, selected->protection.get());
                            AddressPolicyRegistration registration{registered, cancel};
                            registered = &resolver;
                            cancel = [](void* value) noexcept { static_cast<dns::detail::AddressResolver*>(value)->cancel(); };
                            auto generator = [] { return dns::detail::random_id(); };
                            auto answer = co_await resolver.resolve(selected->upstream, {selected->question, types[i]}, selected->deadline, generator, &first);
                            if (session.closed || (canceled && *canceled)) co_return std::unexpected(Error::canceled);
                            auto added = answers.add(std::move(answer));
                            if (!added) {
                                if (selected->local && added.error() == Error::name_not_found) { next_candidate = true; break; }
                                co_return std::unexpected(added.error());
                            }
                            break;
                        }
                        co_return std::unexpected(Error::state);
                    }
                    if (next_candidate) break;
                }
                if (next_candidate) continue;
                auto result = answers.finish();
                if (!result) {
                    if (local_used && result.error() == Error::no_data) continue;
                    co_return std::unexpected(result.error());
                }
                co_return endpoints(*result, port);
            }
            co_return std::unexpected(Error::no_data);
        }
    }

    auto resolve_response_owned(Session& session, corosio::io_context& context, DnsSlot& slot, std::size_t selected,
        std::string name, std::uint16_t type, Clock::time_point deadline, std::shared_ptr<dns::LocalSnapshot const> snapshot,
        bool disable_cache, std::size_t* rotation, std::optional<std::string> candidate, std::optional<dns::ClientSubnet> subnet)
        -> capy::task<std::expected<dns::detail::LocalResponseSelection, dns::detail::ResolveError>> {
        using Error = dns::detail::ResolveError;
        if (slot.canceled || session.closed) co_return std::unexpected(Error::canceled);
        auto const* routing_ptr = dns_detail::active_dns_routing(session);
        if (slot.operation || slot.cancel_operation || !session.dns || !routing_ptr || selected >= routing_ptr->servers.size())
            co_return std::unexpected(Error::state);
        auto fixed = candidate ? std::optional<std::string_view>(*candidate) : std::nullopt;
        dns_detail::ResponseOperation operation(session, context, selected, name, type, deadline, snapshot ? &snapshot : nullptr,
            disable_cache, rotation, fixed, subnet);
        struct Registration { DnsSlot& slot; ~Registration() { slot.cancel_operation = nullptr; slot.operation = nullptr; } } registration{slot};
        slot.operation = &operation;
        slot.cancel_operation = [](void* value) noexcept { static_cast<dns_detail::ResponseOperation*>(value)->cancel(); };
        auto result = co_await operation.run();
        if (slot.canceled || session.closed) co_return std::unexpected(Error::canceled);
        co_return result;
    }
}
