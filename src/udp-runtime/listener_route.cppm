// Ordered routing & DNS launch helpers for BasicUdpListener.
export module ss_udp.listener_route;
import std;
import corosio;
import dns.corosio_local;
import dns.policy;
import rules;
import ss_udp.ordered_route;
export import ss_udp.resolve;

export namespace shadowsocks::detail {
    enum class UdpTunnelReplyResult { delivered, dropped, busy, error };
    using UdpTunnelReplySink = std::function<UdpTunnelReplyResult(UdpSessionHandle const&, UdpPeer, std::span<std::uint8_t const>)>;

    struct UdpOrderedRouting {
        std::shared_ptr<rules::RouteProgram const> program;
        std::size_t fallback = 0;
        bool skip_unknown = false;
        std::chrono::milliseconds sniff_timeout{200};
        std::function<bool(std::size_t)> allows;
        std::function<std::expected<void, UdpResolveError>(udp_io::io_context&, UdpDispatcher&, std::uint64_t, std::size_t,
            std::span<UdpPeer const>, std::optional<std::string_view>, std::chrono::steady_clock::time_point, UdpTunnelReplySink)> send;
        std::function<void()> stop;
        std::function<bool()> drained;
        std::function<void()> finish;
    };

    struct ListenerRouteOps {
        template<class Listener>
        static auto advance_ordered(Listener& owner, OrderedUdpDecision& decision, std::uint64_t token,
            std::chrono::steady_clock::time_point& deadline) -> std::expected<UdpResolvedAction, UdpResolveError> {
            using Clock = std::chrono::steady_clock;
            auto fail = [&](UdpResolveError error) -> std::expected<UdpResolvedAction, UdpResolveError> {
                (void)owner.sniff_owner_->complete(token);
                return std::unexpected(error);
            };
            auto now = Clock::now();
            if (owner.stopped_ || now >= deadline) return fail(UdpResolveError::canceled);
            auto packet = owner.state_.dispatcher().pending_packet(token);
            if (!packet) return fail(UdpResolveError::state);
            auto step = decision.next(packet->packet.payload, true);
            deadline = std::min(deadline, decision.limit());
            if (Clock::now() >= deadline) return fail(UdpResolveError::canceled);
            if (step.stop == OrderedUdpStop::sniff_wait) {
                if (!owner.sniff_owner_->wait(token, now)) return fail(UdpResolveError::state);
                return UdpResolvedAction::complete;
            }
            if (step.stop == OrderedUdpStop::resolve) return UdpResolvedAction::resolve_again;
            if (step.stop != OrderedUdpStop::route || !owner.ordered_->allows(step.outbound))
                return fail(UdpResolveError::dispatch);
            if (decision.needs_resolution()) {
                if (!decision.resolve_selected()) return fail(UdpResolveError::state);
                return UdpResolvedAction::resolve_again;
            }
            UdpTunnelReplySink sink = [&owner](UdpSessionHandle const& session, UdpPeer source, std::span<std::uint8_t const> payload) {
                return owner.queue_tunnel_reply(session, source, payload);
            };
            auto sent = owner.ordered_->send(owner.context_, owner.state_.dispatcher(), token, step.outbound,
                decision.candidates(), decision.inbound(), deadline, std::move(sink));
            (void)owner.sniff_owner_->complete(token);
            if (!sent) return std::unexpected(sent.error());
            return UdpResolvedAction::complete;
        }

        template<class Listener>
        static auto send_legacy(Listener& owner, std::uint64_t token, std::span<UdpPeer const> candidates,
            std::optional<std::string_view> inbound, std::chrono::steady_clock::time_point deadline)
            -> std::expected<UdpResolvedAction, UdpResolveError> {
            using Clock = std::chrono::steady_clock;
            auto selected = owner.state_.dispatcher().select_route(token, candidates, Clock::now());
            if (!selected) return std::unexpected(UdpResolveError::dispatch);
            std::array target{selected->target};
            UdpTunnelReplySink sink = [&owner](UdpSessionHandle const& session, UdpPeer source, std::span<std::uint8_t const> payload) {
                return owner.queue_tunnel_reply(session, source, payload);
            };
            auto sent = owner.ordered_->send(owner.context_, owner.state_.dispatcher(), token, selected->outbound,
                target, inbound, deadline, std::move(sink));
            if (!sent) return std::unexpected(sent.error());
            return UdpResolvedAction::complete;
        }

        template<class Listener>
        static auto start_resolution(Listener& owner, UdpPending pending, UdpPeer source,
            std::optional<std::string_view> inbound, std::chrono::steady_clock::time_point deadline,
            std::shared_ptr<OrderedUdpDecision> decision = {}) -> bool {
            using Clock = std::chrono::steady_clock;
            auto const& a = pending.address;
            if (a.size() < 5 || a[0] != 3 || a.size() != static_cast<std::size_t>(a[1]) + 4) return false;
            UdpResolvePlan plan{owner.upstream_, 1, owner.dns_options_.tcp_only, {}};
            std::optional<UdpResolvePlan> alternate;
            std::optional<dns::detail::FamilyCachePolicy> cache_policy;
#ifdef NEXUS_DNS_RESPONSE
            UdpResponseRouting const* response_routing = nullptr;
            UdpResponseContext response_context{};
#endif
            if (owner.dns_routing_) {
                auto name = std::string_view(reinterpret_cast<char const*>(a.data() + 2), a[1]);
                auto types = dns::detail::address_types(owner.dns_options_.strategy);
                auto* packet = owner.state_.dispatcher().pending_packet(pending.token);
                auto auth_user = packet ? packet->auth_user : std::nullopt;
                policy::DnsContext input{.network = rules::Network::udp, .source_port = source.port,
                    .source_ip_bytes = std::span(source.address).first(source.family == 4 ? 4 : 16),
                    .inbound = inbound, .auth_user = auth_user};
#ifdef NEXUS_DNS_RESPONSE
                if (owner.has_response_program_) {
                    for (unsigned i = 0; i < dns::detail::address_type_count(owner.dns_options_.strategy); ++i)
                        if (policy::dns_preflight_reject(owner.dns_routing_->rules, name, types[i], input)) return false;
                    response_routing = &*owner.dns_routing_;
                    response_context.source = source.address;
                    response_context.size = source.family == 4 ? 4 : 16;
                    response_context.port = source.port;
                    response_context.inbound = inbound;
                    response_context.auth_user = auth_user;
                } else {
#endif
                    auto selected = policy::select_question_dns_action(owner.dns_routing_->rules, name, types[0],
                        owner.dns_routing_->fallback, owner.dns_options_.disable_cache, input);
                    auto second = dns::detail::address_type_count(owner.dns_options_.strategy) == 2 ?
                        policy::select_question_dns_action(owner.dns_routing_->rules, name, types[1],
                            owner.dns_routing_->fallback, owner.dns_options_.disable_cache, input) : selected;
                    if (selected.action == policy::DnsAction::reject || second.action == policy::DnsAction::reject)
                        return false;
                    cache_policy.emplace();
                    (*cache_policy)[types[0] == 1 ? 0 : 1] = selected.disable_cache;
                    if (dns::detail::address_type_count(owner.dns_options_.strategy) == 2)
                        (*cache_policy)[types[1] == 1 ? 0 : 1] = second.disable_cache;
                    plan = owner.dns_plan(selected.server);
                    if (dns::detail::address_type_count(owner.dns_options_.strategy) == 2 && second.server != selected.server)
                        alternate = owner.dns_plan(second.server);
#ifdef NEXUS_DNS_RESPONSE
                }
#endif
            }
            UdpResolvedHandler handler;
            if (decision)
                handler = [&owner, decision](std::uint64_t token, std::span<UdpPeer const> candidates,
                    Clock::time_point& deadline_ref) -> std::expected<UdpResolvedAction, UdpResolveError> {
                    if (!decision->supply(candidates)) {
                        (void)owner.sniff_owner_->complete(token);
                        return std::unexpected(UdpResolveError::state);
                    }
                    return advance_ordered(owner, *decision, token, deadline_ref);
                };
            else if (owner.ordered_)
                handler = [&owner, inbound](std::uint64_t token, std::span<UdpPeer const> candidates,
                    Clock::time_point& until) {
                    return send_legacy(owner, token, candidates, inbound, until);
                };
            auto started = owner.resolver_.start(std::move(pending), plan.upstream, plan.view, Clock::now(), deadline,
                owner.dns_options_.strategy, plan.tcp, owner.dns_options_.disable_cache, owner.dns_options_.edns,
                std::move(plan.hops), std::move(alternate), cache_policy
#ifdef NEXUS_DNS_RESPONSE
                , response_routing, response_context
#endif
                , std::move(handler));
            return started.has_value();
        }

        template<class Listener>
        static auto drain_ordered(Listener& owner) -> void {
            using Clock = std::chrono::steady_clock;
            auto busy = [&owner](std::uint64_t token) { return owner.resolver_.busy(token); };
            while (!owner.stopped_) {
                auto ready = owner.sniff_owner_->pop(Clock::now(), busy);
                if (!ready) break;
                struct Guard {
                    Listener& owner;
                    std::uint64_t token;
                    bool transferred = false;
                    ~Guard() {
                        if (!transferred) {
                            (void)owner.sniff_owner_->complete(token);
                            (void)owner.state_.dispatcher().cancel(token);
                        }
                    }
                } guard{owner, ready->token};
                auto result = advance_ordered(owner, *ready->decision, ready->token, ready->deadline);
                if (!result) continue;
                if (*result == UdpResolvedAction::complete) { guard.transferred = true; continue; }
                auto packet = owner.state_.dispatcher().pending_packet(ready->token);
                if (!packet) continue;
                guard.transferred = start_resolution(owner, {ready->token, packet->packet.address}, packet->source,
                    ready->decision->inbound(), ready->deadline, ready->decision);
            }
        }
    };
}
