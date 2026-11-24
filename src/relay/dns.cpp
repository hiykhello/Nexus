module relay;
import :dns_internal;
import std;
import relay.dns_state;
import dns.corosio_local;
import dns.response_program;
import dns.address_race_program;
import dns.response_race_walk;
import dns.response_query;
import dns.local_response;
import dns.predefined;
import dns.shared_coordinator;
import relay.dns_backend;
import capy;
import corosio;
#ifdef NEXUS_TEST_DNS_LIFETIME
extern "C" void nexus_test_dns_registered();
#endif
#ifdef NEXUS_TEST_DNS_OWNER
extern "C" void nexus_test_dns_registration_destroy();
#endif
#ifdef NEXUS_TEST_DNS_SHARED_ACCESS
extern "C" void nexus_test_dns_shared_access(void const*) noexcept;
#endif
namespace relay {
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
    using GroupRefresh=dns::detail::BasicRefreshOwner<dns_hp_experiment::GroupBinding>;
#endif
    namespace {
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
        auto coordinated_strategy(dns::detail::AddressStrategy value) -> dns_hp_experiment::CoordinatedStrategy {
            using Source=dns::detail::AddressStrategy;
            using Target=dns_hp_experiment::CoordinatedStrategy;
            switch (value) {
            case Source::prefer_ipv4: return Target::prefer_ipv4;
            case Source::prefer_ipv6: return Target::prefer_ipv6;
            case Source::ipv4_only: return Target::ipv4_only;
            case Source::ipv6_only: return Target::ipv6_only;
            }
            std::terminate();
        }
#endif
        using dns_detail::strategy;
        using dns_detail::endpoints;
        using dns_detail::LocalSnapshotRef;
        using CachePolicy=std::optional<dns::detail::FamilyCachePolicy>;
        using DnsResult=std::expected<std::vector<corosio::endpoint>,dns::detail::ResolveError>;
        template<bool Full> using DnsValue=std::conditional_t<Full,dns::AddressAnswer,std::vector<corosio::endpoint>>;
        template<bool Full> using DnsValueResult=std::expected<DnsValue<Full>,dns::detail::ResolveError>;
        template<bool Full>
        auto resolve_local_value(Session& session, corosio::io_context& context, std::string name, std::uint16_t port,
                                dns::detail::AddressStrategy family, Clock::time_point deadline,
                                void*& dns_operation, void (*&cancel_dns)(void*) noexcept,LocalSnapshotRef retained=nullptr,CachePolicy cache_policy={},
                                std::optional<dns::ClientSubnet> subnet={}) -> capy::task<DnsValueResult<Full>> {
            if (session.closed) co_return std::unexpected(dns::detail::ResolveError::canceled);
            if (!session.local_dns || !port || cancel_dns) co_return std::unexpected(dns::detail::ResolveError::state);
            if (subnet && !dns::valid_client_subnet(*subnet)) co_return std::unexpected(dns::detail::ResolveError::state);
            auto snapshot=retained ? *retained : session.local_dns->source.acquire();
            if (!snapshot) co_return std::unexpected(dns::detail::ResolveError::state);
            auto rotation=snapshot->config.rotate ? session.local_dns->rotation++ : 0;
#ifdef NEXUS_DNS_SHARED
            if (!session.dns || !session.dns->coordinator || !session.dns->reader || !session.dns->local_views)
                co_return std::unexpected(dns::detail::ResolveError::state);
            using LocalResolver=dns_hp_experiment::LocalCoordinatedResolver;
            LocalResolver operation(*session.dns->coordinator,*session.dns->reader,*session.dns->local_views,
                snapshot,family,rotation,session.dns->routing.disable_cache,cache_policy,subnet);
#else
            using LocalResolver=dns::detail::LocalAddressResolver;
            LocalResolver operation(context,snapshot->config,snapshot->hosts,family,rotation,subnet);
#endif
            struct Registration {
                void*& operation; void (*&cancel)(void*) noexcept;
                ~Registration() {
                    cancel=nullptr; operation=nullptr;
#ifdef NEXUS_TEST_DNS_OWNER
                    nexus_test_dns_registration_destroy();
#endif
                }
            } registration{dns_operation,cancel_dns};
            dns_operation=&operation;
            cancel_dns=[](void* pointer) noexcept { static_cast<LocalResolver*>(pointer)->cancel(); };
#ifdef NEXUS_TEST_DNS_LIFETIME
            nexus_test_dns_registered();
#endif
            auto addresses=co_await [&] {
                if constexpr (Full) return operation.resolve_answer(std::move(name),deadline);
                else return operation.resolve(std::move(name),deadline);
            }();
            if (session.closed) co_return std::unexpected(dns::detail::ResolveError::canceled);
            if (!addresses) co_return std::unexpected(addresses.error());
            if constexpr (Full) co_return std::move(*addresses);
            else { auto r=endpoints(*addresses,port); if (r.empty()) co_return std::unexpected(dns::detail::ResolveError::no_data); co_return r; }
        }
        auto resolve_local_impl(Session& s, corosio::io_context& c, std::string n, std::uint16_t p, dns::detail::AddressStrategy f, Clock::time_point d)
            -> capy::task<DnsResult> { co_return co_await resolve_local_value<false>(s,c,std::move(n),p,f,d,s.dns_operation,s.cancel_dns); }
        template<bool Full>
        auto try_resolve_cached(Session& session, std::size_t server_index, std::span<corosio::endpoint const> servers,
            std::string_view name, std::uint16_t port, dns::detail::AddressStrategy family, CachePolicy cache_policy,
            std::optional<dns::ClientSubnet> const& subnet, std::uint32_t rule_scope) -> std::optional<DnsValueResult<Full>> {
#if defined(NEXUS_TEST_DNS_LIFETIME) || defined(NEXUS_TEST_DNS_OWNER)
            (void)session; (void)server_index; (void)servers; (void)name; (void)port; (void)family; (void)cache_policy; (void)subnet; (void)rule_scope;
            return std::nullopt;
#else
            if (!session.dns || session.closed || !session.dns->routing.servers[server_index].port) return std::nullopt;
            if (subnet && !dns::valid_client_subnet(*subnet)) return std::unexpected(dns::detail::ResolveError::state);
            auto const& routing = session.dns->routing;
            auto disable = cache_policy.value_or(dns::detail::FamilyCachePolicy{routing.disable_cache, routing.disable_cache});
            auto types = dns::detail::address_types(family);
            auto count = dns::detail::address_type_count(family);
            for (unsigned i = 0; i < count; ++i) if (disable[types[i] == 1 ? 0 : 1]) return std::nullopt;
            corosio::endpoint upstream; bool found_up = false;
            for (auto const& ep : servers) if (valid_destination(ep)) { upstream = ep; found_up = true; break; }
            if (!found_up) return std::nullopt;
            auto* transports = session.dns_transports();
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
            auto now_ms = ms < 0 ? std::uint64_t{0} : static_cast<std::uint64_t>(ms);
            dns::detail::AddressAnswers<Full> answers;
            auto neg_err = [](dns::NegativeKind k) noexcept {
                return k == dns::NegativeKind::name_not_found ? dns::detail::ResolveError::name_not_found : dns::detail::ResolveError::no_data;
            };
#ifdef NEXUS_TEST_DNS_SHARED_ACCESS
            nexus_test_dns_shared_access(&session.dns->cache);
#endif
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
            if (!session.dns->coordinator || !session.dns->views || !session.dns->reader) return std::nullopt;
            auto view = session.dns->views->view(server_index, upstream, subnet, rule_scope);
            if (!view) return std::nullopt;
            auto v = transports ? transports->address_view(*view) : *view;
            for (unsigned i = 0; i < count; ++i) {
                auto hit = session.dns->cache.lookup_fresh(dns::CacheKey{v, std::string(name), types[i]}, now_ms, *session.dns->reader);
                if (!hit || !*hit) return std::nullopt;
                auto& entry = **hit;
                std::expected<dns::AddressAnswer, dns::detail::ResolveError> step = std::unexpected(dns::detail::ResolveError::state);
                if (entry.answer) step = std::move(*entry.answer);
                else if (entry.negative) step = std::unexpected(neg_err(*entry.negative));
                else return std::nullopt;
                if (auto added = answers.add(std::move(step)); !added) return std::unexpected(added.error());
            }
#else
            if (subnet.has_value()) return std::nullopt;
            auto base = (static_cast<std::uint64_t>(rule_scope) << 7) | (server_index + 1);
            auto v = transports ? transports->address_view(base) : base;
            for (unsigned i = 0; i < count; ++i) {
                dns::CacheKey key{v, std::string(name), types[i]};
                auto pos =
#if defined(NEXUS_TEST_DNS_SNAPSHOT) || defined(NEXUS_TEST_DNS_GROUP)
                    session.dns->reader ? session.dns->cache.lookup(key, now_ms, *session.dns->reader) : session.dns->cache.lookup(key, now_ms);
#else
                    session.dns->cache.lookup(key, now_ms);
#endif
                std::expected<dns::AddressAnswer, dns::detail::ResolveError> step = std::unexpected(dns::detail::ResolveError::state);
                if (pos && *pos) step = std::move(**pos);
                else {
                    auto neg =
#if defined(NEXUS_TEST_DNS_SNAPSHOT) || defined(NEXUS_TEST_DNS_GROUP)
                        session.dns->reader ? session.dns->cache.lookup_negative(key, now_ms, *session.dns->reader) : session.dns->cache.lookup_negative(key, now_ms);
#else
                        session.dns->cache.lookup_negative(key, now_ms);
#endif
                    if (!neg || !*neg) return std::nullopt;
                    step = std::unexpected(neg_err(**neg));
                }
                if (auto added = answers.add(std::move(step)); !added) return std::unexpected(added.error());
            }
#endif
            auto finished = answers.finish();
            if (!finished) return std::unexpected(finished.error());
            if constexpr (Full) return std::move(*finished);
            else return endpoints(*finished, port);
#endif
        }

        template<bool Full>
        auto query_server(Session& session, corosio::io_context& context, std::size_t server_index,
                          std::span<corosio::endpoint const> servers, std::string const& name, std::uint16_t port,
                          dns::detail::AddressStrategy family, Clock::time_point deadline,
                          void*& dns_operation, void (*&cancel_dns)(void*) noexcept,LocalSnapshotRef retained=nullptr,CachePolicy cache_policy={},
                          std::optional<dns::ClientSubnet> subnet={}, std::uint32_t rule_scope=0) -> capy::task<DnsValueResult<Full>> {
            if (Clock::now()>=deadline) co_return std::unexpected(dns::detail::ResolveError::timeout);
            if (session.closed) co_return std::unexpected(dns::detail::ResolveError::canceled);
            if (cancel_dns) co_return std::unexpected(dns::detail::ResolveError::state);
            if (auto cached = try_resolve_cached<Full>(session, server_index, servers, name, port, family, cache_policy, subnet, rule_scope))
                co_return std::move(*cached);
            auto const& server=session.dns->routing.servers[server_index];
            auto* transports=session.dns_transports();
            auto const& protection=transports ? transports->queries[server_index] : server.protection;
            if (!server.port) {
                co_return co_await resolve_local_value<Full>(session,context,name,port,family,deadline,dns_operation,cancel_dns,retained,cache_policy,subnet);
            }
            for (auto const& upstream : servers) {
                if (!valid_destination(upstream)) continue;
#ifdef NEXUS_TEST_DNS_SHARED_ACCESS
                nexus_test_dns_shared_access(&session.dns->cache);
#endif
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
                if (!session.dns->coordinator || !session.dns->views || !session.dns->reader)
                    co_return std::unexpected(dns::detail::ResolveError::state);
                auto view=session.dns->views->view(server_index,upstream,subnet,rule_scope);
                if (!view) co_return std::unexpected(view.error()==dns_hp_experiment::ViewRegistry::Error::limit ||
                    view.error()==dns_hp_experiment::ViewRegistry::Error::allocation ? dns::detail::ResolveError::limit : dns::detail::ResolveError::state);
                if (transports) *view=transports->address_view(*view);
                using Resolver=dns_hp_experiment::CoordinatorQuery;
                Resolver operation(*session.dns->coordinator,&*session.dns->reader,coordinated_strategy(family),server.tcp,
                    session.dns->routing.disable_cache,session.dns->routing.edns,session.dns->optimistic,cache_policy,subnet,protection);
#elif defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_GROUP)
                using Resolver=dns::detail::BasicDualAddressResolver<dns_hp_experiment::GroupBinding>;
#else
                using Resolver=dns::detail::DualAddressResolver;
#endif
#if !defined(NEXUS_DNS_SHARED) && !defined(NEXUS_TEST_DNS_COORDINATOR)
                Resolver operation(context,session.dns->cache,server.tcp,family,
                    session.dns->routing.disable_cache,session.dns->routing.edns,
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
                    static_cast<GroupRefresh*>(session.dns->refresh.get())
#else
                    nullptr
#endif
#if defined(NEXUS_TEST_DNS_SNAPSHOT) || defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_GROUP)
                    ,session.dns->reader ? &*session.dns->reader : nullptr
#else
                    ,nullptr
#endif
                    ,cache_policy,subnet,protection.get());
#endif
                struct Registration {
                    void*& operation; void (*&cancel)(void*) noexcept;
                    ~Registration() { cancel=nullptr; operation=nullptr;
#ifdef NEXUS_TEST_DNS_OWNER
                        nexus_test_dns_registration_destroy();
#endif
                    }
                } registration{dns_operation,cancel_dns};
                dns_operation=&operation;
                cancel_dns=[](void* pointer) noexcept { static_cast<Resolver*>(pointer)->cancel(); };
#ifdef NEXUS_TEST_DNS_LIFETIME
                nexus_test_dns_registered();
#endif
                auto base=(static_cast<std::uint64_t>(rule_scope)<<7)|(server_index+1);
                auto non_shared_view=transports ? transports->address_view(base) : base;
                auto resolved=co_await [&] {
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
                    if constexpr (Full) return operation.resolve_answer(upstream,*view,name,deadline);
                    else return operation.resolve_native(upstream,*view,name,deadline);
#else
                    if constexpr (Full) return operation.resolve_answer(upstream,non_shared_view,name,deadline);
                    else return operation.resolve(upstream,non_shared_view,name,deadline);
#endif
                }();
                if (session.closed) co_return std::unexpected(dns::detail::ResolveError::canceled);
                if (!resolved) { if (resolved.error()==dns::detail::ResolveError::transport) continue; co_return std::unexpected(resolved.error()); }
                if constexpr (Full) co_return std::move(*resolved); else co_return endpoints(*resolved,port);
            }
            co_return std::unexpected(dns::detail::ResolveError::transport);
        }
        template<bool Full>
        auto resolve_dns_value(Session& session, corosio::io_context& context, std::size_t selected,
                         std::string name, std::uint16_t port, dns::detail::AddressStrategy family, Clock::time_point deadline,
                         void*& dns_operation, void (*&cancel_dns)(void*) noexcept, bool const* canceled=nullptr,LocalSnapshotRef retained=nullptr,CachePolicy cache_policy={},
                         std::optional<dns::ClientSubnet> subnet={}, std::uint32_t rule_scope=0) -> capy::task<DnsValueResult<Full>> {
            auto const& routing=session.dns->routing;
            if (!routing.servers[selected].resolver) {
                if (canceled && *canceled) co_return std::unexpected(dns::detail::ResolveError::canceled);
                if (routing.servers[selected].port) {
                    auto ep = session.dns->endpoint(selected); std::span<corosio::endpoint const> one(&ep, 1);
                    if (!cancel_dns && Clock::now() < deadline)
                        if (auto cached = try_resolve_cached<Full>(session, selected, one, name, port, family, cache_policy, subnet, rule_scope))
                            co_return std::move(*cached);
                    co_return co_await query_server<Full>(session,context,selected,one,name,port,family,deadline,dns_operation,cancel_dns,retained,cache_policy,subnet,rule_scope);
                }
                co_return co_await query_server<Full>(session,context,selected,{},name,port,family,deadline,dns_operation,cancel_dns,retained,cache_policy,subnet,rule_scope);
            }
            std::vector<std::size_t> chain; auto current=selected;
            while (routing.servers[current].resolver) { chain.push_back(current); current=*routing.servers[current].resolver; }
            std::vector<corosio::endpoint> eps;
            if (routing.servers[current].port) eps.push_back(session.dns->endpoint(current));
            for (auto it=chain.rbegin();it!=chain.rend();++it) {
                if (canceled && *canceled) co_return std::unexpected(dns::detail::ResolveError::canceled);
                auto const& next=routing.servers[*it];
                auto resolved=co_await query_server<false>(session,context,current,eps,next.host,next.port,strategy(session),deadline,dns_operation,cancel_dns,retained);
                if (!resolved) co_return std::unexpected(resolved.error());
                eps=std::move(*resolved); current=*it;
            }
            if (canceled && *canceled) co_return std::unexpected(dns::detail::ResolveError::canceled);
            co_return co_await query_server<Full>(session,context,current,eps,name,port,family,deadline,dns_operation,cancel_dns,retained,cache_policy,subnet,rule_scope);
        }
    }

    namespace dns_detail {
        auto strategy(Session const& session) -> dns::detail::AddressStrategy {
            auto value = session.dns ? session.dns->routing.strategy : DnsStrategy::automatic;
            using F = dns::detail::AddressStrategy;
            return value == DnsStrategy::prefer_ipv6 ? F::prefer_ipv6 : value == DnsStrategy::ipv4_only ? F::ipv4_only :
                value == DnsStrategy::ipv6_only ? F::ipv6_only : F::prefer_ipv4;
        }
        auto endpoints(std::span<dns::Address const> addresses, std::uint16_t port) -> std::vector<corosio::endpoint> {
            std::vector<corosio::endpoint> result; result.reserve(addresses.size());
            for (auto const& address : addresses) {
                if (address.size == 4) {
                    corosio::ipv4_address::bytes_type bytes{}; std::copy_n(address.bytes.begin(), 4, bytes.begin());
                    result.emplace_back(corosio::ipv4_address(bytes), port);
                } else if (address.size == 16) result.emplace_back(corosio::ipv6_address(address.bytes), port);
            }
            return result;
        }
        auto query_server_endpoints(Session& s, corosio::io_context& ctx, std::size_t idx, std::span<corosio::endpoint const> sv,
            std::string const& name, std::uint16_t port, dns::detail::AddressStrategy fam, Clock::time_point dl,
            void*& op, void (*&can)(void*) noexcept, LocalSnapshotRef ret) -> capy::task<DnsResult> {
            return query_server<false>(s, ctx, idx, sv, name, port, fam, dl, op, can, ret);
        }
        auto resolve_dns_full(Session& s, corosio::io_context& ctx, std::size_t sel, std::string name, std::uint16_t port,
            dns::detail::AddressStrategy fam, Clock::time_point dl, void*& op, void (*&can)(void*) noexcept, bool const* cxl,
            LocalSnapshotRef ret, dns::detail::FamilyCachePolicy cp, std::optional<dns::ClientSubnet> sub, std::uint32_t sc)
            -> capy::task<std::expected<dns::AddressAnswer, dns::detail::ResolveError>> {
            return resolve_dns_value<true>(s, ctx, sel, std::move(name), port, fam, dl, op, can, cxl, ret, cp, sub, sc);
        }
    }
    auto Session::dns_rules() const noexcept -> std::span<policy::DnsRule const> {
        return (route_snapshot && route_snapshot->dns) ? route_snapshot->dns->rules : dns ? std::span<policy::DnsRule const>(dns->routing.rules) : std::span<policy::DnsRule const>{};
    }
    auto Session::dns_requirements() const noexcept -> policy::DnsContextRequirements {
        return (route_snapshot && route_snapshot->dns) ? route_snapshot->dns->context : dns ? dns->context : policy::DnsContextRequirements{};
    }

    static auto resolve_destination_policy(Session& session,corosio::io_context& context,std::string name,std::uint16_t port,
        Clock::time_point deadline,policy::DnsContext input,void*& operation,
        void (*&cancel)(void*) noexcept,bool const* canceled=nullptr,std::optional<std::size_t> view_final={},
        ResolveOverride ov={}) -> capy::task<DnsResult> {
        if (session.closed || (canceled && *canceled)) co_return std::unexpected(dns::detail::ResolveError::canceled);
        if (Clock::now()>=deadline) co_return std::unexpected(dns::detail::ResolveError::timeout);
        auto family=dns_detail::to_address_strategy(ov.strategy,strategy(session));
        if (!session.dns) co_return co_await resolve_local_value<false>(session,context,std::move(name),port,family,deadline,operation,cancel);
        auto types=dns::detail::address_types(family);
        auto count=dns::detail::address_type_count(family);
        session.fill_dns_context(input);
        auto const& routing=session.dns->routing;
        if (ov.server) {
            if (*ov.server>=routing.servers.size()) co_return std::unexpected(dns::detail::ResolveError::state);
            dns::detail::FamilyCachePolicy cache_policy{};
            if (ov.disable_cache) cache_policy={*ov.disable_cache,*ov.disable_cache};
            if (!cancel && !routing.servers[*ov.server].resolver && routing.servers[*ov.server].port) {
                auto ep = session.dns->endpoint(*ov.server);
                if (auto cached = try_resolve_cached<false>(session, *ov.server, std::span(&ep, 1), name, port, family, cache_policy, ov.client_subnet, 0))
                    co_return std::move(*cached);
            }
            co_return co_await resolve_dns_value<false>(session,context,*ov.server,std::move(name),port,family,deadline,
                operation,cancel,canceled,nullptr,cache_policy,ov.client_subnet);
        }
#ifdef NEXUS_DNS_RESPONSE
        auto has_response=session.route_snapshot && session.route_snapshot->dns ?
            session.route_snapshot->dns->has_response_program : session.dns->has_response_program;
        if (has_response && !ov.strategy && !ov.disable_cache && !ov.rewrite_ttl && !ov.client_subnet) {
            for (unsigned i=0;i<count;++i) if (policy::dns_preflight_reject(session.dns_rules(),name,types[i],input))
                co_return std::unexpected(dns::detail::ResolveError::policy_rejected);
            co_return co_await dns_detail::resolve_response_program(session,context,name,port,family,deadline,input,operation,cancel,canceled,view_final);
        }
#endif
        auto select=[&](std::uint16_t type) {
            return policy::select_question_dns_action(session.dns_rules(),name,type,view_final.value_or(routing.final),routing.disable_cache,input);
        };
        auto first=select(types[0]);
        auto second=count==2 ? select(types[1]) : first;
        if (first.action==policy::DnsAction::reject || second.action==policy::DnsAction::reject)
            co_return std::unexpected(dns::detail::ResolveError::policy_rejected);
        if (!ov.strategy && first.strategy) {
            if (count==1 || first.strategy==second.strategy) {
                auto reordered=dns_detail::to_address_strategy(first.strategy,family);
                if (reordered!=family) {
                    family=reordered;
                    auto old_first=types[0];
                    types=dns::detail::address_types(family);
                    count=dns::detail::address_type_count(family);
                    if (types[0]!=old_first) std::swap(first,second);
                    if (count==1) second=first;
                }
            }
        }
        auto want=[&](std::uint16_t qt,policy::DnsDecision const& dec) {
            auto st=ov.strategy ? ov.strategy : dec.strategy;
            if (!st) return true;
            return !((*st==rules::DnsRuleStrategy::ipv4_only && qt==28) ||
                     (*st==rules::DnsRuleStrategy::ipv6_only && qt==1));
        };
        if (count==2) {
            bool w0=want(types[0],first), w1=want(types[1],second);
            if (!w0 && !w1) co_return std::unexpected(dns::detail::ResolveError::no_data);
            if (!w0) {
                types[0]=types[1]; first=second; count=1;
                family=types[0]==1 ? dns::detail::AddressStrategy::ipv4_only : dns::detail::AddressStrategy::ipv6_only;
            } else if (!w1) {
                count=1; second=first;
                family=types[0]==1 ? dns::detail::AddressStrategy::ipv4_only : dns::detail::AddressStrategy::ipv6_only;
            }
        } else if (!want(types[0],first)) {
            co_return std::unexpected(dns::detail::ResolveError::no_data);
        }
        // Keep local search, hosts and ordinary same-server dual lookups as
        // one operation. Different routes must expose their canonical names
        // before their independently resolved families may be combined.
        dns::detail::FamilyCachePolicy cache_policy{};
        cache_policy[types[0]==1 ? 0 : 1]=ov.disable_cache.value_or(first.disable_cache);
        if (count==2) cache_policy[types[1]==1 ? 0 : 1]=ov.disable_cache.value_or(second.disable_cache);
        auto scope0=routing.independent_cache && first.rule ? static_cast<std::uint32_t>(*first.rule+1) : 0u;
        auto scope1=routing.independent_cache && second.rule ? static_cast<std::uint32_t>(*second.rule+1) : 0u;
        if (count==1 || (first.server==second.server && scope0==scope1)) {
            if (!cancel && !routing.servers[first.server].resolver && routing.servers[first.server].port) {
                auto ep = session.dns->endpoint(first.server);
                if (auto cached = try_resolve_cached<false>(session, first.server, std::span(&ep, 1), name, port, family, cache_policy, ov.client_subnet, scope0))
                    co_return std::move(*cached);
            }
            co_return co_await resolve_dns_value<false>(session,context,first.server,std::move(name),port,family,deadline,
                operation,cancel,canceled,nullptr,cache_policy,ov.client_subnet,scope0);
        }
        auto uses_local=[&](std::size_t server) {
            auto const& routing=session.dns->routing;
            while (routing.servers[server].resolver) server=*routing.servers[server].resolver;
            return !routing.servers[server].port;
        };
        // Capture before either question suspends, including a local
        // dependency needed only by the second question's bootstrap chain.
        std::shared_ptr<dns::LocalSnapshot const> snapshot;
        if (uses_local(first.server) || uses_local(second.server)) {
            if (!session.local_dns) co_return std::unexpected(dns::detail::ResolveError::state);
            snapshot=session.local_dns->source.acquire();
            if (!snapshot) co_return std::unexpected(dns::detail::ResolveError::state);
        }
        dns::detail::AddressAnswers<false> answers;
        for (unsigned i=0;i<count;++i) {
            auto selected=i ? second.server : first.server;
            auto sc=i ? scope1 : scope0;
            auto one=types[i]==1 ? dns::detail::AddressStrategy::ipv4_only : dns::detail::AddressStrategy::ipv6_only;
            auto result=co_await resolve_dns_value<true>(session,context,selected,name,port,one,deadline,
                operation,cancel,canceled,snapshot ? &snapshot : nullptr,cache_policy,ov.client_subnet,sc);
            auto added=answers.add(std::move(result));
            if (!added) co_return std::unexpected(added.error());
        }
        auto result=answers.finish();
        if (!result) co_return std::unexpected(result.error());
        co_return endpoints(*result,port);
    }

    auto resolve_destination(Session& session,corosio::io_context& context,std::string name,std::uint16_t port,
        Clock::time_point deadline,policy::DnsContext input,ResolveOverride ov) -> capy::task<DnsResult> {
        return resolve_destination_policy(session,context,std::move(name),port,deadline,input,session.dns_operation,session.cancel_dns,nullptr,{},ov);
    }
    auto resolve_local(Session& session, corosio::io_context& context, std::string name, std::uint16_t port,
                       Clock::time_point deadline) -> capy::task<std::optional<std::vector<corosio::endpoint>>> {
        auto r=co_await resolve_local_impl(session,context,std::move(name),port,dns::detail::AddressStrategy::prefer_ipv4,deadline);
        co_return r ? std::optional(std::move(*r)) : std::nullopt;
    }
    auto resolve_local_owned(Session& session, corosio::io_context& context, DnsSlot& slot, std::string name,
                             std::uint16_t port, Clock::time_point deadline) -> capy::task<std::optional<std::vector<corosio::endpoint>>> {
        if (slot.canceled) co_return std::nullopt;
        auto r=co_await resolve_local_value<false>(session,context,std::move(name),port,dns::detail::AddressStrategy::prefer_ipv4,deadline,slot.operation,slot.cancel_operation);
        co_return r ? std::optional(std::move(*r)) : std::nullopt;
    }
    auto resolve_bootstrap_impl(Session& session, corosio::io_context& context, std::size_t selected,
                           std::string name, std::uint16_t port, Clock::time_point deadline,
                           void*& dns_operation, void (*&cancel_dns)(void*) noexcept, bool const* canceled=nullptr) -> capy::task<std::optional<std::vector<corosio::endpoint>>> {
        if (!session.dns || session.closed || (canceled && *canceled) || selected>=session.dns->routing.resolver_count()) co_return std::nullopt;
        auto const& routing=session.dns->routing;
        auto resolved=co_await (selected<routing.servers.size() ?
            resolve_dns_value<false>(session,context,selected,std::move(name),port,strategy(session),deadline,dns_operation,cancel_dns,canceled) :
            resolve_destination_policy(session,context,std::move(name),port,deadline,{},dns_operation,cancel_dns,canceled,routing.view_finals[selected-routing.servers.size()]));
        co_return (resolved && !session.closed && (!canceled || !*canceled)) ? std::optional(std::move(*resolved)) : std::nullopt;
    }
    auto resolve_bootstrap(Session& s, corosio::io_context& c, std::size_t sel, std::string n, std::uint16_t p, Clock::time_point d)
        -> capy::task<std::optional<std::vector<corosio::endpoint>>> { co_return co_await resolve_bootstrap_impl(s,c,sel,std::move(n),p,d,s.dns_operation,s.cancel_dns); }
    auto resolve_bootstrap_owned(Session& s, corosio::io_context& c, DnsSlot& sl, std::size_t sel, std::string n, std::uint16_t p, Clock::time_point d)
        -> capy::task<std::optional<std::vector<corosio::endpoint>>> { co_return co_await resolve_bootstrap_impl(s,c,sel,std::move(n),p,d,sl.operation,sl.cancel_operation,&sl.canceled); }
#ifdef NEXUS_DNS_RESPONSE
    auto resolve_destination_race(Session& session,corosio::io_context& context,std::string name,std::uint16_t port,
        Clock::time_point deadline,policy::DnsContext input,std::span<dns::ResponseRaceMode const> modes) -> capy::task<DnsResult> {
        if(session.closed)co_return std::unexpected(dns::detail::ResolveError::canceled);
        if(!session.dns || !port)co_return std::unexpected(dns::detail::ResolveError::state);
        co_return co_await dns_detail::resolve_response_program(session,context,name,port,strategy(session),deadline,input,session.dns_operation,session.cancel_dns,nullptr,{},modes);
    }
#endif
#ifdef NEXUS_ENABLE_SOCKS_UDP
    auto resolve_udp_domain(Session& session, corosio::io_context& context, std::string name,
                            std::uint16_t port, Clock::time_point deadline,net::UdpEndpoint const* source) -> capy::task<std::optional<std::vector<corosio::endpoint>>> {
        if (session.closed) co_return std::nullopt;
        // Native SOCKS UDP supplies its admitted datagram peer explicitly; stream-carried UDP uses the immediate stream peer.
        auto stream_source=!source ? source_endpoint(session,session.dns_requirements().source) : std::nullopt;
        if (stream_source) source=&*stream_source;
        policy::DnsContext input{.network=rules::Network::udp};
        if (source) { input.source_port=source->port; input.source_ip_bytes=std::span(source->address).first(source->family==4 ? 4 : 16); }
        auto resolved=co_await resolve_destination(session,context,std::move(name),port,deadline,input);
        if (!resolved || resolved->empty() || resolved->size()>64 || session.closed || Clock::now()>=deadline) co_return std::nullopt;
        co_return std::move(*resolved);
    }
#endif

}
