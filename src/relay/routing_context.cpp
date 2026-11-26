module;
#include <boost/capy/task.hpp>
#include <boost/corosio/delay.hpp>

module relay;
import std;
import dns.tls_query;
import dns.https_query;
import relay.dns_state;
import rules.rule_input;
import platform.network_state;
import dns.local_config;
import capy;
import corosio;
namespace relay {
    namespace {
        class RoutingContext final : public capy::execution_context::service {
            auto shutdown() noexcept -> void override { server = nullptr; routing_servers.clear(); active_servers = 0; }
        public:
            Server* server = nullptr;
            std::size_t active_servers = 0;
            std::vector<Server*> routing_servers;
            explicit RoutingContext(capy::execution_context&) noexcept {}
        };

        auto input_format(RuleFormat fmt) noexcept -> std::optional<rules::InputFormat> {
            using F = RuleFormat;
            using I = rules::InputFormat;
            switch (fmt) {
            case F::kdl: return I::kdl;
            case F::beve: return I::beve;
            case F::srs: return I::srs;
            case F::nxmm: return I::nxmm;
            case F::json: return I::json;
            case F::domain_list: return I::domain_list;
            case F::ipcidr_list: return I::ipcidr_list;
            case F::classical: return I::classical;
            case F::adguard: return I::adguard;
            }
            return {};
        }

        auto compile_indexed_routes(std::span<IndexedRouteRule const> input,std::size_t fallback,
            std::size_t outbound_count,std::optional<std::string_view> inbound,
            std::vector<std::size_t>* referenced=nullptr)
            -> std::expected<rules::RouteMatcher,std::string> {
            if (fallback>=outbound_count || input.size()>256) return std::unexpected("invalid route action or count");
            std::vector<rules::RouteRule> route_rules;
            std::size_t predicate_count=0;
            for (std::size_t index=0;index<input.size();++index) {
                auto const& rule=input[index];
                auto format=input_format(rule.format);
                if (rule.outbound>=outbound_count || !format)
                    return std::unexpected("invalid route action or format");
                if (rule.format==RuleFormat::nxmm) {
                    std::shared_ptr<rules::MmapMatcher const> mmap = rule.mmap;
                    if (!mmap) {
                        auto opened = rules::MmapMatcher::open_bytes(std::string(rule.data));
                        if (!opened) return std::unexpected(std::move(opened.error()));
                        mmap = std::make_shared<rules::MmapMatcher const>(std::move(*opened));
                    }
                    auto n = mmap->exact_count() + mmap->suffix_count() + mmap->v4_count() + mmap->v6_count();
                    if (n > rules::max_rules - predicate_count) return std::unexpected("too many route predicates");
                    predicate_count += n;
                    if (mmap->has_domain() || mmap->has_ip() || mmap->tail_beve_bytes() > 0) {
                        route_rules.push_back({{}, rule.outbound, index, std::move(mmap), rule.ip_cidr_match_source});
                        if (referenced) referenced->push_back(rule.outbound);
                    }
                    continue;
                }
                auto parsed=rules::parse_rule_input(rule.data,*format,rule.ip_cidr_match_source);
                if (!parsed) return std::unexpected(parsed.error().message);
                if (parsed->rules.size()>rules::max_rules-predicate_count) return std::unexpected("too many route predicates");
                predicate_count+=parsed->rules.size();
                if (!parsed->rules.empty()) {
                    route_rules.push_back({std::move(*parsed),rule.outbound,index});
                    if (referenced) referenced->push_back(rule.outbound);
                }
            }
            auto matcher=rules::RouteMatcher::compile(route_rules,fallback,outbound_count,
                rules::SourceMetadata::provided,inbound,rules::AuthMetadata::provided);
            if (!matcher) return std::unexpected(matcher.error().message);
            return std::move(*matcher);
        }

        auto compile_ordered_rules(OrderedRuleInput input,std::size_t fallback,std::size_t outbound_count)
            -> std::expected<OrderedTcpPolicy,std::string> {
            if(fallback>=outbound_count || fallback==1 || !input.sniff_timeout_ms || input.sniff_timeout_ms>10000)
                return std::unexpected("invalid ordered TCP fallback or sniff timeout");
            auto program=rules::RouteProgram::compile(input.rules,outbound_count);
            if(!program)return std::unexpected(program.error().message);
            return OrderedTcpPolicy{std::move(*program),fallback,std::chrono::milliseconds(input.sniff_timeout_ms),
                input.skip_unknown ? sniff::UnknownRoutePolicy::skip : sniff::UnknownRoutePolicy::pause,input.udp};
        }
    }

    auto Server::set_indexed_routes(std::span<IndexedRouteRule const> input, std::size_t fallback,
                                    std::optional<std::string_view> inbound) -> std::expected<void, std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before changing rules");
        auto matcher=compile_indexed_routes(input,fallback,2+outbounds.size(),inbound);
        if(!matcher)return std::unexpected(std::move(matcher.error()));
        if (runtime_mode) matcher->set_runtime_mode(runtime_mode);
        policy=std::move(*matcher);
        ordered_tcp.reset();
        return {};
    }

    auto Server::set_ordered_tcp(std::span<rules::ProgramRule const> entries,std::size_t fallback,
        std::uint32_t timeout_ms,bool skip_unknown,bool udp) -> std::expected<void,std::string> {
        if(running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before changing rules");
        auto candidate=compile_ordered_rules({entries,timeout_ms,skip_unknown,udp},fallback,2+outbounds.size());
        if(!candidate)return std::unexpected(std::move(candidate.error()));
        ordered_tcp=std::make_shared<OrderedTcpPolicy>(std::move(*candidate));
        return {};
    }

    auto compile_routes(std::span<IndexedRouteRule const> input,std::size_t fallback,
        std::size_t outbound_count,std::optional<std::string_view> inbound,std::optional<OrderedRuleInput> ordered,
        std::shared_ptr<rules::OutboundDistribution const> distribution,
        std::span<std::size_t const> extra_outbounds)
        -> std::expected<RouteSnapshot,std::string> {
        auto physical_count=outbound_count;
        if (distribution) outbound_count+=distribution->groups.size();
        std::vector<std::size_t> referenced{fallback};
        referenced.insert(referenced.end(),extra_outbounds.begin(),extra_outbounds.end());
        auto matcher=compile_indexed_routes(input,fallback,outbound_count,inbound,&referenced);
        if(!matcher)return std::unexpected(std::move(matcher.error()));
        matcher->set_distribution(distribution);
        RouteSnapshot result{std::move(*matcher),std::nullopt};
        if(ordered) {
            auto program=compile_ordered_rules(*ordered,fallback,outbound_count);
            if(!program)return std::unexpected(std::move(program.error()));
            result.ordered.emplace(std::move(*program));
            for (auto const& rule : ordered->rules)
                if (rule.action.kind==rules::ProgramActionKind::route) referenced.push_back(rule.action.outbound);
        }
        if (physical_count<=258) {
            std::vector<bool> seen(outbound_count);
            std::bitset<256> mask{};
            while (!referenced.empty()) {
                auto index=referenced.back();
                referenced.pop_back();
                if (index>=outbound_count || seen[index]) continue;
                seen[index]=true;
                if (index<physical_count) {
                    if (index>=2) mask.set(index-2);
                } else {
                    auto const& members=distribution->groups[index-physical_count];
                    referenced.insert(referenced.end(),members.begin(),members.end());
                }
            }
            result.tunnel_references=mask;
        }
        return result;
    }

    auto Server::compile_route_snapshot(std::span<IndexedRouteRule const> input,std::size_t fallback,
        std::optional<std::string_view> inbound,std::optional<OrderedRuleInput> ordered,
        std::shared_ptr<rules::OutboundDistribution const> distribution) const
        -> std::expected<RouteSnapshot,std::string> {
        auto result=compile_routes(input,fallback,2+outbounds.size(),inbound,ordered,std::move(distribution));
        if (result && runtime_mode) result->matcher.set_runtime_mode(runtime_mode);
        return result;
    }

    auto Server::set_runtime_mode(std::shared_ptr<rules::RuntimeRouteMode const> mode) noexcept -> void {
        runtime_mode=std::move(mode);
        policy.set_runtime_mode(runtime_mode);
        for (auto& worker : workers) worker->set_runtime_mode(runtime_mode);
    }

    auto Server::set_route_snapshots(std::shared_ptr<RouteSnapshots> source,std::size_t index) -> bool {
        if(running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())return false;
        route_snapshots=std::move(source);
        route_snapshot_index=index;
        return true;
    }


    auto Server::set_session_limit(std::size_t maximum) -> bool {
        if (!maximum || running || (listener && listener->is_open()) || !workers.empty() ||
            traffic || quota.used()!=0) return false;
        quota=SessionQuota(maximum);
        return true;
    }

    auto Session::admit_principal(std::string_view user,PrincipalResource resource) noexcept -> bool {
        auth_user=user;
        if (!principal_policy) return true;
        principal=principal_policy->find(user);
        if (!principal) return true;
        principal_lease=principal->acquire(resource);
        return principal_lease.has_value();
    }

    auto Session::admit_principal_child(Session const& parent) noexcept -> bool {
        auth_user=parent.auth_user;
        principal=parent.principal;
        if (!principal) return true;
        principal_lease=principal->acquire(PrincipalResource::stream);
        return principal_lease.has_value();
    }

    auto Session::reserve_principal_stream(bool upstream,std::size_t size)
        -> capy::task<std::optional<PrincipalBytes::Reservation>> {
        using namespace std::chrono_literals;
        auto const& bytes=principal->bytes();
        while (!closed) {
            auto now=Clock::now();
            auto credit=bytes.reserve(upstream,size,false,now);
            if (credit) co_return std::move(*credit);
            auto reason=credit.error().reason;
            if (reason!=PrincipalBytes::Denial::rate && reason!=PrincipalBytes::Denial::pending) co_return std::nullopt;
            auto wait=std::clamp(credit.error().retry-now,Clock::duration(1ms),Clock::duration(100ms));
            auto [error]=co_await io::delay(wait);
            if (error) break;
        }
        co_return std::nullopt;
    }

    auto Session::reserve_principal_datagram(bool upstream,std::size_t size) -> std::optional<PrincipalBytes::Reservation> {
        if (!principal) return std::optional<PrincipalBytes::Reservation>(std::in_place);
        return principal->bytes().reserve_datagram(upstream,size,Clock::now());
    }

    auto Server::set_principal_policy(std::shared_ptr<PrincipalPolicy const> snapshot) noexcept -> bool {
        if (running || !sessions.empty() || !workers.empty()) return false;
        principals=std::move(snapshot);
        return true;
    }

    auto Server::current_route_snapshot() const noexcept -> std::shared_ptr<RouteSnapshot const> {
        if (!route_snapshots) return {};
        auto const ver = route_snapshots->version(std::memory_order_acquire);
        if (ver == 0) return {};
        if (cached_route_version == ver) return cached_route_snapshot;
        auto gen = route_snapshots->load(std::memory_order_acquire);
        cached_route_version = ver;
        if (!gen || route_snapshot_index >= gen->size()) { cached_route_snapshot.reset(); return {}; }
        auto const* snap = &(*gen)[route_snapshot_index];
        return cached_route_snapshot = std::shared_ptr<RouteSnapshot const>(std::move(gen), snap);
    }

    auto ingress_metadata(platform::network::Monitor const* monitor,net::UdpEndpoint const& source,
        std::optional<std::uint8_t> dscp,std::uint32_t index) noexcept -> rules::IngressMetadata {
        rules::IngressMetadata metadata{.dscp=dscp};
        if (auto snapshot=monitor ? monitor->get() : nullptr) {
            bool ipv6=source.family==6;
            metadata.source_mac=snapshot->neighbor_mac(std::span(source.address).first(ipv6 ? 16 : 4),index);
            metadata.gateway_mac=snapshot->gateway_mac(ipv6);
        }
        return metadata;
    }

    auto Server::set_network_monitor(std::shared_ptr<platform::network::Monitor const> monitor) noexcept -> void {
        network_monitor=std::move(monitor);
    }

    auto Server::transparent_metadata(net::UdpEndpoint const& source,std::optional<std::uint8_t> dscp,
        std::uint32_t index) const noexcept -> rules::IngressMetadata {
        return ingress_metadata(network_monitor.get(),source,dscp,index);
    }

    auto Server::attach_session(Session& session,SessionQuota::Lease&& lease,std::shared_ptr<RouteSnapshot const> snapshot)->void {
        session.network_monitor=network_monitor.get(); session.populate_network_metadata();
        session.find_process=find_process_enabled; session.group_hooks=group_hooks.get();
        session.dns=dns.get(); session.local_dns=local_dns.get(); session.reverse_cache=reverse_cache.get();
#ifdef NEXUS_ENABLE_FAKEIP
        session.fakeip=fakeip.get(); session.fakeip_view=fakeip_view;
#endif
        session.quota=std::move(lease); session.principal_policy=principals.get(); session.ss_dynamic_users=ss_dynamic_users;
        session.splice_pipes=splice_pipes ? &*splice_pipes : nullptr; session.direct_buffers=&direct_buffers;
        session.splice_pipe_pool=splice_pipes ? &splice_pipe_pool : nullptr;
        session.splice_max_idle_pipes=splice_max_idle_pipes;
        session.traffic.registry_=traffic.get();
        session.route_snapshot=snapshot ? std::move(snapshot) : current_route_snapshot(); session.runtime_mode=runtime_mode.get();
        if(session.route_snapshot) {
            auto const& snap=*session.route_snapshot;
#ifdef NEXUS_ENABLE_FAKEIP
            if (snap.dns && snap.dns->view) session.fakeip_view=*snap.dns->view;
#endif
            if (snap.dns && snap.dns->view) session.reverse_view=*snap.dns->view;
            session.inbound=snap.matcher.inbound(); session.ordered_tcp=snap.ordered ? &*snap.ordered : nullptr;
        } else { session.inbound=policy.inbound(); session.ordered_tcp=ordered_tcp.get(); }
        session.started=session.touched=Clock::now(); session.handshake_deadline=session.started+std::chrono::seconds(10);
        session.direct_connect_timeout_ms=direct_connect_timeout_ms;
        session.direct_tcp_options=direct_tcp_options.configured() ? &direct_tcp_options : nullptr;
        session.tunnel_factories=borrowed_outbounds ? borrowed_outbounds : &outbounds;
        sessions.push_back(&session); session.registry_index=sessions.size()-1; session.registry=&sessions;
    }
    auto register_context_server(corosio::io_context& io, Server* srv, bool has_proxy_dns) -> void {
        auto& rc = io.use_service<RoutingContext>();
        ++rc.active_servers;
        if (has_proxy_dns) { rc.routing_servers.push_back(srv); rc.server = srv; }
    }
    auto unregister_context_server(corosio::io_context& io, Server* srv) noexcept -> std::size_t {
        auto* rc = io.find_service<RoutingContext>();
        if (!rc) return 0;
        std::erase(rc->routing_servers, srv);
        if (rc->server == srv) rc->server = rc->routing_servers.empty() ? nullptr : rc->routing_servers.back();
        return rc->active_servers > 0 ? --rc->active_servers : 0;
    }
    auto Server::from_context(corosio::io_context& io) noexcept -> Server* {
        auto* context=io.find_service<RoutingContext>();
        return context && context->server && context->server->running ? context->server : nullptr;
    }

    auto Server::activate_context()->std::expected<void,std::error_code> {
        if(running)return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_GROUP)
        if (this->dns_routing && !this->dns) {
            if (!dns_group || !dns_group->supports_binding(dns_group_index,dns_reader_base,1))
                return std::unexpected(std::make_error_code(std::errc::invalid_argument));
            this->dns=std::make_unique<DnsState>(*this->dns_routing,*dns_group,dns_group_index,dns_reader_base);
        }
#else
        if (this->dns_routing && !this->dns) this->dns=std::make_unique<DnsState>(*this->dns_routing);
#endif
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
        if (dns && dns_refresh_budget && !dns->refresh)
            dns->refresh.reset(make_group_refresh(context,dns->cache,*dns_refresh_budget));
#endif
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
        if (dns && !dns->coordinator) {
            if (!dns_coordinator || !dns_view_registry || !dns_view_registry->sealed() ||
                dns_profiles.size()!=dns->routing.servers.size())
                return std::unexpected(std::make_error_code(std::errc::invalid_argument));
            dns->views.emplace(*dns_view_registry,dns_profiles);
#ifdef NEXUS_DNS_SHARED
            if (!dns_local_registry) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
            dns->local_views.emplace(*dns_local_registry);
            // Foreground callers use a 10 s deadline; the shared I/O must not
            // terminate a joined request at the experiment's 5 s default.
            dns->coordinator.emplace(context,dns->cache,*dns_coordinator,std::chrono::seconds(30));
#ifdef NEXUS_DNS_RESPONSE
            if (dns->has_response_program) {
                if (!dns_response_cache) return std::unexpected(std::make_error_code(std::errc::invalid_argument));
                dns->response_coordinator.emplace(context,*dns_response_cache,*dns_coordinator,std::chrono::seconds(30));
            }
#endif
#else
            dns->coordinator.emplace(context,dns->cache,*dns_coordinator);
#endif
            dns->optimistic=dns_optimistic;
        }
#endif
        this->local_dns=std::make_unique<LocalDnsState>();
        dns::resume_tls_queries(context);
        dns::resume_https_queries(context);
        if(!start_outbound_contexts())return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        register_context_server(context, this, (dns_routing && std::ranges::any_of(dns_routing->servers,&DnsServer::proxy_detour)) || route_snapshots!=nullptr);
        context_registered=true;
        running=true;return {};
    }
    auto Server::prepare_routing(unsigned count,bool child_workers)->std::expected<void,std::error_code> {
        auto& state=*this;
        if(running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())return std::unexpected(std::make_error_code(std::errc::operation_in_progress));
        if(!count)return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        { std::lock_guard lock(state.failure_mutex); state.failure_state.reset(); }
#ifdef NEXUS_DNS_SHARED
        // A standalone restart may change the number of workers. Retire the
        // previous, fully drained generation before registering fresh readers.
        if (state.owned_dns_generation) {
            state.dns.reset(); state.dns_group=nullptr; state.dns_coordinator=nullptr;
            state.dns_view_registry=nullptr; state.dns_local_registry=nullptr; state.dns_profiles.clear();
#ifdef NEXUS_DNS_RESPONSE
            state.dns_response_cache=nullptr;
#endif
            state.owned_dns_generation.reset();
        }
        if (!state.dns_group) {
            try {
                auto seconds=state.dns_routing ? state.dns_routing->optimistic_cache_seconds : 0;
                auto generation=std::make_unique<SharedDnsGeneration>(1,count,seconds);
                auto bound=state.bind_shared_dns(*generation,0,0);
                if (!bound) return std::unexpected(bound.error());
                generation->seal(); state.owned_dns_generation=std::move(generation);
            } catch (std::bad_alloc const&) { return std::unexpected(std::make_error_code(std::errc::not_enough_memory)); } catch (std::out_of_range const&) { return std::unexpected(std::make_error_code(std::errc::invalid_argument)); }
        }
#endif
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_GROUP)
#ifdef NEXUS_DNS_SHARED
        if (true) {
            DnsRouting local{{DnsServer{}},{},0};
            auto const& routing=state.dns_routing ? *state.dns_routing : local;
#else
        if (state.dns_routing) {
            auto const& routing=*state.dns_routing;
#endif
            if (!state.dns_group || !state.dns_group->supports_binding(state.dns_group_index,state.dns_reader_base,count))
                return std::unexpected(std::make_error_code(std::errc::invalid_argument));
            // The previous stopped instance may still own this reader. Release
            // it before constructing the replacement in the same slot.
            state.dns.reset();
            state.dns=std::make_unique<DnsState>(routing,*state.dns_group,state.dns_group_index,
                count==1 && !child_workers ? std::optional<std::size_t>{state.dns_reader_base} : std::nullopt);
        }
#endif
        stopping=false;failed=false;return {};
    }
    auto Server::inherit_routing(Server const& parent,std::size_t index,std::size_t count,
                                 std::optional<std::uint32_t> direct_mark)->void {
        if(running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())throw std::logic_error("stop before inheriting routing");
                this->network_monitor=parent.network_monitor;
                this->find_process_enabled=parent.find_process_enabled;
                this->group_hooks=parent.group_hooks;
                this->policy=parent.policy;
                this->ordered_tcp=parent.ordered_tcp;
                this->route_snapshots=parent.route_snapshots;
                this->route_snapshot_index=parent.route_snapshot_index;
                this->runtime_mode=parent.runtime_mode;
                this->policy.set_runtime_mode(this->runtime_mode);
                this->credentials=parent.credentials;
                this->fixed_tcp_target=parent.fixed_tcp_target;
                this->fixed_unix_target=parent.fixed_unix_target;
                this->udp_advertise=parent.udp_advertise;
                this->principals=parent.principals;
                this->memory_shed=parent.memory_shed;
                this->ss_dynamic_users=parent.ss_dynamic_users;
                this->direct_connect_timeout_ms=parent.direct_connect_timeout_ms;
                this->direct_tcp_options=parent.direct_tcp_options;
                this->listen_options=parent.listen_options; this->detour_target=parent.detour_target; this->detour_enabled=parent.detour_enabled;
#ifdef NEXUS_TPROXY_UDP
                this->transparent_datagrams=parent.transparent_datagrams;
#endif
                if (direct_mark) this->direct_tcp_options.binding.routing_mark=direct_mark;
                this->dns_routing=parent.dns_routing;
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_GROUP)
                if (parent.dns) this->dns=std::make_unique<DnsState>(parent.dns->routing,*parent.dns_group,
                                                                      parent.dns_group_index,parent.dns_reader_base+index);
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
                this->dns_refresh_budget=parent.dns_refresh_budget;
#endif
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
                this->dns_coordinator=parent.dns_coordinator;
                this->dns_view_registry=parent.dns_view_registry;
#ifdef NEXUS_DNS_SHARED
#ifdef NEXUS_DNS_RESPONSE
                this->dns_response_cache=parent.dns_response_cache;
#endif
                this->dns_local_registry=parent.dns_local_registry;
#endif
                this->dns_profiles=parent.dns_profiles;
                this->dns_optimistic=parent.dns_optimistic;
#endif
#else
                if (parent.dns) this->dns=std::make_unique<DnsState>(*parent.dns_routing,&parent.dns->cache);
#endif
#ifdef NEXUS_ENABLE_FAKEIP
                this->fakeip=parent.fakeip;
                this->fakeip_view=parent.fakeip_view;
#endif
                this->reverse_cache=parent.reverse_cache;
                this->borrowed_outbounds=&parent.outbounds;
#ifdef NEXUS_ENABLE_SNELL
                this->borrowed_snell_inbound=&parent.snell_inbound;
#endif
#ifdef NEXUS_ENABLE_ANYTLS
                this->borrowed_anytls_inbound=&parent.anytls_inbound;
#endif
#ifdef NEXUS_ENABLE_SHADOWTLS
                this->borrowed_shadowtls_inbound=&parent.shadowtls_inbound;
#endif
#ifdef NEXUS_ENABLE_TROJAN
                this->borrowed_trojan_inbound=&parent.trojan_inbound;
#endif
#ifdef NEXUS_ENABLE_VLESS
                this->borrowed_vless_inbound=&parent.vless_inbound;
#endif
#ifdef NEXUS_ENABLE_SS2022
                this->borrowed_shadowsocks_inbound=&parent.shadowsocks_inbound;
#endif
#ifdef NEXUS_ENABLE_NAIVE
                this->borrowed_naive_inbound=&parent.naive_inbound;
                this->borrowed_http_modern_inbound=&parent.http_modern_inbound;
                this->naive_tcp_enabled=parent.naive_tcp_enabled;
                this->http_modern_tcp_enabled=parent.http_modern_tcp_enabled;
#endif
                this->quota=parent.quota;
                this->splice_pipes=parent.splice_pipes;
                this->traffic_slot_limit=parent.traffic_slot_limit;
                this->traffic=(parent.traffic && count>1 && parent.traffic_slot_limit>0 && parent.traffic_slot_limit<=4096)
                    ? std::make_shared<TrafficRegistry>(parent.traffic_slot_limit) : parent.traffic;
                this->cached_route_version=0;
                this->cached_route_snapshot.reset();
    }
}
