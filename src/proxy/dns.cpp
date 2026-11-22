module proxy;
import std;
import proxy.dns_state;
import dns.corosio_local;
import dns.response_program;
import dns.address_race_program;
import dns.response_race_walk;
import dns.response_query;
import dns.local_response;
import dns.predefined;
import dns.shared_coordinator;
import proxy.dns_backend;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
#ifdef NEXUS_TEST_DNS_LIFETIME
extern "C" void nexus_test_dns_registered();
#endif
#ifdef NEXUS_TEST_DNS_OWNER
extern "C" void nexus_test_dns_registration_destroy();
#endif
#ifdef NEXUS_TEST_DNS_SHARED_ACCESS
extern "C" void nexus_test_dns_shared_access(void const*) noexcept;
#endif
namespace proxy {
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
        auto strategy(Session const& session) -> dns::detail::AddressStrategy {
            auto value=session.dns ? session.dns->routing.strategy : DnsStrategy::automatic;
            using Family=dns::detail::AddressStrategy;
            if (value==DnsStrategy::prefer_ipv6) return Family::prefer_ipv6;
            if (value==DnsStrategy::ipv4_only) return Family::ipv4_only;
            if (value==DnsStrategy::ipv6_only) return Family::ipv6_only;
            return Family::prefer_ipv4;
        }
        using CachePolicy=std::optional<dns::detail::FamilyCachePolicy>;
        using LocalSnapshotRef=std::shared_ptr<dns::LocalSnapshot const> const*;
        using DnsResult=std::expected<std::vector<nex::corosio::endpoint>,dns::detail::ResolveError>;
        template<bool Full> using DnsValue=std::conditional_t<Full,dns::AddressAnswer,std::vector<nex::corosio::endpoint>>;
        template<bool Full> using DnsValueResult=std::expected<DnsValue<Full>,dns::detail::ResolveError>;
        auto endpoints(std::span<dns::Address const> addresses,std::uint16_t port) -> std::vector<nex::corosio::endpoint> {
            std::vector<nex::corosio::endpoint> result;
            result.reserve(addresses.size());
            for (auto const& address:addresses) {
                if (address.size==4) {
                    nex::corosio::ipv4_address::bytes_type bytes{}; std::copy_n(address.bytes.begin(),4,bytes.begin());
                    result.emplace_back(nex::corosio::ipv4_address(bytes),port);
                } else if (address.size==16) result.emplace_back(nex::corosio::ipv6_address(address.bytes),port);
            }
            return result;
        }
        template<bool Full>
        auto resolve_local_value(Session& session, nex::corosio::io_context& context, std::string name, std::uint16_t port,
                                dns::detail::AddressStrategy family, Clock::time_point deadline,
                                void*& dns_operation, void (*&cancel_dns)(void*) noexcept,LocalSnapshotRef retained=nullptr,CachePolicy cache_policy={},
                                std::optional<dns::ClientSubnet> subnet={}) -> nex::capy::task<DnsValueResult<Full>> {
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
            auto task=[&] {
                if constexpr (Full) return operation.resolve_answer(std::move(name),deadline);
                else return operation.resolve(std::move(name),deadline);
            }();
            auto addresses=co_await std::move(task);
            if (session.closed) co_return std::unexpected(dns::detail::ResolveError::canceled);
            if (!addresses) co_return std::unexpected(addresses.error());
            if constexpr (Full) co_return std::move(*addresses);
            else {
                auto result=endpoints(*addresses,port);
                if (result.empty()) co_return std::unexpected(dns::detail::ResolveError::no_data);
                co_return result;
            }
        }
        auto resolve_local_impl(Session& session, nex::corosio::io_context& context, std::string name, std::uint16_t port,
                                dns::detail::AddressStrategy family, Clock::time_point deadline) -> nex::capy::task<DnsResult> {
            co_return co_await resolve_local_value<false>(session,context,std::move(name),port,family,deadline,session.dns_operation,session.cancel_dns);
        }
        template<bool Full>
        auto query_server(Session& session, nex::corosio::io_context& context, std::size_t server_index,
                          std::vector<nex::corosio::endpoint> const& servers, std::string const& name, std::uint16_t port,
                          dns::detail::AddressStrategy family, Clock::time_point deadline,
                          void*& dns_operation, void (*&cancel_dns)(void*) noexcept,LocalSnapshotRef retained=nullptr,CachePolicy cache_policy={},
                          std::optional<dns::ClientSubnet> subnet={}) -> nex::capy::task<DnsValueResult<Full>> {
            if (Clock::now()>=deadline) co_return std::unexpected(dns::detail::ResolveError::timeout);
            if (session.closed) co_return std::unexpected(dns::detail::ResolveError::canceled);
            if (cancel_dns) co_return std::unexpected(dns::detail::ResolveError::state);
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
                auto view=session.dns->views->view(server_index,upstream,subnet);
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
                    ~Registration() {
                        cancel=nullptr; operation=nullptr;
#ifdef NEXUS_TEST_DNS_OWNER
                        nexus_test_dns_registration_destroy();
#endif
                    }
                } registration{dns_operation,cancel_dns};
                dns_operation=&operation;
                cancel_dns=[](void* pointer) noexcept {
                    static_cast<Resolver*>(pointer)->cancel();
                };
#ifdef NEXUS_TEST_DNS_LIFETIME
                nexus_test_dns_registered();
#endif
                auto task=[&] {
                    if constexpr (Full) return operation.resolve_answer(upstream,
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
                        *view,
#else
                        transports ? transports->address_view(server_index+1) : server_index+1,
#endif
                        name,deadline);
                    else return operation.
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
                        resolve_native(upstream,*view,name,deadline);
#else
                        resolve(upstream,transports ? transports->address_view(server_index+1) : server_index+1,name,deadline);
#endif
                }();
                auto resolved=co_await std::move(task);
                if (session.closed) co_return std::unexpected(dns::detail::ResolveError::canceled);
                if (!resolved) {
                    auto error=resolved.error();
                    if (error==dns::detail::ResolveError::transport) continue;
                    co_return std::unexpected(error);
                }
                if constexpr (Full) co_return std::move(*resolved);
                else co_return endpoints(*resolved,port);
            }
            co_return std::unexpected(dns::detail::ResolveError::transport);
        }
        template<bool Full>
        auto resolve_dns_value(Session& session, nex::corosio::io_context& context, std::size_t selected,
                         std::string name, std::uint16_t port, dns::detail::AddressStrategy family, Clock::time_point deadline,
                         void*& dns_operation, void (*&cancel_dns)(void*) noexcept, bool const* canceled=nullptr,LocalSnapshotRef retained=nullptr,CachePolicy cache_policy={},
                         std::optional<dns::ClientSubnet> subnet={}) -> nex::capy::task<DnsValueResult<Full>> {
            auto const& routing=session.dns->routing;
            std::vector<std::size_t> chain;
            auto current=selected;
            while (routing.servers[current].resolver) {
                chain.push_back(current);
                current=*routing.servers[current].resolver;
            }
            std::vector<nex::corosio::endpoint> endpoints;
            if (routing.servers[current].port) endpoints.push_back(session.dns->endpoint(current));
            for (auto it=chain.rbegin();it!=chain.rend();++it) {
                if (canceled && *canceled) co_return std::unexpected(dns::detail::ResolveError::canceled);
                auto const& next=routing.servers[*it];
                auto resolved=co_await query_server<false>(session,context,current,endpoints,next.host,next.port,strategy(session),deadline,dns_operation,cancel_dns,retained);
                if (!resolved) co_return std::unexpected(resolved.error());
                endpoints=std::move(*resolved);
                current=*it;
            }
            if (canceled && *canceled) co_return std::unexpected(dns::detail::ResolveError::canceled);
            co_return co_await query_server<Full>(session,context,current,endpoints,name,port,family,deadline,dns_operation,cancel_dns,retained,cache_policy,subnet);
        }
#ifdef NEXUS_DNS_RESPONSE
        using RawSelection=dns::detail::LocalResponseSelection;
#include "dns_message_response.hpp"
        struct LocalResponseLookup {
            nex::corosio::io_context& context;
            dns_hp_experiment::ResponseCoordinatorOwner* owner;
            dns_hp_experiment::LocalViewBinding* views;
            std::optional<dns::ClientSubnet> subnet;
            std::optional<dns_hp_experiment::ResponseCoordinatorQuery> active;
            std::optional<dns::detail::MessageQuery> message;
            auto cancel() noexcept -> void { if (active) active->cancel(); if (message) message->cancel(); }
            auto resolve(std::shared_ptr<dns::LocalSnapshot const> const& snapshot,nex::corosio::endpoint upstream,
                std::string const& name,std::uint16_t type,Clock::time_point deadline,bool tcp,bool disabled)
                -> nex::capy::task<std::expected<dns::Response,dns::detail::ResolveError>> {
                if (type != 1 && type != 28) {
                    message.emplace(context,tcp);
                    auto response=co_await message_response(*message,upstream,name,type,deadline,false);
                    message.reset();co_return response;
                }
                if (!owner || !views) co_return std::unexpected(dns::detail::ResolveError::state);
                auto view=views->view(snapshot,upstream,subnet);if (!view) co_return std::unexpected(view.error());
                active.emplace(*owner);
                auto response=co_await active->resolve(upstream,*view,{name,type},deadline,tcp,false,disabled,subnet);
                active.reset();co_return response;
            }
        };
#include "dns_response_transport.hpp"
#include "dns_response_operation.hpp"
#include "dns_address_race.hpp"
#include "dns_address_program.hpp"
#endif

    }

    auto Session::dns_rules() const noexcept -> std::span<policy::DnsRule const> {
        if (route_snapshot && route_snapshot->dns) return route_snapshot->dns->rules;
        if (dns) return dns->routing.rules;
        return {};
    }

    auto Session::dns_requirements() const noexcept -> policy::DnsContextRequirements {
        if (route_snapshot && route_snapshot->dns) return route_snapshot->dns->context;
        return dns ? dns->context : policy::DnsContextRequirements{};
    }

    static auto resolve_destination_policy(Session& session,nex::corosio::io_context& context,std::string name,std::uint16_t port,
        Clock::time_point deadline,policy::DnsContext input,void*& operation,
        void (*&cancel)(void*) noexcept,bool const* canceled=nullptr,std::optional<std::size_t> view_final={}) -> nex::capy::task<DnsResult> {
        if (session.closed || (canceled && *canceled)) co_return std::unexpected(dns::detail::ResolveError::canceled);
        if (Clock::now()>=deadline) co_return std::unexpected(dns::detail::ResolveError::timeout);
        auto family=strategy(session);
        if (!session.dns) co_return co_await resolve_local_value<false>(session,context,std::move(name),port,family,deadline,operation,cancel);
        auto types=dns::detail::address_types(family);
        auto count=dns::detail::address_type_count(family);
        input.inbound=session.inbound;
        input.auth_user=session.auth_user;
        input.source_interface=session.source_interface;
#ifdef NEXUS_DNS_RESPONSE
        auto has_response=session.route_snapshot && session.route_snapshot->dns ?
            session.route_snapshot->dns->has_response_program : session.dns->has_response_program;
        if (has_response) {
            for (unsigned i=0;i<count;++i) if (policy::dns_preflight_reject(session.dns_rules(),name,types[i],input))
                co_return std::unexpected(dns::detail::ResolveError::policy_rejected);
            co_return co_await resolve_response_program(session,context,name,port,family,deadline,input,operation,cancel,canceled,view_final);
        }
#endif
        auto const& routing=session.dns->routing;
        auto select=[&](std::uint16_t type) {
            return policy::select_question_dns_action(session.dns_rules(),name,type,view_final.value_or(routing.final),routing.disable_cache,input);
        };
        auto first=select(types[0]);
        auto second=count==2 ? select(types[1]) : first;
        if (first.action==policy::DnsAction::reject || second.action==policy::DnsAction::reject)
            co_return std::unexpected(dns::detail::ResolveError::policy_rejected);
        // Keep local search, hosts and ordinary same-server dual lookups as
        // one operation. Different routes must expose their canonical names
        // before their independently resolved families may be combined.
        dns::detail::FamilyCachePolicy cache_policy{};
        cache_policy[types[0]==1 ? 0 : 1]=first.disable_cache;
        if (count==2) cache_policy[types[1]==1 ? 0 : 1]=second.disable_cache;
        if (first.server==second.server)
            co_return co_await resolve_dns_value<false>(session,context,first.server,std::move(name),port,family,deadline,
                operation,cancel,canceled,nullptr,cache_policy);
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
            auto one=types[i]==1 ? dns::detail::AddressStrategy::ipv4_only : dns::detail::AddressStrategy::ipv6_only;
            auto result=co_await resolve_dns_value<true>(session,context,selected,name,port,one,deadline,
                operation,cancel,canceled,snapshot ? &snapshot : nullptr,cache_policy);
            auto added=answers.add(std::move(result));
            if (!added) co_return std::unexpected(added.error());
        }
        auto result=answers.finish();
        if (!result) co_return std::unexpected(result.error());
        co_return endpoints(*result,port);
    }

    auto resolve_destination(Session& session,nex::corosio::io_context& context,std::string name,std::uint16_t port,
        Clock::time_point deadline,policy::DnsContext input) -> nex::capy::task<DnsResult> {
        return resolve_destination_policy(session,context,std::move(name),port,deadline,input,
            session.dns_operation,session.cancel_dns);
    }

    auto resolve_local(Session& session, nex::corosio::io_context& context, std::string name, std::uint16_t port,
                       Clock::time_point deadline) -> nex::capy::task<std::optional<std::vector<nex::corosio::endpoint>>> {
        auto resolved=co_await resolve_local_impl(session,context,std::move(name),port,dns::detail::AddressStrategy::prefer_ipv4,deadline);
        if (!resolved) co_return std::nullopt;
        co_return std::move(*resolved);
    }
    auto resolve_local_owned(Session& session, nex::corosio::io_context& context, DnsSlot& slot, std::string name,
                             std::uint16_t port, Clock::time_point deadline) -> nex::capy::task<std::optional<std::vector<nex::corosio::endpoint>>> {
        if (slot.canceled) co_return std::nullopt;
        auto resolved=co_await resolve_local_value<false>(session,context,std::move(name),port,dns::detail::AddressStrategy::prefer_ipv4,deadline,slot.operation,slot.cancel_operation);
        if (!resolved) co_return std::nullopt;
        co_return std::move(*resolved);
    }
    auto resolve_bootstrap_impl(Session& session, nex::corosio::io_context& context, std::size_t selected,
                           std::string name, std::uint16_t port, Clock::time_point deadline,
                           void*& dns_operation, void (*&cancel_dns)(void*) noexcept, bool const* canceled=nullptr) -> nex::capy::task<std::optional<std::vector<nex::corosio::endpoint>>> {
        if (!session.dns || session.closed || (canceled && *canceled)) co_return std::nullopt;
        auto const& routing=session.dns->routing;
        if (selected>=routing.resolver_count()) co_return std::nullopt;
        auto task=selected<routing.servers.size() ?
            resolve_dns_value<false>(session,context,selected,std::move(name),port,strategy(session),deadline,
                dns_operation,cancel_dns,canceled) :
            resolve_destination_policy(session,context,std::move(name),port,deadline,{},dns_operation,cancel_dns,
                canceled,routing.view_finals[selected-routing.servers.size()]);
        auto resolved=co_await std::move(task);
        if (!resolved || session.closed || (canceled && *canceled)) co_return std::nullopt;
        co_return std::move(*resolved);
    }
    auto resolve_bootstrap(Session& session, nex::corosio::io_context& context, std::size_t selected,
                           std::string name, std::uint16_t port, Clock::time_point deadline) -> nex::capy::task<std::optional<std::vector<nex::corosio::endpoint>>> {
        co_return co_await resolve_bootstrap_impl(session,context,selected,std::move(name),port,deadline,session.dns_operation,session.cancel_dns);
    }
    auto resolve_bootstrap_owned(Session& session, nex::corosio::io_context& context, DnsSlot& slot, std::size_t selected,
                                 std::string name, std::uint16_t port, Clock::time_point deadline) -> nex::capy::task<std::optional<std::vector<nex::corosio::endpoint>>> {
        co_return co_await resolve_bootstrap_impl(session,context,selected,std::move(name),port,deadline,slot.operation,slot.cancel_operation,&slot.canceled);
    }
#ifdef NEXUS_DNS_RESPONSE
    auto resolve_destination_race(Session& session,nex::corosio::io_context& context,std::string name,std::uint16_t port,
        Clock::time_point deadline,policy::DnsContext input,std::span<dns::ResponseRaceMode const> modes) -> nex::capy::task<DnsResult> {
        if(session.closed)co_return std::unexpected(dns::detail::ResolveError::canceled);
        if(!session.dns || !port)co_return std::unexpected(dns::detail::ResolveError::state);
        co_return co_await resolve_response_program(session,context,name,port,strategy(session),deadline,input,session.dns_operation,session.cancel_dns,nullptr,{},modes);
    }
    auto resolve_response_owned(Session& session,nex::corosio::io_context& context,DnsSlot& slot,std::size_t selected,
        std::string name,std::uint16_t type,Clock::time_point deadline,std::shared_ptr<dns::LocalSnapshot const> snapshot,
        bool disable_cache,std::size_t* rotation,std::optional<std::string> candidate,std::optional<dns::ClientSubnet> subnet)
        -> nex::capy::task<std::expected<dns::detail::LocalResponseSelection,dns::detail::ResolveError>> {
        using Error=dns::detail::ResolveError;
        if(slot.canceled || session.closed)co_return std::unexpected(Error::canceled);
        if(slot.operation || slot.cancel_operation || !session.dns || selected>=session.dns->routing.servers.size())co_return std::unexpected(Error::state);
        auto fixed=candidate ? std::optional<std::string_view>(*candidate) : std::nullopt;
        ResponseOperation operation(session,context,selected,name,type,deadline,snapshot ? &snapshot : nullptr,disable_cache,rotation,fixed,subnet);
        struct Registration {DnsSlot& slot;~Registration(){slot.cancel_operation=nullptr;slot.operation=nullptr;}} registration{slot};
        slot.operation=&operation;
        slot.cancel_operation=[](void* value) noexcept {static_cast<ResponseOperation*>(value)->cancel();};
        auto result=co_await operation.run();
        if(slot.canceled || session.closed)co_return std::unexpected(Error::canceled);
        co_return result;
    }
#endif

#ifdef NEXUS_ENABLE_SOCKS_UDP
    auto resolve_udp_domain(Session& session, nex::corosio::io_context& context, std::string name,
                            std::uint16_t port, Clock::time_point deadline,net::UdpEndpoint const* source) -> nex::capy::task<std::optional<std::vector<nex::corosio::endpoint>>> {
        if (session.closed) co_return std::nullopt;
        // Native SOCKS UDP supplies its admitted datagram peer explicitly.
        // Stream-carried UDP uses the immediate authenticated stream peer.
        auto stream_source=!source ? source_endpoint(session,session.dns_requirements().source) : std::nullopt;
        if (stream_source) source=&*stream_source;
        policy::DnsContext input{.network=rules::Network::udp};
        if (source) {
            input.source_port=source->port;
            input.source_ip_bytes=std::span(source->address).first(source->family==4 ? 4 : 16);
        }
        auto resolved=co_await resolve_destination(session,context,std::move(name),port,deadline,input);
        if (!resolved || resolved->empty() || resolved->size()>64 || session.closed || Clock::now()>=deadline) co_return std::nullopt;
        co_return std::move(*resolved);
    }
#endif

}
