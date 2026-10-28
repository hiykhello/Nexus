module;
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/resolver.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/udp_socket.hpp>
#include <sys/random.h>

module nexus.proxy;
import proxy.v4;
import std;
import nexus.socks5;
import nexus.rules;
import nexus.http.connect;
import nexus.dns.message;
import nexus.dns.cache;
import nexus.thirdparty.corosio;
#ifdef NEXUS_TEST_FAKEIP
import nexus.dns.fakeip_request;
extern "C" void nexus_test_fakeip_blocked();
#endif

#include "dns_state.hpp"
#include "../dns/corosio_dual_resolve.hpp"

namespace nexus::proxy {
    namespace {
        auto failure_code(std::error_code error) noexcept -> std::uint8_t {
            if (error == std::errc::network_unreachable) return 3;
            if (error == std::errc::host_unreachable) return 4;
            if (error == std::errc::connection_refused) return 5;
            if (error == std::errc::timed_out || error == capy::cond::timeout) return 6;
            return 1;
        }
        using DnsResult=std::expected<std::vector<io::endpoint>,dns::detail::ResolveError>;
        auto query_server(Session& session, io::io_context& context, std::size_t server_index,
                          std::vector<io::endpoint> const& servers, std::string const& name, std::uint16_t port,
                          dns::detail::AddressStrategy family) -> capy::task<DnsResult> {
            auto const& server=session.dns->routing.servers[server_index];
            if (!server.port) {
                session.resolver=std::make_unique<io::resolver>(context);
                auto [error,endpoints]=co_await session.resolver->resolve(name,std::to_string(port));
                session.resolver.reset();
                if (session.closed) co_return std::unexpected(dns::detail::ResolveError::canceled);
                if (error || endpoints.empty() || endpoints.size()>64) co_return std::unexpected(dns::detail::ResolveError::transport);
                if (family==dns::detail::AddressStrategy::ipv4_only || family==dns::detail::AddressStrategy::ipv6_only) {
                    auto ipv6=family==dns::detail::AddressStrategy::ipv6_only;
                    std::erase_if(endpoints,[ipv6](auto const& ep) { return ep.address().is_v6()!=ipv6; });
                } else {
                    auto ipv6=family==dns::detail::AddressStrategy::prefer_ipv6;
                    std::stable_partition(endpoints.begin(),endpoints.end(),[ipv6](auto const& ep) { return ep.address().is_v6()==ipv6; });
                }
                if (endpoints.empty()) co_return std::unexpected(dns::detail::ResolveError::no_data);
                co_return endpoints;
            }
            for (auto const& upstream : servers) {
                auto operation=std::make_shared<dns::detail::DualAddressResolver>(context,session.dns->cache,server.tcp,family,
                    session.dns->routing.disable_cache,session.dns->routing.edns);
                session.cancel_dns=[operation] { operation->cancel(); };
                auto resolved=co_await operation->resolve(upstream,server_index+1,name,session.started+std::chrono::seconds(10));
                session.cancel_dns={};
                if (session.closed) co_return std::unexpected(dns::detail::ResolveError::canceled);
                if (!resolved) {
                    if (resolved.error()==dns::detail::ResolveError::transport) continue;
                    co_return std::unexpected(resolved.error());
                }
                std::vector<io::endpoint> endpoints;
                for (auto const& address : *resolved) {
                    if (address.size==4) {
                        io::ipv4_address::bytes_type bytes{};
                        std::copy_n(address.bytes.begin(),4,bytes.begin());
                        endpoints.emplace_back(io::ipv4_address(bytes),port);
                    } else {
                        io::ipv6_address::bytes_type bytes{};
                        std::copy_n(address.bytes.begin(),16,bytes.begin());
                        endpoints.emplace_back(io::ipv6_address(bytes),port);
                    }
                }
                co_return endpoints;
            }
            co_return std::unexpected(dns::detail::ResolveError::transport);
        }
        auto resolve_dns(Session& session, io::io_context& context, std::size_t selected,
                         std::string name, std::uint16_t port, dns::detail::AddressStrategy family) -> capy::task<DnsResult> {
            auto const& routing=session.dns->routing;
            std::vector<std::size_t> chain;
            auto current=selected;
            while (routing.servers[current].resolver) {
                chain.push_back(current);
                current=*routing.servers[current].resolver;
            }
            std::vector<io::endpoint> endpoints;
            if (routing.servers[current].port) endpoints.push_back(session.dns->endpoint(current));
            for (auto it=chain.rbegin();it!=chain.rend();++it) {
                auto const& next=routing.servers[*it];
                auto resolved=co_await query_server(session,context,current,endpoints,next.host,next.port,family);
                if (!resolved) co_return std::unexpected(resolved.error());
                endpoints=std::move(*resolved);
                current=*it;
            }
            co_return co_await query_server(session,context,current,endpoints,name,port,family);
        }
    }

    auto resolve_bootstrap(Session& session, io::io_context& context, std::size_t selected,
                           std::string name, std::uint16_t port) -> capy::task<std::optional<std::vector<io::endpoint>>> {
        if (!session.dns || selected>=session.dns->routing.servers.size() || session.closed) co_return std::nullopt;
        auto strategy=session.dns->routing.strategy;
        auto family=dns::detail::AddressStrategy::prefer_ipv4;
        if (strategy==DnsStrategy::prefer_ipv6) family=dns::detail::AddressStrategy::prefer_ipv6;
        else if (strategy==DnsStrategy::ipv4_only) family=dns::detail::AddressStrategy::ipv4_only;
        else if (strategy==DnsStrategy::ipv6_only) family=dns::detail::AddressStrategy::ipv6_only;
        auto resolved=co_await resolve_dns(session,context,selected,std::move(name),port,family);
        if (!resolved || session.closed) co_return std::nullopt;
        co_return std::move(*resolved);
    }

        // Shared routing and dialing ensures both protocols enforce the same policy.
        auto dial_impl(std::shared_ptr<Session> session, io::io_context& context,
                  rules::RouteMatcher const& policy, socks5::Request const& original) -> capy::task<std::uint8_t> {
#ifdef NEXUS_TEST_FAKEIP
            auto request=original;
            if (session->fakeip) {
                auto translated=dns::translate_fakeip_request(*session->fakeip,original,session->fakeip_view);
                if (!translated) co_return 2;
                request=translated->request;
                session->fakeip_target=std::move(translated->target);
            }
#else
            auto const& request=original;
#endif
            std::vector<io::endpoint> destinations;
            std::optional<std::string_view> domain_name;
            if (request.address_type == 3) {
                auto domain = std::string_view(reinterpret_cast<char const*>(request.address.data()), request.address_length);
                domain_name=domain;
                auto preflight=policy.preflight(domain);
                if (!preflight) co_return 1;
                if (*preflight && **preflight==static_cast<std::size_t>(RouteAction::block)) co_return 2;
                auto dns_index=session->dns ? session->dns->select(domain) : 0;
                auto strategy=session->dns ? session->dns->routing.strategy : DnsStrategy::automatic;
                if (session->dns && session->dns->routing.servers[dns_index].port) {
                    auto family=dns::detail::AddressStrategy::prefer_ipv4;
                    if (strategy==DnsStrategy::prefer_ipv6) family=dns::detail::AddressStrategy::prefer_ipv6;
                    else if (strategy==DnsStrategy::ipv4_only) family=dns::detail::AddressStrategy::ipv4_only;
                    else if (strategy==DnsStrategy::ipv6_only) family=dns::detail::AddressStrategy::ipv6_only;
                    auto resolved=co_await resolve_dns(*session,context,dns_index,std::string(domain),request.port,family);
                    if (session->closed) co_return 1;
                    if (!resolved) co_return 4;
                    destinations=std::move(*resolved);
                } else {
                    session->resolver = std::make_unique<io::resolver>(context);
                    auto [error, endpoints] = co_await session->resolver->resolve(domain, std::to_string(request.port));
                    session->resolver.reset();
                    if (session->closed) co_return 1;
                    if (error || endpoints.empty()) co_return 4;
                    if (endpoints.size() > 64) co_return 1;
                    destinations = std::move(endpoints);
                    if (strategy==DnsStrategy::ipv4_only || strategy==DnsStrategy::ipv6_only) {
                        auto ipv6=strategy==DnsStrategy::ipv6_only;
                        std::erase_if(destinations,[ipv6](auto const& endpoint) { return endpoint.address().is_v6()!=ipv6; });
                    } else if (strategy==DnsStrategy::prefer_ipv4 || strategy==DnsStrategy::prefer_ipv6) {
                        auto ipv6=strategy==DnsStrategy::prefer_ipv6;
                        std::stable_partition(destinations.begin(),destinations.end(),[ipv6](auto const& endpoint) {
                            return endpoint.address().is_v6()==ipv6;
                        });
                    }
                    if (destinations.empty()) co_return 4;
                }
            } else if (request.address_type == 1) {
                io::ipv4_address::bytes_type raw{};
                std::copy_n(request.address.begin(), raw.size(), raw.begin());
                destinations.emplace_back(io::ipv4_address(raw), request.port);
            } else {
                io::ipv6_address::bytes_type raw{};
                std::copy_n(request.address.begin(), raw.size(), raw.begin());
                destinations.emplace_back(io::ipv6_address(raw), request.port);
            }
            std::error_code error;
            bool blocked = false;
            std::size_t next = 0;
            auto const connect_deadline = session->started + std::chrono::seconds(10);
            while (next < destinations.size()) {
                // The condition cannot await a tunnel. Stop classifying at the
                // first tunnel or policy error; handle that candidate after
                // the direct sequence completes, then resume in order.
                bool attempted = false, boundary = false, policy_error = false;
                std::optional<std::size_t> tunnel_action;
                io::endpoint tunnel_destination;
                auto condition = [&](std::error_code const&, io::endpoint const& destination) {
                    if (boundary) return false;
                    if (session->closed) { boundary=true; return false; }
                    ++next;
#ifdef NEXUS_TEST_FAKEIP
                    if (session->fakeip) {
                        auto address=destination.address();
                        auto allowed=address.is_v4() ? dns::validate_fakeip_resolution(*session->fakeip,address.to_v4().to_bytes()) :
                                                       dns::validate_fakeip_resolution(*session->fakeip,address.to_v6().to_bytes());
                        if (!allowed) { nexus_test_fakeip_blocked(); blocked=true; return false; }
                    }
#endif
                    auto ip=destination.address().to_string();
                    auto matched=policy.match({.domain=domain_name,.ip=ip});
                    if (!matched) { boundary=true; policy_error=true; return false; }
                    if (*matched==static_cast<std::size_t>(RouteAction::block)) { blocked=true; return false; }
                    if (*matched>=static_cast<std::size_t>(RouteAction::vless)) {
                        boundary=true; tunnel_action=*matched; tunnel_destination=destination; return false;
                    }
                    attempted=true;
                    return true;
                };
                auto candidates=std::span{destinations}.subspan(next);
                if (Clock::now() >= connect_deadline) co_return failure_code(std::make_error_code(std::errc::timed_out));
                auto operation = nex::corosio::connect(session->target, candidates, condition);
                auto [connect_error, connected_endpoint]=co_await nex::corosio::timeout(
                    std::move(operation), connect_deadline);
                if (connect_error) session->target.close();
                (void)connected_endpoint;
                if (session->closed) co_return 1;
                if (!connect_error) co_return 0;
                if (connect_error == capy::cond::timeout) co_return 6;
                // Upstream leaves the last failed socket open; close it before
                // starting a tunnel or leaving the candidate loop.
                if (attempted) error=connect_error;
                if (policy_error) co_return 1;
                if (tunnel_action) {
                    auto index=*tunnel_action-static_cast<std::size_t>(RouteAction::vless);
                    if (!session->tunnel_factories || index>=session->tunnel_factories->size()) co_return 1;
                    session->tunnel=(*session->tunnel_factories)[index](*session,context);
                    auto connected_tunnel=co_await session->tunnel->connect(tunnel_destination);
                    if (session->closed) co_return 1;
                    if (connected_tunnel==TunnelConnectResult::connected) co_return 0;
                    if (connected_tunnel==TunnelConnectResult::failed) co_return 1;
                    session->tunnel={};
                    error=std::make_error_code(std::errc::host_unreachable);
                }
            }
            co_return error ? failure_code(error) : blocked ? 2 : 4;
        }

    namespace {
        struct DialWatch {
            std::stop_source stop;
            capy::async_event done;
            ~DialWatch() { stop.request_stop(); }
        };
        // Error readiness does not consume pipelined bytes or confuse a normal
        // write-side EOF with a reset. It is best effort: an error occurring
        // before registration may be missed by the underlying backend.
        auto watch_client_error(std::shared_ptr<Session> session) -> capy::task<> {
            auto [error]=co_await session->client.wait(io::wait_type::error);
            // Corosio consumes SO_ERROR and returns it; EIO can also mean a
            // harmless hangup with no socket error, including half-close.
            if (!session->closed && error && error!=std::errc::io_error && error!=capy::cond::canceled)
                session->close();
        }
    }

    auto dial(std::shared_ptr<Session> session, io::io_context& context,
              rules::RouteMatcher const& policy, socks5::Request const& request) -> capy::task<std::uint8_t> {
        auto watch=std::make_shared<DialWatch>();
        capy::run_async(context.get_executor(),watch->stop.get_token(),
            [watch] { watch->done.set(); },
            [watch,session](std::exception_ptr) { session->close(); watch->done.set(); })(watch_client_error(session));
        // Stop the watcher even if dialing throws. Its completion retains both
        // the watch and session until the pending socket operation has drained.
        struct StopWatch { std::shared_ptr<DialWatch> state; ~StopWatch() { state->stop.request_stop(); } } guard{watch};
        auto result=co_await dial_impl(session,context,policy,request);
        watch->stop.request_stop();
        (void)co_await watch->done.wait();
        co_return session->closed ? 1 : result;
    }

}
