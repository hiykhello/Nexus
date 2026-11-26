module;
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/timeout.hpp>
#include <boost/corosio/udp_socket.hpp>
module relay;
import proxy.v4;
import std;
import relay.request_backend;
import rules;
import http.connect;
import dns.message;
import capy;
import corosio;
import net.tcp_connect;
import net.tcp_fast_open;
#ifdef NEXUS_TEST_FAKEIP
extern "C" void nexus_test_fakeip_blocked();
extern "C" void nexus_test_fakeip_watcher_done();
#endif


namespace relay {
    namespace {
        auto failure_code(std::error_code error) noexcept -> std::uint8_t {
            if (error == std::errc::network_unreachable) return 3;
            if (error == std::errc::host_unreachable) return 4;
            if (error == std::errc::connection_refused) return 5;
            if (error == std::errc::timed_out || error == capy::cond::timeout) return 6;
            return 1;
        }
    }

        namespace {
            struct SocketRoutingSource {
                auto snapshot(Session& session,rules::RouteMatcher const& policy) const -> std::optional<net::UdpEndpoint> {return source_endpoint(session,policy);}
            };
            struct DatagramRoutingSource {
                net::UdpEndpoint const& peer;
                auto snapshot(Session& session,rules::RouteMatcher const& policy) const -> std::optional<net::UdpEndpoint> {
                    return policy.needs_source() || session.dns_requirements().source ? std::optional(peer) : std::nullopt;
                }
            };
        }
        auto OrderedTcpRequest::prepare(Session& session,socks5::Request const& original) -> bool {
            if(!target.empty() || !endpoints.empty() || input.port || session.closed || !original.port ||
                original.status!=socks5::Status::accepted)return false;
#ifdef NEXUS_ENABLE_FAKEIP
            auto request=original;
            if (session.fakeip) {
                auto translated=dns::translate_fakeip_request(*session.fakeip,original,session.fakeip_view);
                if (!translated) return false;
                request=translated->request;
                session.fakeip_target=std::move(translated->target);
                if (session.fakeip_target) {
                    input.domain_absent[static_cast<std::size_t>(rules::DomainSource::explicit_target)]=true;
                } else input.domain_absent[static_cast<std::size_t>(rules::DomainSource::fakeip)]=true;
            }
#else
            auto const& request=original;
#endif
            if(request.address_type==3) {
                if(!request.address_length)return false;
                target.assign(reinterpret_cast<char const*>(request.address.data()),request.address_length);
#ifdef NEXUS_ENABLE_FAKEIP
                if (session.fakeip_target) input.fakeip_domain=target;
                else
#endif
                    input.explicit_domain=target;
            } else if(request.address_type==1 && request.address_length==4) {
                io::ipv4_address::bytes_type bytes{};std::copy_n(request.address.begin(),bytes.size(),bytes.begin());
                io::endpoint endpoint(io::ipv4_address(bytes),request.port);
                target=endpoint.address().to_string();endpoints.push_back(endpoint);input.ip=target;
                input.domain_absent[static_cast<std::size_t>(rules::DomainSource::explicit_target)]=true;
                if (session.reverse_cache) {
                    dns::Address addr{};addr.size=4;std::copy_n(bytes.begin(),4,addr.bytes.begin());
                    auto now_ms=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                        Clock::now().time_since_epoch()).count());
                    if (auto found=session.reverse_cache->lookup(session.reverse_view,addr,now_ms)) {
                        reverse_name=*found;input.reverse_domain=reverse_name->view();
                    } else input.domain_absent[static_cast<std::size_t>(rules::DomainSource::reverse_dns)]=true;
                } else input.domain_absent[static_cast<std::size_t>(rules::DomainSource::reverse_dns)]=true;
            } else if(request.address_type==4 && request.address_length==16) {
                io::ipv6_address::bytes_type bytes{};std::copy_n(request.address.begin(),bytes.size(),bytes.begin());
                io::endpoint endpoint(io::ipv6_address(bytes),request.port);
                target=endpoint.address().to_string();endpoints.push_back(endpoint);input.ip=target;
                input.domain_absent[static_cast<std::size_t>(rules::DomainSource::explicit_target)]=true;
                if (session.reverse_cache) {
                    dns::Address addr{};addr.size=16;std::copy_n(bytes.begin(),16,addr.bytes.begin());
                    auto now_ms=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                        Clock::now().time_since_epoch()).count());
                    if (auto found=session.reverse_cache->lookup(session.reverse_view,addr,now_ms)) {
                        reverse_name=*found;input.reverse_domain=reverse_name->view();
                    } else input.domain_absent[static_cast<std::size_t>(rules::DomainSource::reverse_dns)]=true;
                } else input.domain_absent[static_cast<std::size_t>(rules::DomainSource::reverse_dns)]=true;
            } else return false;
            if (request.address_type==3)
                input.domain_absent[static_cast<std::size_t>(rules::DomainSource::reverse_dns)]=true;
            input.port=request.port;input.network=rules::Network::tcp;
            session.fill_program_input(input);
            input=session.ingress.apply(input);
            source=source_endpoint(session,true);
            if(source) {
                input.source_port=source->port;
                input.source_ip_bytes=std::span(source->address).first(source->family==4 ? 4 : 16);
            }
            return true;
        }

        // The caller owns the endpoints and classifier until this operation completes.
        // A fixed classifier lets an ordered program dial its selected outbound
        // without performing DNS or evaluating the indexed route policy again.
        template<class Classifier>
        auto dial_candidates(Session& session,io::io_context& context,
            std::span<io::endpoint const> destinations,Clock::time_point limit,Classifier& classify,
            std::span<std::uint8_t const> first={},bool* first_sent=nullptr,
            std::optional<std::string_view> tunnel_domain={}) -> capy::task<std::uint8_t> {
            if (session.closed) co_return 1;
            if (Clock::now()>=limit) co_return 6;
            std::vector<io::endpoint> interleaved;
            if (!destinations.empty() &&
                net::has_dual_stack_families(destinations,[](io::endpoint const& ep) noexcept { return ep.is_v6(); })) {
                interleaved=net::interleave_happy_eyeballs(
                    destinations,[](io::endpoint const& ep) noexcept { return ep.is_v6(); },destinations.front().is_v6());
                destinations=interleaved;
            }
            std::error_code error;
            bool blocked = false;
            std::size_t next = 0;
            // A node that exhausted its bootstrap/socket candidates cannot be
            // repaired by another business address in this same request.
            std::bitset<256> exhausted_tunnels;
            if (session.meters_principal_bytes()) first={};
            auto const connect_deadline = std::min(limit,session.started + std::chrono::milliseconds(session.direct_connect_timeout_ms));
            if (session.direct_connect_timeout_ms>10000)
                session.handshake_deadline=std::max(session.handshake_deadline,connect_deadline+std::chrono::seconds(1));
            while (next < destinations.size()) {
                // The condition cannot await a tunnel. Stop classifying at the
                // first tunnel or policy error; handle that candidate after
                // the direct sequence completes, then resume in order.
                bool attempted = false, boundary = false, policy_error = false;
                std::optional<TrafficRoute> route;
                io::endpoint routed_destination, connected_target;
                std::vector<std::pair<io::endpoint, TrafficRoute>> admitted_routes;
                auto condition = [&](std::error_code const&, io::endpoint const& destination) {
                    if (boundary) return false;
                    if (session.closed) { boundary=true; return false; }
                    ++next;
                    if (!valid_destination(destination)) return false;
#ifdef NEXUS_ENABLE_FAKEIP
                    if (session.fakeip) {
                        auto address=destination.address();
                        auto allowed=address.is_v4() ? dns::validate_fakeip_resolution(*session.fakeip,address.to_v4().to_bytes()) :
                                                       dns::validate_fakeip_resolution(*session.fakeip,address.to_v6().to_bytes());
                        if (!allowed) {
#ifdef NEXUS_TEST_FAKEIP
                            nexus_test_fakeip_blocked();
#endif
                            blocked=true;
                            return false;
                        }
                    }
#endif
                    auto matched=classify(destination);
                    if (!matched) { boundary=true; policy_error=true; return false; }
                    if (matched->outbound==static_cast<std::size_t>(RouteAction::block)) { blocked=true; return false; }
                    if (matched->outbound>=static_cast<std::size_t>(RouteAction::vless)) {
                        auto index=matched->outbound-static_cast<std::size_t>(RouteAction::vless);
                        if (index<exhausted_tunnels.size() && exhausted_tunnels[index]) return false;
                        boundary=true; route=*matched; routed_destination=destination; return false;
                    }
                    route=*matched;
                    routed_destination=destination;
                    admitted_routes.emplace_back(destination,*matched);
                    attempted=true;
                    return true;
                };
                auto candidates=destinations.subspan(next);
                std::error_code connect_error;
                if (Clock::now() >= connect_deadline) {
                    // Classify without starting another direct connection: a later
                    // candidate may use a tunnel with a longer deadline.
                    (void)condition({},candidates.front());
                    if (policy_error) co_return 1;
                    if (!route || route->outbound<static_cast<std::size_t>(RouteAction::vless)) {
                        error=std::make_error_code(std::errc::timed_out);
                        continue;
                    }
                    connect_error=std::make_error_code(std::errc::host_unreachable);
                } else {
                    bool preparation_failed=false;
                    if(!first.empty() && session.direct_tcp_options && session.direct_tcp_options->tcp_fast_open.value_or(false)) {
                        auto result=co_await net::tcp_fast_open_candidates(session.target,candidates,condition,first,connect_deadline,*session.direct_tcp_options);
                        connect_error=result.result.error;preparation_failed=result.preparation_failed;connected_target=result.endpoint;
                        if (result.result.accepted && result.result.accepted<=first.size()) {
                            session.select_traffic_path(ConnectPath::direct);
                            session.count_traffic(true,result.result.accepted);
                        }
                        if(preparation_failed)co_return failure_code(connect_error);
                        if(connect_error && result.result.accepted)co_return failure_code(connect_error);
                        if(!connect_error) {
                            if(result.result.accepted>first.size()){session.target.close();co_return 1;}
                            if(Clock::now()>=connect_deadline){session.target.close();co_return 6;}
                            auto suffix=first.subspan(result.result.accepted);
                            while(!suffix.empty()) {
                                auto [write_error,count]=co_await corosio::timeout(
                                    session.target.write_some(capy::const_buffer(suffix.data(),suffix.size())),connect_deadline);
                                if (count && count<=suffix.size()) session.count_traffic(true,count);
                                if(session.closed)co_return 1;
                                if(write_error || !count || count>suffix.size() || Clock::now()>=connect_deadline) {
                                    session.target.close();
                                    co_return Clock::now()>=connect_deadline || capy::is_timeout(write_error) ? 6 : failure_code(write_error);
                                }
                                suffix=suffix.subspan(count);
                            }
                            if(first_sent)*first_sent=true;
                        }
                    } else {
                        platform::TcpSocketOptions default_tcp_options;
                        auto const& tcp_options = session.direct_tcp_options ? *session.direct_tcp_options : default_tcp_options;
                        bool const need_timeout = connect_deadline < session.handshake_deadline || !session.registry || session.transport_owner != nullptr;
                        if (!tcp_options.configured() && candidates.size() == 1) {
                            if (condition({}, candidates[0])) {
                                auto [result] = need_timeout
                                    ? co_await corosio::timeout(session.target.connect(candidates[0]), connect_deadline)
                                    : co_await session.target.connect(candidates[0]);
                                connect_error = result;
                                connected_target = candidates[0];
                            } else {
                                connect_error = std::make_error_code(std::errc::no_such_device_or_address);
                            }
                        } else {
                            auto operation = net::connect_tcp_candidates(
                                session.target,candidates,condition,tcp_options,preparation_failed,connect_deadline);
                            auto [result, connected_endpoint] = need_timeout
                                ? co_await corosio::timeout(std::move(operation), connect_deadline)
                                : co_await std::move(operation);
                            connect_error=result;
                            connected_target=connected_endpoint;
                        }
                        if (connect_error) session.target.close();
                        if (preparation_failed) co_return failure_code(connect_error);
                    }
                }
                if (session.closed) co_return 1;
                if (!connect_error) {
                    auto chosen=*route;
                    for (auto const& [ep,r] : admitted_routes) if (ep==connected_target) { chosen=r; break; }
                    session.record_traffic_route(chosen,ConnectPath::direct);
                    co_return 0;
                }
                if (connect_error == capy::cond::timeout) {
                    error=std::make_error_code(std::errc::timed_out);
                    continue;
                }
                // Upstream leaves the last failed socket open; close it before
                // starting a tunnel or leaving the candidate loop.
                if (attempted && error!=std::errc::timed_out) error=connect_error;
                if (policy_error) co_return 1;
                if (route && route->outbound>=static_cast<std::size_t>(RouteAction::vless)) {
                    auto index=route->outbound-static_cast<std::size_t>(RouteAction::vless);
                    if (!session.tunnel_factories || index>=session.tunnel_factories->size()) co_return 1;
                    auto const& factory=(*session.tunnel_factories)[index];
                    auto tunnel_deadline=std::min(limit,session.started+std::chrono::milliseconds(factory.timeout_ms));
                    if (Clock::now()>=tunnel_deadline) {
                        error=std::make_error_code(std::errc::timed_out);
                        continue;
                    }
                    session.tunnel=factory(session,context);
                    if (!session.tunnel) co_return 1;
                    auto connected_tunnel=tunnel_domain ?
                        co_await session.tunnel->connect_domain(*tunnel_domain,routed_destination.port(),tunnel_deadline) :
                        co_await session.tunnel->connect_until(routed_destination,tunnel_deadline);
                    if (session.closed) co_return 1;
                    if (connected_tunnel==TunnelConnectResult::connected) {
                        session.record_traffic_route(*route,ConnectPath::tunnel);
                        co_return 0;
                    }
                    session.record_dial_failure(*route);
                    if (connected_tunnel==TunnelConnectResult::timeout) {
                        session.tunnel={};
                        error=std::make_error_code(std::errc::timed_out);
                        continue;
                    }
                    if (connected_tunnel==TunnelConnectResult::failed) co_return 1;
                    session.tunnel={};
                    if (index<exhausted_tunnels.size()) exhausted_tunnels[index]=true;
                    if (error!=std::errc::timed_out) error=std::make_error_code(std::errc::host_unreachable);
                }
            }
            co_return error ? failure_code(error) : blocked ? 2 : 4;
        }

        // One routing/dial algorithm. The source policy is static: socket
        // callers retain their native path, datagram streams borrow the peer
        // already authenticated by their physical QUIC connection.
        template<class Source>
        auto dial_selected_destination(Session& session, io::io_context& context,
                  rules::RouteMatcher const& policy, socks5::Request const& original,Clock::time_point limit,Source source_policy,
                  std::span<std::uint8_t const> first={},bool* first_sent=nullptr) -> capy::task<std::uint8_t> {
            if (session.closed) co_return 1;
            if (Clock::now()>=limit) co_return 6;
            // Fetch once only for traffic/DNS source predicates; the
            // same snapshot is used before DNS and for every candidate.
            auto source=source_policy.snapshot(session,policy);
            std::optional<std::span<std::uint8_t const>> source_ip;
            std::optional<std::uint16_t> source_port;
            if (source) {
                source_ip=std::span(source->address).first(source->family==4 ? 4 : 16);
                source_port=source->port;
            }
#ifdef NEXUS_ENABLE_FAKEIP
            auto request=original;
            if (session.fakeip) {
                auto translated=dns::translate_fakeip_request(*session.fakeip,original,session.fakeip_view);
                if (!translated) co_return 2;
                request=translated->request;
                session.fakeip_target=std::move(translated->target);
            }
#else
            auto const& request=original;
#endif
            std::array<io::endpoint, 1> single_destination{};
            std::vector<io::endpoint> resolved_destinations;
            std::span<io::endpoint const> destinations;
            std::optional<std::string_view> domain_name;
            if (request.address_type == 3) {
                auto domain = std::string_view(reinterpret_cast<char const*>(request.address.data()), request.address_length);
                domain_name=domain;
                auto minput=session.ingress.apply(rules::MatchInput{.domain=domain,.port=request.port,.network=rules::Network::tcp,
                    .source_port=source_port,.source_ip_bytes=source_ip});
                session.fill_match_input(minput);
                auto preflight=policy.preflight(minput);
                if (!preflight) co_return 1;
                if (*preflight && **preflight==static_cast<std::size_t>(RouteAction::block)) co_return 2;
                // If all possible policy outcomes agree, its outbound timeout
                // bounds resolution too. Otherwise keep the largest possible
                // budget until the resolved address selects an outbound.
                auto timeout_ms=session.direct_connect_timeout_ms;
                bool remote_domain = false;
                if (*preflight) {
                    auto action=**preflight;
                    if (action>=static_cast<std::size_t>(RouteAction::vless)) {
                        auto index=action-static_cast<std::size_t>(RouteAction::vless);
                        if (!session.tunnel_factories || index>=session.tunnel_factories->size()) co_return 1;
                        timeout_ms=(*session.tunnel_factories)[index].timeout_ms;
                        remote_domain=(*session.tunnel_factories)[index].remote_domain_dial;
                    }
                } else if (session.tunnel_factories) {
                    for (auto const& factory:*session.tunnel_factories) timeout_ms=std::max(timeout_ms,factory.timeout_ms);
                }
                auto deadline=std::min(limit,session.started+std::chrono::milliseconds(timeout_ms));
                if (timeout_ms>10000)
                    session.handshake_deadline=std::max(session.handshake_deadline,deadline+std::chrono::seconds(1));
                if (Clock::now()>=deadline) co_return 6;
                if (remote_domain) {
                    std::array<io::endpoint, 1> placeholder{io::endpoint(io::ipv4_address::loopback(), request.port)};
                    auto classify = [&](io::endpoint const& destination) -> std::optional<TrafficRoute> {
                        return TrafficRoute{TrafficRouteMode::indexed, **preflight, {}, {}, traffic_endpoint(destination)};
                    };
                    co_return co_await dial_candidates(session, context, placeholder, limit, classify, first, first_sent, domain_name);
                }
                auto resolved=co_await resolve_destination(session,context,std::string(domain),request.port,deadline,
                    {.network=rules::Network::tcp,.source_port=source_port,.source_ip_bytes=source_ip});
                if (session.closed) co_return 1;
                if (!resolved) co_return resolved.error()==dns::detail::ResolveError::timeout ? 6 :
                    resolved.error()==dns::detail::ResolveError::policy_rejected ? 2 : 4;
                resolved_destinations=std::move(*resolved); destinations=resolved_destinations;
            } else if (request.address_type == 1) {
                io::ipv4_address::bytes_type raw{}; std::copy_n(request.address.begin(), 4, raw.begin());
                single_destination[0]=io::endpoint(io::ipv4_address(raw), request.port); destinations=single_destination;
            } else {
                io::ipv6_address::bytes_type raw{}; std::copy_n(request.address.begin(), 16, raw.begin());
                single_destination[0]=io::endpoint(io::ipv6_address(raw), request.port); destinations=single_destination;
            }
            auto classify = [&](io::endpoint const& destination) -> std::optional<TrafficRoute> {
                if (auto fast = policy.default_outbound_fast())
                    return TrafficRoute{TrafficRouteMode::indexed, *fast, {}, {}, traffic_endpoint(destination)};
                std::string ip_text; std::array<std::uint8_t, 16> raw_ip{};
                auto minput = session.ingress.apply(rules::MatchInput{.domain=domain_name,.port=request.port,
                    .network=rules::Network::tcp,.source_port=source_port,.source_ip_bytes=source_ip});
                if (!domain_name && policy.has_distribution()) {
                    ip_text = destination.address().to_string(); minput.ip = ip_text;
                } else if (auto const addr = destination.address(); addr.is_v4()) {
                    auto b = addr.to_v4().to_bytes(); std::copy_n(b.begin(), 4, raw_ip.begin());
                    minput.ip_bytes = std::span<std::uint8_t const>(raw_ip.data(), 4);
                } else {
                    auto b = addr.to_v6().to_bytes(); std::copy_n(b.begin(), 16, raw_ip.begin());
                    minput.ip_bytes = std::span<std::uint8_t const>(raw_ip.data(), 16);
                }
                session.fill_match_input(minput);
                auto matched=policy.match_with_rule(minput);
                if (!matched) return {};
                return TrafficRoute{TrafficRouteMode::indexed,matched->outbound,matched->rule,matched->predicate,traffic_endpoint(destination)};
            };
            co_return co_await dial_candidates(session,context,destinations,limit,classify,first,first_sent);
        }

        auto dial_route_candidates(Session& session,io::io_context& context,
            std::span<io::endpoint const> destinations,std::size_t action,Clock::time_point limit,
            std::span<std::uint8_t const> first,bool* first_sent,std::optional<std::size_t> rule,
            std::optional<std::string_view> tunnel_domain) -> capy::task<std::uint8_t> {
            auto classify=[action,rule](io::endpoint const& destination) -> std::optional<TrafficRoute> {
                return TrafficRoute{TrafficRouteMode::ordered,action,rule,{},traffic_endpoint(destination)};
            };
            co_return co_await dial_candidates(session,context,destinations,limit,classify,first,first_sent,tunnel_domain);
        }

        // These ordinary functions return the selected operation directly;
        // no forwarding coroutine, extra heap owner, or Session field.
        auto dial_destination(Session& session,io::io_context& context,rules::RouteMatcher const& policy,
            socks5::Request const& request,Clock::time_point limit) -> capy::task<std::uint8_t> {
            return dial_selected_destination(session,context,policy,request,limit,SocketRoutingSource{});
        }
        auto dial_destination(Session& session,io::io_context& context,rules::RouteMatcher const& policy,
            socks5::Request const& request,net::UdpEndpoint const& source,Clock::time_point limit) -> capy::task<std::uint8_t> {
            return dial_selected_destination(session,context,policy,request,limit,DatagramRoutingSource{source});
        }

        // Error readiness does not consume pipelined bytes or confuse a normal
        // write-side EOF with a reset. It is best effort: an error occurring
        // before registration may be missed by the underlying backend.
        auto watch_client_error(Session& session) -> capy::task<capy::results<>> {
#ifdef NEXUS_TEST_FAKEIP
            struct WatchGuard { ~WatchGuard() { nexus_test_fakeip_watcher_done(); } } guard;
#endif
            try {
                auto [error]=co_await session.client.wait(io::wait_type::error);
                // Corosio consumes SO_ERROR and returns it; EIO can also mean a
                // harmless hangup with no socket error, including half-close.
                if (!session.closed && error && error!=std::errc::io_error && error!=capy::cond::canceled)
                    session.close();
                co_return capy::results<>{};
            } catch (...) { session.close(); throw; }
        }
    namespace {
        auto dial_branch(Session& session, io::io_context& context,
                         rules::RouteMatcher const& policy, socks5::Request const& request,Clock::time_point limit,
                         std::span<std::uint8_t const> first,bool* first_sent)
            -> capy::task<capy::results<std::uint8_t>> {
            auto code=co_await dial_selected_destination(session,context,policy,request,limit,SocketRoutingSource{},first,first_sent);
            // The join treats this private completion signal as a stop request
            // for the error watcher, while retaining the actual SOCKS code.
            co_return capy::results<std::uint8_t>{std::make_error_code(std::errc::operation_canceled),code};
        }
    }

    auto dial(Session& session, io::io_context& context,
              rules::RouteMatcher const& policy, socks5::Request const& request,Clock::time_point limit,
              std::span<std::uint8_t const> first,bool* first_sent) -> capy::task<std::uint8_t> {
#if !defined(NEXUS_TEST_FAKEIP)
        // Fast direct single-IP connect: skips when_all(watch_client_error), range-connect coro, and redundant timer.
        if ((request.address_type == 1 || request.address_type == 4) &&
#ifdef NEXUS_ENABLE_FAKEIP
            !session.fakeip &&
#endif
            !session.direct_tcp_options && !policy.needs_source() &&
            policy.default_outbound_fast() == static_cast<std::size_t>(RouteAction::direct)) {
            if (session.closed) co_return 1;
            io::endpoint ep;
            if (request.address_type == 1) {
                io::ipv4_address::bytes_type raw{}; std::copy_n(request.address.begin(), 4, raw.begin());
                ep = io::endpoint(io::ipv4_address(raw), request.port);
            } else {
                io::ipv6_address::bytes_type raw{}; std::copy_n(request.address.begin(), 16, raw.begin());
                ep = io::endpoint(io::ipv6_address(raw), request.port);
            }
            if (!valid_destination(ep)) co_return 4;
            auto const dl = std::min(limit, session.started + std::chrono::milliseconds(session.direct_connect_timeout_ms));
            if (session.direct_connect_timeout_ms > 10000)
                session.handshake_deadline = std::max(session.handshake_deadline, dl + std::chrono::seconds(1));
            if (Clock::now() >= dl) co_return 6;
            auto [err] = (dl < session.handshake_deadline || !session.registry || session.transport_owner != nullptr)
                ? co_await corosio::timeout(session.target.connect(ep), dl)
                : co_await session.target.connect(ep);
            if (session.closed) { session.target.close(); co_return 1; }
            if (err) { session.target.close(); co_return failure_code(err); }
            session.record_traffic_route({TrafficRouteMode::indexed, 0, {}, {}, traffic_endpoint(ep)}, ConnectPath::direct);
            co_return 0;
        }
#endif
        auto [signal,code,watch_result]=co_await capy::when_all(
            dial_branch(session,context,policy,request,limit,first,first_sent),watch_client_error(session));
        (void)signal; (void)watch_result;
        co_return session.closed ? 1 : code;
    }

}
