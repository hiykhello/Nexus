module proxy;
import std;
import sniff.tcp;
import sniff.tcp_io;
import sniff.route_tcp;
import platform.ip_address;
import net.ordered_datagram;
import dns.message;
import dns.input_budget;
import dns.message_program;
import dns.local_config;
import proxy.dns_state;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import sniff.udp_quic;
import tls.record_fragment;

namespace proxy {
#include "redirect_tcp_dns.hpp"
    auto resolve_route_action(Session& session,nex::corosio::io_context& context,rules::ProgramCursor& cursor,rules::ProgramStep step,
        rules::ProgramInput& input,sniff::RouteCandidates& candidates,std::vector<nex::corosio::endpoint>& endpoints,Clock::time_point deadline)
        -> nex::capy::task<std::expected<void,RouteResolveFailure>> {
        std::optional<platform::IpAddress> source;
        auto source_bytes=input.source_ip_bytes;
        if(input.source_ip) {
            if(source_bytes || !(source=platform::parse_ip_address(*input.source_ip)))
                co_return std::unexpected(RouteResolveFailure{sniff::RouteResolveError::state,{}});
            source_bytes=source->view();
        }
        struct Resolver {
            Session& session;nex::corosio::io_context& context;policy::DnsContext dns;
            std::optional<dns::detail::ResolveError> failure;
            auto operator()(std::string_view name,std::uint16_t port,Clock::time_point limit)
                -> nex::capy::task<std::expected<std::vector<nex::corosio::endpoint>,dns::detail::ResolveError>> {
                auto result=co_await resolve_destination(session,context,std::string(name),port,limit,dns);
                if(!result)failure=result.error();
                co_return result;
            }
        } resolver{session,context,{.network=input.network,.source_port=input.source_port,.source_ip_bytes=source_bytes}};
        auto result=co_await sniff::resolve_tcp_action(cursor,step,input,candidates,endpoints,resolver,deadline);
        if(!result)co_return std::unexpected(RouteResolveFailure{result.error(),resolver.failure});
        co_return std::expected<void,RouteResolveFailure>{};
    }
    namespace {
        auto apply_direct_shaping(Session& session,rules::ProgramAction const& action) noexcept -> void {
            if (action.tls_record_fragment) {
                session.direct_shaping.tls_record_fragment=true;
                if (action.tls_fragment_min) session.direct_shaping.tls_fragment_min=action.tls_fragment_min;
                if (action.tls_fragment_max) session.direct_shaping.tls_fragment_max=action.tls_fragment_max;
            }
            if (action.tcp_prefix_len) {
                session.direct_shaping.tcp_prefix=action.tcp_prefix;
                session.direct_shaping.tcp_prefix_len=action.tcp_prefix_len;
            }
        }
    }

    auto shape_direct_first_payload(Session& session,std::span<std::uint8_t const> input)
        -> std::optional<std::vector<std::uint8_t>> {
        if (session.tunnel || !session.direct_shaping.pending() || input.empty()) return std::nullopt;
        session.direct_shaping.applied=true;
        std::vector<std::uint8_t> out;
        auto const& sh=session.direct_shaping;
        if (sh.tcp_prefix_len)
            out.insert(out.end(),sh.tcp_prefix.begin(),sh.tcp_prefix.begin()+sh.tcp_prefix_len);
        if (sh.tls_record_fragment) {
            auto seed=static_cast<std::uint64_t>(session.started.time_since_epoch().count())^0x9e3779b97f4a7c15ULL;
            auto frag=tls::fragment_tls_client_hello(input,
                sh.tls_fragment_min ? sh.tls_fragment_min : 16,
                sh.tls_fragment_max ? sh.tls_fragment_max : 64,seed);
            out.insert(out.end(),frag.begin(),frag.end());
        } else {
            out.insert(out.end(),input.begin(),input.end());
        }
        return out;
    }

    auto replay_shaped_direct(Session& session,std::span<std::uint8_t const> head,
        std::span<std::uint8_t const> tail,Clock::time_point deadline) -> nex::capy::task<bool> {
        std::vector<std::uint8_t> combined;
        combined.reserve(head.size()+tail.size());
        combined.insert(combined.end(),head.begin(),head.end());
        combined.insert(combined.end(),tail.begin(),tail.end());
        auto shaped=shape_direct_first_payload(session,combined);
        auto bytes=shaped ? std::span<std::uint8_t const>(*shaped) : std::span<std::uint8_t const>(combined);
        sniff::TcpReplay replay(bytes);
        co_return co_await replay_ordered_tcp(session,replay,deadline);
    }

    auto execute_ordered_tcp(Session& session,nex::corosio::io_context& context,rules::RouteProgram const& program,
        rules::ProgramCursor& cursor,rules::ProgramInput& input,sniff::TcpSniffer& sniffer,
        sniff::RouteCandidates& candidates,std::vector<nex::corosio::endpoint>& endpoints,
        std::size_t fallback,Clock::time_point sniff_deadline,Clock::time_point deadline,sniff::UnknownRoutePolicy unknown_policy,
        void* reader_context,nex::capy::task<sniff::TcpReadResult> (*reader)(void*,sniff::TcpSniffer&,Clock::time_point),
        std::optional<std::span<std::uint8_t const>> first_override)
        -> nex::capy::task<OrderedTcpResult> {
        using Stop=sniff::RouteTcpStop;
        if(session.closed || !input.network || *input.network!=rules::Network::tcp || !input.port || !*input.port)
            co_return OrderedTcpResult{Stop::state_error};
        sniff_deadline=std::min(sniff_deadline,deadline);
        std::size_t selected=fallback;
        std::optional<std::size_t> route_rule;
        bool route_only=false;
        for (;;) {
            if(session.closed)co_return OrderedTcpResult{Stop::canceled};
            if(Clock::now()>=deadline)co_return OrderedTcpResult{Stop::io_error,6};
            auto read=[&](sniff::TcpSniffer& target,Clock::time_point limit) {
                return reader ? reader(reader_context,target,limit) : sniff::read_tcp_sniff(session.client,target,limit);
            };
            auto result=co_await sniff::run_tcp_route_with_reader(program,cursor,input,sniffer,read,sniff_deadline,true,unknown_policy);
            if(session.closed)co_return OrderedTcpResult{Stop::canceled};
            if(result.stop==Stop::options) {
                auto const& step=*result.step;
                if (auto timeout=step.action.connect_timeout_ms) {
                    deadline=std::min(deadline,session.started+std::chrono::milliseconds(timeout));
                    sniff_deadline=std::min(sniff_deadline,deadline);
                }
                apply_direct_shaping(session,step.action);
                if(!cursor.complete(step))co_return OrderedTcpResult{Stop::state_error};
                continue;
            }
            if(result.stop==Stop::resolve) {
                auto resolved=co_await resolve_route_action(session,context,cursor,*result.step,input,candidates,endpoints,deadline);
                if(!resolved) {
                    auto error=resolved.error();
                    auto code=error.action==sniff::RouteResolveError::deadline ||
                        (error.dns && *error.dns==dns::detail::ResolveError::timeout) ? 6 :
                        error.dns && *error.dns==dns::detail::ResolveError::policy_rejected ? 2 :
                        error.dns ? 4 : 1;
                    co_return OrderedTcpResult{Stop::io_error,static_cast<std::uint8_t>(code),error.dns};
                }
                route_only=result.step->action.route_only;
                continue;
            }
            if(result.stop==Stop::terminal) {
                if(result.step->action.kind==rules::ProgramActionKind::reject) {
                    bool drop=global_reject_storm_guard().should_drop(
                        result.step->action.reject_method,result.step->action.reject_no_drop);
                    co_return OrderedTcpResult{.stop=Stop::terminal,.code=2,.reject_drop=drop};
                }
                if (auto timeout=result.step->action.connect_timeout_ms)
                    deadline=std::min(deadline,session.started+std::chrono::milliseconds(timeout));
                if (Clock::now()>=deadline) co_return OrderedTcpResult{Stop::io_error,6};
                if (result.step->action.kind==rules::ProgramActionKind::hijack_dns)
                    co_return OrderedTcpResult{.stop=Stop::terminal,.code=0,.deadline=deadline,.dns_hijacked=true};
                apply_direct_shaping(session,result.step->action);
                selected=result.step->action.outbound;
                route_rule=result.step->rule_index;
                break;
            }
            if(result.stop==Stop::exhausted)break;
            co_return OrderedTcpResult{result.stop,1,{},std::move(result.rule_error),result.system};
        }
        auto domain=input.fakeip_domain ? input.fakeip_domain : input.explicit_domain;
        if (session.route_snapshot)
            selected=session.route_snapshot->matcher.choose_outbound(selected,domain.value_or(input.ip.value_or("")));
        if(selected==static_cast<std::size_t>(RouteAction::block))co_return OrderedTcpResult{Stop::terminal,2};
        if(!candidates.view() && domain) {
            if(input.ip || !endpoints.empty())co_return OrderedTcpResult{Stop::state_error};
            std::optional<platform::IpAddress> source;
            auto source_bytes=input.source_ip_bytes;
            if(input.source_ip) {
                if(source_bytes || !(source=platform::parse_ip_address(*input.source_ip)))
                    co_return OrderedTcpResult{Stop::state_error};
                source_bytes=source->view();
            }
            auto resolved=co_await resolve_destination(session,context,std::string(*domain),*input.port,deadline,
                {.network=input.network,.source_port=input.source_port,.source_ip_bytes=source_bytes});
            if(!resolved) {
                auto error=resolved.error();
                auto code=error==dns::detail::ResolveError::timeout ? 6 :
                    error==dns::detail::ResolveError::policy_rejected ? 2 : 4;
                co_return OrderedTcpResult{Stop::io_error,static_cast<std::uint8_t>(code),error};
            }
            if(session.closed)co_return OrderedTcpResult{Stop::canceled};
            if(!candidates.assign(*resolved,input))co_return OrderedTcpResult{Stop::state_error};
            endpoints=std::move(*resolved);
        }
        bool first_sent=false;
        auto first=first_override ? *first_override : sniffer.wire();
        // Recover pre-read bytes through the metered replay rather than the
        // direct Fast Open path, which cannot wait on the user budget.
        if (session.meters_principal_bytes() || session.direct_shaping.pending()) first={};
        auto code=co_await dial_route_candidates(session,context,endpoints,selected,deadline,first,&first_sent,route_rule,route_only ? domain : std::nullopt);
        if(session.closed)co_return OrderedTcpResult{Stop::canceled};
        co_return OrderedTcpResult{.stop=Stop::terminal,.code=code,.first_sent=first_sent,.deadline=deadline};
    }

    auto route_ordered_stream_tcp(Session& session,nex::corosio::io_context& context,socks5::Request const& request,void* client,
        nex::capy::task<sniff::TcpReadResult> (*reader)(void*,sniff::TcpSniffer&,Clock::time_point)) -> nex::capy::task<bool> {
        auto result=co_await route_ordered_stream_tcp(session,context,request,client,reader,nullptr);
        co_return result==OrderedStreamResult::connected;
    }

    auto route_ordered_stream_tcp(Session& session,nex::corosio::io_context& context,socks5::Request const& request,void* client,
        nex::capy::task<sniff::TcpReadResult> (*reader)(void*,sniff::TcpSniffer&,Clock::time_point),TcpDnsHandler dns)
        -> nex::capy::task<OrderedStreamResult> {
        using Result=OrderedStreamResult;
        OrderedTcpRequest owner;
        if (!owner.prepare(session,request)) co_return Result::rejected;
        owner.input.dns_hijack_tcp=dns!=nullptr;
        std::array<std::uint8_t,16384> wire,scratch;
        sniff::TcpSniffer sniffer(wire,scratch);
        rules::ProgramCursor cursor;
        auto const& policy=*session.ordered_tcp;
        auto result=co_await execute_ordered_tcp(session,context,policy.program,cursor,owner.input,sniffer,
            owner.candidates,owner.endpoints,policy.fallback,Clock::now()+policy.sniff_timeout,
            session.handshake_deadline,policy.unknown_policy,client,reader);
        if (result.code || session.closed) co_return result.reject_drop ? Result::rejected_drop : Result::rejected;
        if (result.dns_hijacked) {
            auto handled=co_await dns(client,sniffer.wire(),result.deadline);
            co_return handled ? Result::dns_handled : Result::rejected;
        }
        if (result.first_sent || sniffer.wire().empty()) co_return Result::connected;
        if (!session.tunnel && session.direct_shaping.pending()) {
            auto replayed=co_await replay_shaped_direct(session,sniffer.wire(),{},result.deadline);
            co_return replayed ? Result::connected : Result::rejected;
        }
        sniff::TcpReplay replay(sniffer.wire());
        auto replayed=co_await replay_ordered_tcp(session,replay,result.deadline);
        co_return replayed ? Result::connected : Result::rejected;
    }

    auto write_principal_payload(Session& session,bool upstream,std::span<std::uint8_t const> pending)
        -> nex::capy::task<bool> {
        auto& socket=upstream ? session.target : session.client;
        while (!pending.empty() && !session.closed) {
            auto credit=co_await session.reserve_principal_stream(upstream,pending.size());
            if (!credit) {session.close();co_return false;}
            auto output=pending.first(credit->size());
            std::size_t written=output.size();
            credit->submit();
            if (upstream && session.tunnel) {
                if (!co_await session.tunnel->send(output)) co_return false;
            } else {
                auto [error,n]=co_await socket.write_some(nex::capy::const_buffer(output.data(),output.size()));
                if (n>output.size()) co_return false;
                if (error || !n) {
                    credit->complete(n);
                    if (n) session.count_traffic(upstream,n);
                    co_return false;
                }
                written=n;
            }
            credit->complete(written);
            session.count_traffic(upstream,written);
            session.touched=Clock::now();
            pending=pending.subspan(written);
        }
        co_return pending.empty() && !session.closed;
    }

    auto replay_ordered_tcp(Session& session,sniff::TcpReplay& replay,Clock::time_point deadline)
        -> nex::capy::task<bool> {
        if(session.closed)co_return false;
        bool sent=false;
        if (session.meters_principal_bytes()) {
            auto write=[&](std::span<std::uint8_t const> bytes) -> nex::capy::task<nex::capy::results<>> {
                if (co_await write_principal_payload(session,true,bytes)) co_return nex::capy::results<>{};
                co_return nex::capy::results<>{std::make_error_code(std::errc::io_error)};
            };
            sent=co_await replay.send_all(write,deadline);
        } else if(session.tunnel) {
            auto write=[&](std::span<std::uint8_t const> bytes) -> nex::capy::task<nex::capy::results<>> {
                if(!co_await session.tunnel->send(bytes))
                    co_return nex::capy::results<>{std::make_error_code(std::errc::io_error)};
                session.count_traffic(true,bytes.size());
                co_return nex::capy::results<>{};
            };
            sent=co_await replay.send_all(write,deadline);
        } else {
            sent=co_await replay.send(session.target,deadline);
            session.count_traffic(true,replay.committed());
        }
        if(!sent || session.closed) {session.close();co_return false;}
        session.touched=Clock::now();
        co_return true;
    }

    auto hijack_dns_query(Session& session,nex::corosio::io_context& context,std::span<std::uint8_t const> payload,
        net::UdpEndpoint source,Clock::time_point deadline,rules::Network network)
        -> nex::capy::task<std::optional<std::vector<std::uint8_t>>> {
        if(!session.dns || !session.local_dns || session.closed || session.cancel_dns || Clock::now()>=deadline)
            co_return std::nullopt;
        std::optional<dns::InputBudget::Lease> reservation;
        auto query=dns::parse_query(payload);
        if (!query) {
            if (network==rules::Network::tcp) co_return dns::query_error_response(payload);
            co_return std::nullopt;
        }
        if (network==rules::Network::tcp) {
            auto cost=dns::listener_query_cost(*query);
            if (!cost) co_return std::nullopt;
            reservation=dns::default_listener_query_budget().acquire(*cost);
            if (!reservation) co_return std::nullopt;
        }
        auto& state=*session.dns;
        dns::MessageLocalSource local(session.local_dns->source);
        std::vector<dns::MessageUpstream> upstreams;
        upstreams.reserve(state.routing.servers.size());
        auto* transports=session.dns_transports();
        for(std::size_t i=0;i<state.routing.servers.size();++i) {
            auto const& server=state.routing.servers[i];
            dns::MessageUpstream upstream{.tcp=server.tcp,.host=server.host,.port=server.port,.resolver=server.resolver,.protection=transports ? transports->queries[i] : server.protection};
            if(!server.port)upstream.local=&local;
            else if(server.host.empty())upstream.endpoint=state.endpoint(i);
            upstreams.push_back(std::move(upstream));
        }
        auto view=session.route_snapshot && session.route_snapshot->dns ?
            session.route_snapshot->dns->view : std::nullopt;
        dns::MessageProgram program(context,session.dns_rules(),upstreams,state.routing.final,
            state.wire_cache(),state.routing.disable_cache,{},nullptr,view,session.reverse_cache);
        struct CancelRegistration {
            Session& session;
            ~CancelRegistration(){session.dns_operation=nullptr;session.cancel_dns=nullptr;}
        } registration{session};
        session.dns_operation=&program;
        session.cancel_dns=[](void* operation) noexcept {static_cast<dns::MessageProgram*>(operation)->cancel();};
        auto response=co_await program.run(*query,deadline,{.network=network,
            .source_port=source.port,.source_ip_bytes=std::span(source.address).first(source.family==4 ? 4 : 16),
            .inbound=session.inbound,.auth_user=session.auth_user,.source_interface=session.source_interface});
        if(session.closed || Clock::now()>=deadline)co_return std::nullopt;
        if(!response) {
            using Error=dns::detail::ResolveError;
            auto error=response.error();
            if(error==Error::canceled || error==Error::policy_dropped)co_return std::nullopt;
            policy::PredefinedResponse failure;
            failure.rcode=error==Error::invalid_request ? 1 : error==Error::policy_rejected || error==Error::refused ? 5 : 2;
            auto wire=dns::synthetic_message(*query,failure);
            if(!wire)co_return std::nullopt;
            response=std::move(*wire);
        }
        if (network==rules::Network::tcp) co_return std::move(*response);
        co_return dns::udp_response_fits(*query,std::move(*response));
    }

    auto ordered_datagram_router(Session& session,nex::corosio::io_context& context,std::optional<net::UdpEndpoint> source,
        std::optional<bool> fakeip_alias)
        -> net::stream_datagrams::OrderedRouter {
        return [&session,&context,source,fakeip_alias](net::ProxyAddress const& target,std::span<std::uint8_t const> payload,Clock::time_point received,
            Clock::time_point& deadline,net::stream_datagrams::OrderedSniffer const& inspect)
            -> nex::capy::task<std::optional<net::stream_datagrams::OrderedSelection>> {
            if(session.closed || !session.ordered_tcp || !target.port || target.length>target.bytes.size())co_return std::nullopt;
            auto const& policy=*session.ordered_tcp;
            rules::ProgramInput input{.port=target.port,.network=rules::Network::udp,.inbound=session.inbound,.auth_user=session.auth_user};
            input.source_interface=session.source_interface;
            if (policy.program.has_dns_hijack()) input.dns_query=dns::parse_query(payload).has_value();
            input=session.ingress.apply(input);
            if (fakeip_alias==false)
                input.domain_absent[static_cast<std::size_t>(rules::DomainSource::fakeip)]=true;
            if(source){input.source_port=source->port;input.source_ip_bytes=std::span(source->address).first(source->family==4 ? 4 : 16);}
            std::string address,sniffed;std::optional<dns::ReverseName> reverse_name;std::vector<nex::corosio::endpoint> endpoints;sniff::RouteCandidates candidates;
            if(target.family==net::ProxyAddressFamily::domain) {
                address.assign(reinterpret_cast<char const*>(target.bytes.data()),target.length);
                if (fakeip_alias==true) {
                    input.fakeip_domain=address;
                    input.domain_absent[static_cast<std::size_t>(rules::DomainSource::explicit_target)]=true;
                } else input.explicit_domain=address;
                input.domain_absent[static_cast<std::size_t>(rules::DomainSource::reverse_dns)]=true;
            } else {
                nex::corosio::endpoint endpoint;
                dns::Address rev_addr{};
                if(target.family==net::ProxyAddressFamily::ipv4 && target.length==4) {
                    nex::corosio::ipv4_address::bytes_type bytes{};std::copy_n(target.bytes.begin(),4,bytes.begin());endpoint={nex::corosio::ipv4_address(bytes),target.port};
                    rev_addr.size=4;std::copy_n(bytes.begin(),4,rev_addr.bytes.begin());
                } else if(target.family==net::ProxyAddressFamily::ipv6 && target.length==16) {
                    nex::corosio::ipv6_address::bytes_type bytes{};std::copy_n(target.bytes.begin(),16,bytes.begin());endpoint={nex::corosio::ipv6_address(bytes),target.port};
                    rev_addr.size=16;std::copy_n(bytes.begin(),16,rev_addr.bytes.begin());
                } else co_return std::nullopt;
                address=endpoint.address().to_string();input.ip=address;endpoints.push_back(endpoint);
                input.domain_absent[static_cast<std::size_t>(rules::DomainSource::explicit_target)]=true;
                if (session.reverse_cache) {
                    auto now_ms=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                        Clock::now().time_since_epoch()).count());
                    if (auto found=session.reverse_cache->lookup(session.reverse_view,rev_addr,now_ms)) {
                        reverse_name=*found;input.reverse_domain=reverse_name->view();
                    } else input.domain_absent[static_cast<std::size_t>(rules::DomainSource::reverse_dns)]=true;
                } else input.domain_absent[static_cast<std::size_t>(rules::DomainSource::reverse_dns)]=true;
            }
            auto domain=input.fakeip_domain ? input.fakeip_domain : input.explicit_domain;
            auto resolve=[&]() -> nex::capy::task<bool> {
                if(!domain)co_return true;
                policy::DnsContext dns{.network=rules::Network::udp};
                if(source){dns.source_port=source->port;dns.source_ip_bytes=std::span(source->address).first(source->family==4 ? 4 : 16);}
                auto result=co_await resolve_destination(session,context,std::string(*domain),target.port,deadline,dns);
                if(!result || session.closed || Clock::now()>=deadline || !candidates.assign(*result,input))co_return false;
                endpoints=std::move(*result);co_return true;
            };
            rules::ProgramCursor cursor;
            std::size_t selected=policy.fallback;
            std::optional<std::size_t> route_rule;
            for(;;) {
                auto step=cursor.poll(policy.program,input);if(!step)co_return std::nullopt;
                if(step->kind==rules::ProgramPreflightKind::uncertain) {
                    if(policy.unknown_policy!=sniff::UnknownRoutePolicy::skip || !cursor.skip_unknown(step->rule_index))co_return std::nullopt;
                    continue;
                }
                if(step->kind==rules::ProgramPreflightKind::exhausted)break;
                auto action=*step->step;
                if(action.action.kind==rules::ProgramActionKind::reject)co_return std::nullopt;
                if(auto timeout=action.action.connect_timeout_ms) {
                    deadline=std::min(deadline,received+std::chrono::milliseconds(timeout));
                    if (Clock::now()>=deadline) co_return std::nullopt;
                }
                if (action.action.kind==rules::ProgramActionKind::hijack_dns) {
                    if (!source || fakeip_alias==true) co_return std::nullopt;
                    auto credit=session.reserve_principal_datagram(true,payload.size());
                    if (!credit) co_return std::nullopt;
                    credit->submit();
                    auto reply=co_await hijack_dns_query(session,context,payload,*source,deadline);
                    credit->complete(payload.size());
                    if (!reply) co_return std::nullopt;
                    session.count_traffic(true,payload.size());
                    co_return net::stream_datagrams::OrderedSelection{.outbound=0,.rule=action.rule_index,
                        .dns_reply=std::move(reply)};
                }
                if (action.action.kind==rules::ProgramActionKind::route) {
                    selected=action.action.outbound;
                    route_rule=action.rule_index;
                    break;
                }
                if(action.action.kind==rules::ProgramActionKind::route_options) {
                    if(!cursor.complete(action))co_return std::nullopt;
                } else if(action.action.kind==rules::ProgramActionKind::resolve) {
                    if(!co_await resolve() || !cursor.complete(action))co_return std::nullopt;
                } else if(action.action.kind==rules::ProgramActionKind::sniff) {
                    auto query=dns::parse_query(payload);input.sniffed_domain.reset();
                    if(query) {
                        input.protocol=rules::Protocol::dns;
                        if(rules::valid_domain(query->question.name)) {
                            sniffed=std::move(query->question.name);input.sniffed_domain=sniffed;
                        }
                    } else if(sniff::stun_datagram(payload)) {
                        input.protocol=rules::Protocol::stun;
                        input.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)]=true;
                    } else {
                        auto quic=co_await inspect(std::min(deadline,Clock::now()+policy.sniff_timeout));
                        if (quic.status==sniff::QuicProbeStatus::matched) {
                            input.protocol=rules::Protocol::quic;
                            if (quic.domain) {
                                sniffed=std::move(*quic.domain);input.sniffed_domain=sniffed;
                            }
                        }
                    }
                    if(!cursor.complete(action))co_return std::nullopt;
                } else co_return std::nullopt;
                if(session.closed || Clock::now()>=deadline)co_return std::nullopt;
            }
            if (session.route_snapshot)
                selected=session.route_snapshot->matcher.choose_outbound(selected,domain.value_or(input.ip.value_or("")));
            if(selected==1)co_return std::nullopt;
            if(domain && !candidates.view() && !co_await resolve())co_return std::nullopt;
            net::stream_datagrams::OrderedSelection result{selected,{},route_rule};
            for(auto const& endpoint:endpoints) {
                if(endpoint.address().is_v6() && endpoint.address().to_v6().scope_id())continue;
                net::UdpEndpoint peer{endpoint.address().is_v4() ? std::uint8_t{4} : std::uint8_t{6},{},endpoint.port()};
                if(peer.family==4){auto bytes=endpoint.address().to_v4().to_bytes();std::ranges::copy(bytes,peer.address.begin());}
                else {auto bytes=endpoint.address().to_v6().to_bytes();std::ranges::copy(bytes,peer.address.begin());}
                result.candidates.push_back(peer);
            }
            co_return result;
        };
    }

}
