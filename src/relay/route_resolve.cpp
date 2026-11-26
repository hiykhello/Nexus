module relay;
import :dns_internal;
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
import relay.dns_state;
import capy;
import corosio;
import sniff.udp_quic;
import tls.record_fragment;

namespace relay {
    auto resolve_route_action(Session& session,corosio::io_context& context,rules::ProgramCursor& cursor,rules::ProgramStep step,
        rules::ProgramInput& input,sniff::RouteCandidates& candidates,std::vector<corosio::endpoint>& endpoints,Clock::time_point deadline)
        -> capy::task<std::expected<void,RouteResolveFailure>> {
        std::optional<platform::IpAddress> source;
        auto source_bytes=input.source_ip_bytes;
        if(input.source_ip) {
            if(source_bytes || !(source=platform::parse_ip_address(*input.source_ip)))
                co_return std::unexpected(RouteResolveFailure{sniff::RouteResolveError::state,{}});
            source_bytes=source->view();
        }
        struct Resolver {
            Session& session;corosio::io_context& context;policy::DnsContext dns;ResolveOverride ov;
            std::optional<dns::detail::ResolveError> failure;
            auto operator()(std::string_view name,std::uint16_t port,Clock::time_point limit)
                -> capy::task<std::expected<std::vector<corosio::endpoint>,dns::detail::ResolveError>> {
                auto result=co_await resolve_destination(session,context,std::string(name),port,limit,dns,ov);
                if(!result)failure=result.error();
                co_return result;
            }
        };
        policy::DnsContext dns_ctx{.network=input.network,.source_port=input.source_port,.source_ip_bytes=source_bytes,.client=input.client};
        session.fill_dns_context(dns_ctx);
        ResolveOverride ov{step.action.resolve_strategy,step.action.resolve_server,
            step.action.resolve_disable_cache,step.action.resolve_rewrite_ttl};
        if (step.action.resolve_client_subnet) {
            auto const& s=*step.action.resolve_client_subnet;
            ov.client_subnet=dns::ClientSubnet{static_cast<std::uint16_t>(s.size==4 ? 1 : 2),s.bits,s.address};
        }
        Resolver resolver{session,context,dns_ctx,ov,{}};
        auto result=co_await sniff::resolve_tcp_action(cursor,step,input,candidates,endpoints,resolver,deadline);
        if(!result)co_return std::unexpected(RouteResolveFailure{result.error(),resolver.failure});
        co_return std::expected<void,RouteResolveFailure>{};
    }
    namespace {
        auto apply_direct_shaping(Session& session,rules::ProgramAction const& action) -> void {
            if (!action.tls_record_fragment && !action.tcp_prefix_len &&
                !action.override_address && !action.override_port) return;
            auto& ex=session.ensure_mutable_extras();
            if (action.tls_record_fragment) {
                ex.direct_shaping.tls_record_fragment=true;
                if (action.tls_fragment_min) ex.direct_shaping.tls_fragment_min=action.tls_fragment_min;
                if (action.tls_fragment_max) ex.direct_shaping.tls_fragment_max=action.tls_fragment_max;
                if (action.tls_fragment_fallback_delay_ms)
                    ex.direct_shaping.tls_fragment_fallback_delay_ms=action.tls_fragment_fallback_delay_ms;
            }
            if (action.tcp_prefix_len) {
                ex.direct_shaping.tcp_prefix=action.tcp_prefix;
                ex.direct_shaping.tcp_prefix_len=action.tcp_prefix_len;
            }
            if (action.override_address) ex.route_override_address=action.override_address;
            if (action.override_port) ex.route_override_port=action.override_port;
        }
    }

    auto shape_direct_first_payload(Session& session,std::span<std::uint8_t const> input)
        -> std::optional<std::vector<std::uint8_t>> {
        if (session.tunnel || !session.direct_shaping_pending() || input.empty()) return std::nullopt;
        auto& sh=session.ensure_mutable_extras().direct_shaping;
        sh.applied=true;
        std::vector<std::uint8_t> out;
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
        std::span<std::uint8_t const> tail,Clock::time_point deadline) -> capy::task<bool> {
        std::vector<std::uint8_t> combined;
        combined.reserve(head.size()+tail.size());
        combined.insert(combined.end(),head.begin(),head.end());
        combined.insert(combined.end(),tail.begin(),tail.end());
        auto shaped=shape_direct_first_payload(session,combined);
        auto bytes=shaped ? std::span<std::uint8_t const>(*shaped) : std::span<std::uint8_t const>(combined);
        auto const* sh=session.direct_shaping_ptr();
        std::size_t const prefix_len=(shaped && sh) ? std::min<std::size_t>(sh->tcp_prefix_len,bytes.size()) : 0u;
        if (!session.tunnel && shaped && sh && sh->tls_record_fragment) {
            auto const fallback_delay_ms=sh->tls_fragment_fallback_delay_ms;
            auto payload=bytes;
            if (prefix_len) {
                sniff::TcpReplay prefix_replay(bytes.first(prefix_len));
                if (!co_await replay_ordered_tcp(session,prefix_replay,deadline)) co_return false;
                payload=bytes.subspan(prefix_len);
            }
            if (fallback_delay_ms && payload.size()>=5 &&
                payload[0]==0x16 && payload[1]==0x03) {
                auto rec0=std::size_t{5}+((std::size_t{payload[3]}<<8)|payload[4]);
                if (rec0<payload.size()) {
                    sniff::TcpReplay first_rec(payload.first(rec0));
                    if (!co_await replay_ordered_tcp(session,first_rec,deadline)) co_return false;
                    auto rem=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-Clock::now());
                    if (rem<=std::chrono::milliseconds::zero()) { session.close(); co_return false; }
                    auto pause=std::min<std::chrono::milliseconds>(
                        std::chrono::milliseconds(fallback_delay_ms),rem);
                    auto [delay_err]=co_await corosio::delay(pause);
                    if (delay_err || session.closed || Clock::now()>=deadline) { session.close(); co_return false; }
                    sniff::TcpReplay rest_recs(payload.subspan(rec0));
                    co_return co_await replay_ordered_tcp(session,rest_recs,deadline);
                }
            }
            sniff::TcpReplay replay(payload);
            co_return co_await replay_ordered_tcp(session,replay,deadline);
        }
        sniff::TcpReplay replay(bytes);
        co_return co_await replay_ordered_tcp(session,replay,deadline);
    }

    auto execute_ordered_tcp(Session& session,corosio::io_context& context,rules::RouteProgram const& program,
        rules::ProgramCursor& cursor,rules::ProgramInput& input,sniff::TcpSniffer& sniffer,
        sniff::RouteCandidates& candidates,std::vector<corosio::endpoint>& endpoints,
        std::size_t fallback,Clock::time_point sniff_deadline,Clock::time_point deadline,sniff::UnknownRoutePolicy unknown_policy,
        void* reader_context,capy::task<sniff::TcpReadResult> (*reader)(void*,sniff::TcpSniffer&,Clock::time_point),
        std::optional<std::span<std::uint8_t const>> first_override)
        -> capy::task<OrderedTcpResult> {
        using Stop=sniff::RouteTcpStop;
        if(session.closed || !input.network || *input.network!=rules::Network::tcp || !input.port || !*input.port)
            co_return OrderedTcpResult{Stop::state_error};
        sniff_deadline=std::min(sniff_deadline,deadline);
        std::size_t selected=fallback;
        std::optional<std::size_t> route_rule;
        bool route_only=false, sniff_override_destination=false;
        input.route_mode=session.active_route_mode();
        if (input.route_mode==rules::RouteMode::rule || program.has_dns_hijack()) for (;;) {
            if(session.closed)co_return OrderedTcpResult{Stop::canceled};
            if(Clock::now()>=deadline)co_return OrderedTcpResult{Stop::io_error,6};
            auto read=[&](sniff::TcpSniffer& target,Clock::time_point limit) {
                return reader ? reader(reader_context,target,limit) : sniff::read_tcp_sniff(session.client,target,limit);
            };
            auto result=co_await sniff::run_tcp_route_with_reader(program,cursor,input,sniffer,read,sniff_deadline,true,unknown_policy);
            if(result.override_destination_with_sniff) sniff_override_destination=true;
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
                    if (input.route_mode!=rules::RouteMode::rule) break;
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
        auto const ov_addr=session.route_override_addr();
        auto const ov_port=session.route_override_port_val();
        auto overrode_ip=sniff_override_destination && input.sniffed_domain && !ov_addr;
        auto domain=overrode_ip ? input.sniffed_domain : (input.fakeip_domain ? input.fakeip_domain : input.explicit_domain);
        if (auto ov=session.mode_override_outbound(domain.value_or(input.ip.value_or("")))) {
            selected=*ov; route_rule.reset();
        } else if (session.route_snapshot)
            selected=session.route_snapshot->matcher.choose_outbound(selected,domain.value_or(input.ip.value_or("")));
        if(selected==static_cast<std::size_t>(RouteAction::block))co_return OrderedTcpResult{Stop::terminal,2};
        bool remote_domain = false;
        if (!ov_addr && domain && selected >= static_cast<std::size_t>(RouteAction::vless) &&
            session.tunnel_factories) {
            auto idx = selected - static_cast<std::size_t>(RouteAction::vless);
            if (idx < session.tunnel_factories->size() && (*session.tunnel_factories)[idx].remote_domain_dial) {
                remote_domain = true;
                endpoints = {corosio::endpoint(corosio::ipv4_address::loopback(),
                    ov_port ? ov_port : *input.port)};
            }
        }
        if(!remote_domain && !ov_addr && domain &&
           ((!candidates.view() && !overrode_ip) || (overrode_ip && (endpoints.empty() || selected<static_cast<std::size_t>(RouteAction::vless) || session.dns)))) {
            if(!overrode_ip && (input.ip || !endpoints.empty()))co_return OrderedTcpResult{Stop::state_error};
            std::optional<platform::IpAddress> source;
            auto source_bytes=input.source_ip_bytes;
            if(input.source_ip) {
                if(source_bytes || !(source=platform::parse_ip_address(*input.source_ip)))
                    co_return OrderedTcpResult{Stop::state_error};
                source_bytes=source->view();
            }
            policy::DnsContext dns_ctx{.network=input.network,.source_port=input.source_port,.source_ip_bytes=source_bytes,.client=input.client};
            session.fill_dns_context(dns_ctx);
            auto resolved=co_await resolve_destination(session,context,std::string(*domain),*input.port,deadline,dns_ctx);
            if(!resolved) {
                auto error=resolved.error();
                auto code=error==dns::detail::ResolveError::timeout ? 6 :
                    error==dns::detail::ResolveError::policy_rejected ? 2 : 4;
                co_return OrderedTcpResult{Stop::io_error,static_cast<std::uint8_t>(code),error};
            }
            if(session.closed)co_return OrderedTcpResult{Stop::canceled};
            if(!overrode_ip && !candidates.assign(*resolved,input))co_return OrderedTcpResult{Stop::state_error};
            endpoints=std::move(*resolved);
        }
        if (ov_addr) {
            auto port=ov_port ? ov_port : *input.port;
            if (auto literal=platform::parse_ip_address(*ov_addr)) {
                if (literal->size==4) {
                    corosio::ipv4_address::bytes_type b{};
                    std::copy_n(literal->bytes.begin(),4,b.begin());
                    endpoints={corosio::endpoint(corosio::ipv4_address(b),port)};
                } else {
                    endpoints={corosio::endpoint(corosio::ipv6_address(literal->bytes),port)};
                }
            } else {
                std::optional<platform::IpAddress> source;
                auto source_bytes=input.source_ip_bytes;
                if(input.source_ip) {
                    if(source_bytes || !(source=platform::parse_ip_address(*input.source_ip)))
                        co_return OrderedTcpResult{Stop::state_error};
                    source_bytes=source->view();
                }
                auto resolved=co_await resolve_destination(session,context,std::string(*ov_addr),port,deadline,
                    {.network=input.network,.source_port=input.source_port,.source_ip_bytes=source_bytes});
                if(!resolved) {
                    auto error=resolved.error();
                    auto code=error==dns::detail::ResolveError::timeout ? 6 :
                        error==dns::detail::ResolveError::policy_rejected ? 2 : 4;
                    co_return OrderedTcpResult{Stop::io_error,static_cast<std::uint8_t>(code),error};
                }
                if(session.closed)co_return OrderedTcpResult{Stop::canceled};
                endpoints=std::move(*resolved);
            }
            route_only=false;
        } else if (ov_port) {
            for (auto& ep : endpoints) ep=corosio::endpoint(ep.address(),ov_port);
        }
        bool first_sent=false;
        auto first=first_override ? *first_override : sniffer.wire();
        // Recover pre-read bytes through the metered replay rather than the
        // direct Fast Open path, which cannot wait on the user budget.
        if (session.meters_principal_bytes() || session.direct_shaping_pending()) first={};
        auto code=co_await dial_route_candidates(session,context,endpoints,selected,deadline,first,&first_sent,route_rule,(route_only || overrode_ip || remote_domain) ? domain : std::nullopt);
        if(session.closed)co_return OrderedTcpResult{Stop::canceled};
        co_return OrderedTcpResult{.stop=Stop::terminal,.code=code,.first_sent=first_sent,.deadline=deadline};
    }

    auto route_ordered_stream_tcp(Session& session,corosio::io_context& context,socks5::Request const& request,void* client,
        capy::task<sniff::TcpReadResult> (*reader)(void*,sniff::TcpSniffer&,Clock::time_point)) -> capy::task<bool> {
        auto result=co_await route_ordered_stream_tcp(session,context,request,client,reader,nullptr);
        co_return result==OrderedStreamResult::connected;
    }

    auto route_ordered_stream_tcp(Session& session,corosio::io_context& context,socks5::Request const& request,void* client,
        capy::task<sniff::TcpReadResult> (*reader)(void*,sniff::TcpSniffer&,Clock::time_point),TcpDnsHandler dns)
        -> capy::task<OrderedStreamResult> {
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
        if (!session.tunnel && session.direct_shaping_pending()) {
            auto replayed=co_await replay_shaped_direct(session,sniffer.wire(),{},result.deadline);
            co_return replayed ? Result::connected : Result::rejected;
        }
        sniff::TcpReplay replay(sniffer.wire());
        auto replayed=co_await replay_ordered_tcp(session,replay,result.deadline);
        co_return replayed ? Result::connected : Result::rejected;
    }

    auto write_principal_payload(Session& session,bool upstream,std::span<std::uint8_t const> pending)
        -> capy::task<bool> {
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
                auto [error,n]=co_await socket.write_some(capy::const_buffer(output.data(),output.size()));
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
        -> capy::task<bool> {
        if(session.closed)co_return false;
        bool sent=false;
        if (session.meters_principal_bytes()) {
            auto write=[&](std::span<std::uint8_t const> bytes) -> capy::task<capy::results<>> {
                if (co_await write_principal_payload(session,true,bytes)) co_return capy::results<>{};
                co_return capy::results<>{std::make_error_code(std::errc::io_error)};
            };
            sent=co_await replay.send_all(write,deadline);
        } else if(session.tunnel) {
            auto write=[&](std::span<std::uint8_t const> bytes) -> capy::task<capy::results<>> {
                if(!co_await session.tunnel->send(bytes))
                    co_return capy::results<>{std::make_error_code(std::errc::io_error)};
                session.count_traffic(true,bytes.size());
                co_return capy::results<>{};
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

    auto hijack_dns_query(Session& session,corosio::io_context& context,std::span<std::uint8_t const> payload,
        net::UdpEndpoint source,Clock::time_point deadline,rules::Network network)
        -> capy::task<std::optional<std::vector<std::uint8_t>>> {
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
        auto const* routing_ptr = dns_detail::active_dns_routing(session);
        if (!routing_ptr) co_return std::nullopt;
        auto const& routing = *routing_ptr;
        auto& state=*session.dns;
        dns::MessageLocalSource local(session.local_dns->source);
        std::vector<dns::MessageUpstream> upstreams;
        upstreams.reserve(routing.servers.size());
        for(std::size_t i=0;i<routing.servers.size();++i) {
            auto const& server=routing.servers[i];
            dns::MessageUpstream upstream{.tcp=server.tcp,.host=server.host,.port=server.port,.resolver=server.resolver,.protection=dns_detail::active_dns_protection(session,i)};
            if(!server.port)upstream.local=&local;
            else if(server.host.empty())upstream.endpoint=dns_detail::active_dns_endpoint(session,i);
            upstreams.push_back(std::move(upstream));
        }
        auto view=session.route_snapshot && session.route_snapshot->dns ?
            session.route_snapshot->dns->view : std::nullopt;
        dns::MessageProgram program(context,session.dns_rules(),upstreams,routing.final,
            state.wire_cache(),routing.disable_cache,{},nullptr,view,session.reverse_cache,routing.independent_cache);
        struct CancelRegistration {
            Session& session;
            ~CancelRegistration(){session.dns_operation=nullptr;session.cancel_dns=nullptr;}
        } registration{session};
        session.dns_operation=&program;
        session.cancel_dns=[](void* operation) noexcept {static_cast<dns::MessageProgram*>(operation)->cancel();};
        policy::DnsContext dns_ctx{.network=network,.source_port=source.port,
            .source_ip_bytes=std::span(source.address).first(source.family==4 ? 4 : 16)};
        session.fill_dns_context(dns_ctx);
        auto response=co_await program.run(*query,deadline,dns_ctx);
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
}
