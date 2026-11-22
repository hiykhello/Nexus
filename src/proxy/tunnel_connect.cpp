module proxy;
import std;
import proxy.v4;
import rules;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace proxy {
    auto TunnelFactory::operator()(Session& session,nex::corosio::io_context& context,bool relay_local) const -> pro::proxy<TunnelFacade> {
        if (requires_direct_socket && (detour || detour_direct)) return {};
        if (!detour) return create(session,context,relay_local,detour_direct ? session.direct_tcp_options : nullptr);
        if (!through || !session.tunnel_factories || *detour>=session.tunnel_factories->size()) return {};
        if (timeout_ms>10000)
            session.handshake_deadline=std::max(session.handshake_deadline,session.started+std::chrono::milliseconds(timeout_ms)+std::chrono::seconds(1));
        return through(session,context,(*session.tunnel_factories)[*detour],relay_local);
    }

    auto LowerConnector::connect(Session& session,Clock::time_point deadline,Candidates& candidates) -> nex::capy::task<TunnelConnectResult> {
        if (!factory) co_return tunnel ? TunnelConnectResult::connected : TunnelConnectResult::failed;
        if (session.closed || dns.canceled) co_return TunnelConnectResult::failed;
        if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
        if (!candidates.resolved) {
            candidates.resolved=true;
            auto answer=bootstrap ? co_await resolve_bootstrap_owned(session,*context,dns,*bootstrap,std::string(host),port,deadline)
                                  : co_await resolve_local_owned(session,*context,dns,std::string(host),port,deadline);
            if (session.closed || dns.canceled) co_return TunnelConnectResult::failed;
            if (!answer || answer->empty() || answer->size()>64)
                co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::retryable;
            candidates.endpoints=std::move(*answer);
        }
        while (candidates.next<candidates.endpoints.size()) {
            auto endpoint=candidates.endpoints[candidates.next++];
            if (!valid_destination(endpoint)) continue;
            if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
            tunnel=(*factory)(session,*context,false);
            if (!tunnel) co_return TunnelConnectResult::failed;
            auto connected=co_await tunnel->connect_until(endpoint,deadline);
            if (session.closed || dns.canceled) co_return TunnelConnectResult::failed;
            if (connected==TunnelConnectResult::connected) co_return connected;
            tunnel->cancel(); tunnel={};
            // Retryable already exhausted the lower node's bootstrap/socket
            // candidates. Other addresses of this node cannot repair it.
            co_return connected;
        }
        co_return TunnelConnectResult::retryable;
    }

    auto connect_tunnel_chain(Session& session,nex::corosio::io_context& context,TunnelFactory const& first,
        std::span<TunnelChainStep const> steps,nex::corosio::endpoint destination,TunnelChainMode mode,Clock::time_point deadline)
        -> nex::capy::task<TunnelConnectResult> {
        if (session.closed || session.tunnel || !first.create || steps.size()>15 ||
            (mode!=TunnelChainMode::tcp && mode!=TunnelChainMode::uot && mode!=TunnelChainMode::xudp && mode!=TunnelChainMode::packets)) co_return TunnelConnectResult::failed;
        if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
        for (auto const& step:steps) if (!step.factory || !*step.factory || !valid_destination(step.endpoint)) co_return TunnelConnectResult::failed;
        if (mode==TunnelChainMode::tcp && !valid_destination(destination)) co_return TunnelConnectResult::failed;
        struct Guard { Session& session; bool done=false; ~Guard() { if (!done && session.tunnel) { session.tunnel->cancel(); session.tunnel={}; } } } guard{session};
        session.tunnel=first(session,context);
        if (!session.tunnel) co_return TunnelConnectResult::failed;
        for (auto const& step:steps) {
            auto connected=co_await session.tunnel->connect_until(step.endpoint,deadline);
            if (session.closed) co_return TunnelConnectResult::failed;
            if (connected!=TunnelConnectResult::connected) co_return connected;
            if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
            auto lower=std::move(session.tunnel);
            session.tunnel=(*step.factory)(session,std::move(lower));
            if (!session.tunnel) co_return TunnelConnectResult::failed;
        }
        TunnelConnectResult result=TunnelConnectResult::failed;
        if (mode==TunnelChainMode::tcp) result=co_await session.tunnel->connect_until(destination,deadline);
        else if (mode==TunnelChainMode::uot && session.tunnel->has_uot()) result=co_await session.tunnel->connect_uot_until(deadline);
        else if (mode==TunnelChainMode::xudp && session.tunnel->has_xudp()) result=co_await session.tunnel->connect_xudp_until(deadline);
        else if (mode==TunnelChainMode::packets) result=co_await session.tunnel->connect_packets(deadline);
        if (session.closed) co_return TunnelConnectResult::failed;
        if (result==TunnelConnectResult::connected) guard.done=true;
        co_return result;
    }
    auto Server::set_outbound_detours(std::span<OutboundDetour const> detours) -> std::expected<void,std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before changing outbound detours");
        if (detours.size()>outbounds.size()) return std::unexpected("too many outbound detours");
        std::vector<policy::DependencyEdge> edges;
        std::array<bool,16> seen{};
        for (auto [outbound,detour]:detours) {
            if (outbound<2 || outbound-2>=outbounds.size() || detour==1 || (detour>=2 && detour-2>=outbounds.size()))
                return std::unexpected("invalid outbound detour index");
            auto index=outbound-2;
            if (seen[index] || outbounds[index].requires_direct_socket || (detour && !outbounds[index].through))
                return std::unexpected("invalid or duplicate outbound detour, or socket settings on a layered node");
            seen[index]=true;
            if (detour) edges.push_back({index,detour-2});
        }
        if (!policy::dependency_order(outbounds.size(),edges)) return std::unexpected("outbound detour cycle");
        for (auto& factory:outbounds) { factory.detour.reset(); factory.detour_direct=false; }
        for (auto edge:edges) outbounds[edge.consumer].detour=edge.prerequisite;
        for (auto [outbound,detour]:detours) if (!detour) outbounds[outbound-2].detour_direct=true;
        return {};
    }

    auto Server::set_direct_tcp_options(TcpSocketOptions options) -> std::expected<void,std::string> {
        if (running || (listener && listener->is_open()) || !sessions.empty() || !workers.empty())
            return std::unexpected("stop the server before changing direct TCP options");
        if (!options.valid()) return std::unexpected("invalid direct TCP options");
        direct_tcp_options=options;
        return {};
    }

}
