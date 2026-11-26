module relay;
import std;
import capy;
import corosio;
import rules;
import relay.dns_state;

namespace relay {
    auto OutboundContext::prewarm_allowed() const noexcept -> bool {
        if (!owner || !factories) return true;
        auto snapshot=owner->current_route_snapshot();
        if (!snapshot) return true;
        auto matches_chain=[&](std::size_t root) noexcept -> bool {
            auto candidate=std::optional{root};
            for (std::size_t hops=0;candidate && *candidate<factories->size() && hops<factories->size();++hops) {
                if (*candidate==factory_index) return true;
                candidate=(*factories)[*candidate].detour;
            }
            return false;
        };
        auto matches_outbound=[&](std::size_t root) noexcept -> bool {
            auto const& dist=snapshot->matcher.distribution();
            auto const physical=dist ? dist->physical_count : (2+factories->size());
            if (root<2) return false;
            if (root<physical) return root-2<factories->size() && matches_chain(root-2);
            if (!dist) return false;
            std::bitset<512> seen_group{};
            std::array<std::size_t,256> stack{};
            std::size_t sp=0;
            stack[sp++]=root;
            while (sp) {
                auto idx=stack[--sp];
                if (idx<2) continue;
                if (idx<physical) {
                    if (idx-2<factories->size() && matches_chain(idx-2)) return true;
                    continue;
                }
                auto g=idx-physical;
                if (g>=dist->groups.size() || g>=seen_group.size() || seen_group.test(g)) continue;
                seen_group.set(g);
                for (auto member : dist->groups[g]) {
                    if (member<2) continue;
                    if (member<physical) {
                        if (member-2<factories->size() && matches_chain(member-2)) return true;
                    } else if (sp<stack.size()) {
                        stack[sp++]=member;
                    }
                }
            }
            return false;
        };
        if (snapshot->dns_transports) {
            for (auto const& outbound : snapshot->dns_transports->outbounds)
                if (outbound && matches_outbound(*outbound)) return true;
        } else if (!snapshot->dns_disabled) {
            auto const* active_routing = snapshot->dns_runtime ? &snapshot->dns_runtime->routing :
                (dns ? &dns->routing : nullptr);
            if (active_routing && std::ranges::any_of(active_routing->servers, &DnsServer::proxy_detour))
                return true;
        }
        if (auto const& runtime=owner->get_runtime_mode()) {
            auto mode=runtime->mode.load(std::memory_order_acquire);
            if (mode==rules::RouteMode::global)
                return matches_outbound(runtime->global_outbound.load(std::memory_order_acquire));
            if (mode==rules::RouteMode::direct) return false;
        }
        if (!snapshot->tunnel_references) return true;
        auto const& referenced=*snapshot->tunnel_references;
        auto limit=std::min(factories->size(),referenced.size());
        for (std::size_t index=0;index<limit;++index)
            if (referenced.test(index) && matches_chain(index)) return true;
        return false;
    }
    struct PacketTunnel::Impl {
        pro::proxy<TunnelFacade> tunnel;
        std::chrono::milliseconds timeout;
        bool fixed_peer;
        Impl(pro::proxy<TunnelFacade>&& value,TunnelFactory const& factory)
            : tunnel(std::move(value)),timeout(factory.timeout_ms),fixed_peer(factory.packet_fixed_peer) {}
    };
    PacketTunnel::PacketTunnel(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
    PacketTunnel::~PacketTunnel()=default;
    auto PacketTunnel::transport() const noexcept -> net::PacketTransport {
        return impl_ && impl_->tunnel ? impl_->tunnel->packet_transport() : net::PacketTransport{};
    }
    auto PacketTunnel::fixed_peer() const noexcept -> bool {
        return impl_ && impl_->fixed_peer;
    }
    auto PacketTunnel::connection_deadline(Clock::time_point limit) const noexcept -> Clock::time_point {
        return impl_ ? std::min(limit,Clock::now()+impl_->timeout) : limit;
    }
    auto PacketTunnel::connect(Clock::time_point deadline) -> capy::task<PacketConnectResult> {
        return connect_until(connection_deadline(deadline));
    }
    auto PacketTunnel::connect(net::ProxyAddress peer,Clock::time_point deadline) -> capy::task<PacketConnectResult> {
        return connect_until(peer,connection_deadline(deadline));
    }
    auto PacketTunnel::connect_until(Clock::time_point deadline) -> capy::task<PacketConnectResult> {
        co_return co_await connect_until(net::ProxyAddress{},deadline);
    }
    auto PacketTunnel::connect_until(net::ProxyAddress peer,Clock::time_point deadline) -> capy::task<PacketConnectResult> {
        if (!impl_ || !impl_->tunnel) co_return PacketConnectResult::failed;
        if (Clock::now()>=deadline) co_return PacketConnectResult::timeout;
        auto result=co_await impl_->tunnel->connect_packets(peer,deadline);
        switch(result) {
        case TunnelConnectResult::connected: co_return PacketConnectResult::connected;
        case TunnelConnectResult::retryable: co_return PacketConnectResult::retryable;
        case TunnelConnectResult::timeout: co_return PacketConnectResult::timeout;
        case TunnelConnectResult::failed: co_return PacketConnectResult::failed;
        }
        co_return PacketConnectResult::failed;
    }
    auto PacketTunnel::send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
        if (!impl_ || !impl_->tunnel) co_return false;
        co_return co_await impl_->tunnel->send(bytes);
    }
    auto PacketTunnel::read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,std::string>> {
        if (!impl_ || !impl_->tunnel) co_return std::unexpected("packet tunnel closed");
        co_return co_await impl_->tunnel->read(bytes);
    }
    auto PacketTunnel::cancel() noexcept -> void {if(impl_ && impl_->tunnel)impl_->tunnel->cancel();}
    auto Server::has_packet_outbound(std::size_t outbound) const noexcept -> bool {
        auto const& factories=borrowed_outbounds ? *borrowed_outbounds : outbounds;
        return outbound>=2 && outbound-2<factories.size();
    }
    auto Server::open_stream(Session& session,std::size_t outbound,corosio::endpoint target,Clock::time_point limit)
        -> capy::task<PacketConnectResult> {
        auto const& factories=borrowed_outbounds ? *borrowed_outbounds : outbounds;
        if(!running || session.closed || session.registry!=&sessions || session.tunnel ||
            outbound<2 || outbound-2>=factories.size() || !valid_destination(target))
            co_return PacketConnectResult::failed;
        auto const& factory=factories[outbound-2];
        auto deadline=std::min(limit,session.started+std::chrono::milliseconds(factory.timeout_ms));
        if(Clock::now()>=deadline)co_return PacketConnectResult::timeout;
        session.tunnel=factory(session,context,false);
        if(!session.tunnel)co_return PacketConnectResult::failed;
        auto result=co_await session.tunnel->connect_until(target,deadline);
        if(result==TunnelConnectResult::connected && !session.closed)co_return PacketConnectResult::connected;
        if(!session.closed) session.record_dial_failure(outbound);
        session.tunnel->cancel();
        session.tunnel={};
        if(result==TunnelConnectResult::timeout)co_return PacketConnectResult::timeout;
        if(result==TunnelConnectResult::retryable)co_return PacketConnectResult::retryable;
        co_return PacketConnectResult::failed;
    }
    auto Server::open_packet_tunnel(Session& session,std::size_t outbound) -> std::unique_ptr<PacketTunnel> {
        if (!running || session.closed || session.registry!=&sessions || outbound<2) return {};
        auto const& factories=borrowed_outbounds ? *borrowed_outbounds : outbounds;
        auto index=outbound-2;
        if (index>=factories.size()) return {};
        auto tunnel=factories[index](session,context,false);
        if (!tunnel || tunnel->packet_transport().kind==net::PacketTransportKind::none) return {};
        return std::unique_ptr<PacketTunnel>(new PacketTunnel(std::make_unique<PacketTunnel::Impl>(std::move(tunnel),factories[index])));
    }
    auto Server::start_outbound_contexts() -> bool {
        if (outbound_contexts_started) return false;
        outbound_contexts_started=true;
        auto const& factories=borrowed_outbounds ? *borrowed_outbounds : outbounds;
        if(factories.size()>outbound_context_order.size())return false;
        outbound_context_count=0;std::array<std::uint8_t,256> marks{};
        auto visit=[&](auto&& self,std::size_t index) -> bool {
            if(index>=factories.size() || marks[index]==1)return false;
            if(marks[index]==2)return true;
            marks[index]=1;
            if(factories[index].detour && !self(self,*factories[index].detour))return false;
            marks[index]=2;outbound_context_order[outbound_context_count++]=static_cast<std::uint16_t>(index);return true;
        };
        for(std::size_t index=0;index<factories.size();++index)if(!visit(visit,index))return false;
        OutboundContext environment{context,dns.get(),local_dns.get(),&factories,&direct_tcp_options,this};
        for(std::size_t i=0;i<outbound_context_count;++i) {
            environment.factory_index=outbound_context_order[i];
            auto const& factory=factories[environment.factory_index];
            if (!factory.start_context) continue;
            TunnelFactory const* detour=nullptr;
            if(factory.detour)detour=&factories[*factory.detour];
            if (!factory.start_context(environment,detour,factory.detour_direct)) return false;
        }
        return true;
    }
    auto Server::stop_outbound_contexts() noexcept -> void {
        if (!outbound_contexts_started) return;
        auto const& factories=borrowed_outbounds ? *borrowed_outbounds : outbounds;
        for(std::size_t i=outbound_context_count;i>0;--i) {
            auto const& factory=factories[outbound_context_order[i-1]];
            if(factory.stop_context)factory.stop_context(context);
            if(factory.quiesced_context) {
                auto deadline=Clock::now()+std::chrono::milliseconds(250);
                while(!factory.quiesced_context(context) && Clock::now()<deadline) {
                    context.restart();(void)context.run_for(std::chrono::milliseconds(5));
                }
            }
        }
    }
    auto Server::reap_outbound_contexts() noexcept -> void {
        if (!outbound_contexts_started) return;
        auto const& factories=borrowed_outbounds ? *borrowed_outbounds : outbounds;
        for(std::size_t i=0;i<outbound_context_count;++i) {
            auto const& factory=factories[outbound_context_order[i]];
            if(factory.reap_context)factory.reap_context(context);
        }
    }
    auto Server::outbound_contexts_quiesced() const noexcept -> bool {
        if (!outbound_contexts_started) return true;
        auto const& factories=borrowed_outbounds ? *borrowed_outbounds : outbounds;
        for(std::size_t i=0;i<outbound_context_count;++i) {
            auto const& factory=factories[outbound_context_order[i]];
            if(factory.quiesced_context && !factory.quiesced_context(context)) return false;
        }
        return true;
    }
    auto Server::finish_outbound_contexts() noexcept -> void {
        if (!outbound_contexts_started) return;
        auto const& factories=borrowed_outbounds ? *borrowed_outbounds : outbounds;
        for(std::size_t i=outbound_context_count;i>0;--i) {
            auto const& factory=factories[outbound_context_order[i-1]];
            if(factory.finish_context)factory.finish_context(context);
        }
        outbound_context_count=0;outbound_contexts_started=false;
    }
}
