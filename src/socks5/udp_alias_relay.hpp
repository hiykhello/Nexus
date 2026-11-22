// Private implementation included by the SOCKS datagram ingress module.
#pragma once
    auto UdpIngress::send_alias(UdpDatagram const& domain,UdpPeer candidate,std::shared_ptr<void> lease,
        std::optional<std::size_t> rule,std::optional<std::size_t> predicate,std::size_t outbound)
        -> std::expected<void,UdpDirectError> {
        using Clock=std::chrono::steady_clock;
        auto packet=pending_route();
        if (!packet || (packet->address_type!=1 && packet->address_type!=4) || !lease ||
            packet->port!=domain.port || !association_.client_peer())
            return std::unexpected(UdpDirectError{UdpRouteError::invalid_target});
        if (outbound==1) return std::unexpected(UdpDirectError{UdpRouteError::blocked});
        if (!outbound && binding_ && binding_->udp_bind_port)
            return std::unexpected(UdpDirectError{UdpRouteError::unsupported});
        auto now=Clock::now();
        if (now>=input_metadata_.deadline)
            return std::unexpected(UdpDirectError{std::make_error_code(std::errc::timed_out)});
        if (allow_target_ && !allow_target_(filter_context_,candidate))
            return std::unexpected(UdpDirectError{UdpRouteError::blocked});
        auto checked=net::udp_validate_candidate(udp_target(domain),udp_endpoint(candidate));
        if (!checked) return std::unexpected(UdpDirectError{checked.error()});
        auto target=udp_peer(*checked);
        UdpPeer alias{packet->address_type,{},packet->port};
        std::copy_n(packet->address.begin(),packet->address_length,alias.address.begin());
        if (outbound>=2) {
            if (!allow_tunnels_) return std::unexpected(UdpDirectError{UdpRouteError::unsupported});
            tunnel_alias_.emplace(UdpTunnelAlias{alias,std::move(lease)});
            tunnel_=UdpSelection{target,outbound,rule,predicate};
            route_pending_=false;
            wake();
            return {};
        }
        auto credit=reserve_bytes(true,packet->data.size());
        if (!credit) return std::unexpected(UdpDirectError{UdpRouteError::blocked});
        auto slot=std::ranges::find_if(aliases_,[&](auto const& relay) {
            return relay.alias==alias && relay.target==target;
        });
        if (slot==aliases_.end()) {
            if (aliases_.size()==64)
                return std::unexpected(UdpDirectError{std::make_error_code(std::errc::no_buffer_space)});
            if (aliases_.size()==aliases_.capacity()) aliases_.reserve(64);
            auto socket=std::make_unique<UdpSocket>(binding_);
            auto sent=socket->send(target,packet->data);
            if (!sent) return std::unexpected(UdpDirectError{sent.error()});
            aliases_.push_back(AliasRelay{alias,target,std::move(lease),std::move(socket),now});
        } else {
            auto sent=slot->socket->send(target,packet->data);
            if (!sent) return std::unexpected(UdpDirectError{sent.error()});
            slot->touched=now;
        }
        credit->complete(packet->data.size());
        route_delivery_(external_route_,{target,0,rule,predicate});
        delivery_(true,packet->data.size());
        discard_route();
        return {};
    }

    auto UdpIngress::poll_aliases(UdpIngressStep& report) -> void {
        auto now=std::chrono::steady_clock::now();
        if (aliases_.empty()) return;
        std::array<std::uint8_t,65536> bytes;
        for (std::size_t checked=0; checked<aliases_.size(); ++checked) {
            next_alias_%=aliases_.size();
            auto& relay=aliases_[next_alias_++];
            auto result=relay.socket->peek(bytes);
            if (!result) {report.output_error=UdpDirectError{result.error()};return;}
            if (!*result) continue;
            auto packet=**result;
            auto consumed=relay.socket->consume();
            if (!consumed) {report.output_error=UdpDirectError{consumed.error()};return;}
            if (!*consumed || **consumed!=packet.size || !packet.valid || packet.source!=relay.target) {
                report.output_dropped=true;
                continue;
            }
            auto queued=queue_tunnel_reply(relay.alias,std::span(bytes).first(packet.size));
            if (!queued) report.output_error=queued.error();
            else if (*queued==UdpReplyStatus::queued) relay.touched=now;
            else report.output_dropped=true;
            return;
        }
    }
