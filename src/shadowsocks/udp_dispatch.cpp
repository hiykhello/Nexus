module shadowsocks.udp_dispatch;
import std;
namespace shadowsocks {
    auto UdpDispatcher::advance(Clock::time_point now) noexcept -> bool {
        if (last_ && now<*last_) return false;
        last_=now; return true;
    }
    auto UdpDispatcher::begin(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> wire,UdpPeer peer,
        Clock::time_point now,std::uint64_t wall,Clock::time_point deadline,rules::RouteMatcher const* policy,UdpListenerAdmission admission,bool allow_tunnel)
        -> std::expected<UdpPending,UdpDispatchError> {
        return begin_impl(psk,wire,peer,now,wall,deadline,policy,true,admission,allow_tunnel);
    }
    auto UdpDispatcher::begin_ordered(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> wire,UdpPeer peer,
        Clock::time_point now,std::uint64_t wall,Clock::time_point deadline,UdpListenerAdmission admission) -> std::expected<UdpPending,UdpDispatchError> {
        return begin_impl(psk,wire,peer,now,wall,deadline,nullptr,false,admission,false);
    }
    auto UdpDispatcher::begin_impl(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> wire,UdpPeer peer,
        Clock::time_point now,std::uint64_t wall,Clock::time_point deadline,rules::RouteMatcher const* policy,bool preflight,UdpListenerAdmission admission,bool allow_tunnel)
        -> std::expected<UdpPending,UdpDispatchError> {
        if (!advance(now)) return std::unexpected(UdpDispatchError::time_reversed);
        if (deadline<=now) return std::unexpected(UdpDispatchError::timeout);
        auto packet=server_.receive(psk,wire,peer,now,wall,admission.allow_new,admission.identity);
        if (!packet) {
            if (admission.rejected_session) *admission.rejected_session=packet.error();
            return std::unexpected(UdpDispatchError::session);
        }
        if (traffic_.admitted)
            traffic_.admitted(traffic_.owner,{packet->packet.session_id,packet->generation,packet->owner},packet->source);
        if (preflight && !server_.preflight(*packet,policy,allow_tunnel)) return std::unexpected(UdpDispatchError::route);
        auto size=packet->packet.address.size()+packet->packet.payload.size();
        if (pending_.size()>=count_limit_ || size>byte_limit_-bytes_) return std::unexpected(UdpDispatchError::full);
        if (exhausted_) return std::unexpected(UdpDispatchError::exhausted);
        auto token=next_;
        // Copy before inserting; failed allocation leaves counters unchanged.
        UdpPending result{token,packet->packet.address};
        pending_.emplace(token,Entry{std::move(*packet),deadline,size,policy,!preflight});
        bytes_+=size;
        if (next_==std::numeric_limits<std::uint64_t>::max()) exhausted_=true; else ++next_;
        return result;
    }
    auto UdpDispatcher::complete(std::uint64_t token,std::span<UdpPeer const> candidates,Clock::time_point now)
        -> std::expected<void,UdpDispatchError> {
        if (!advance(now)) return std::unexpected(UdpDispatchError::time_reversed);
        auto node=pending_.extract(token);
        if (node.empty()) return std::unexpected(UdpDispatchError::stale);
        auto& entry=node.mapped(); bytes_-=entry.bytes;
        if (now>=entry.deadline) return std::unexpected(UdpDispatchError::timeout);
        if (entry.selected) return std::unexpected(UdpDispatchError::route);
        if (candidates.size()>64) return std::unexpected(UdpDispatchError::limit);
        for (auto const& candidate:candidates) {
            auto result=server_.forward(entry.packet,candidate,entry.policy);
            if (result) {
                auto const& accepted=entry.packet;
                delivered({accepted.packet.session_id,accepted.generation,accepted.owner},true,accepted.packet.payload.size());
                return {};
            }
            if (auto e=std::get_if<UdpRouteError>(&result.error())) {
                if (*e==UdpRouteError::blocked || *e==UdpRouteError::invalid_target) continue;
                return std::unexpected(UdpDispatchError::route);
            }
            return std::unexpected(UdpDispatchError::session);
        }
        return std::unexpected(UdpDispatchError::no_candidate);
    }
    auto UdpDispatcher::select_route(std::uint64_t token,std::span<UdpPeer const> candidates,Clock::time_point now)
        -> std::expected<UdpDispatchRoute,UdpDispatchError> {
        if (!advance(now)) return std::unexpected(UdpDispatchError::time_reversed);
        auto it=pending_.find(token);
        if (it==pending_.end()) return std::unexpected(UdpDispatchError::stale);
        auto& entry=it->second;
        if (now>=entry.deadline) return std::unexpected(UdpDispatchError::timeout);
        if (entry.selected) return std::unexpected(UdpDispatchError::route);
        if (candidates.size()>64) return std::unexpected(UdpDispatchError::limit);
        for (auto const& candidate:candidates) {
            auto outbound=server_.select_outbound(entry.packet,candidate,entry.policy,true);
            if (outbound) {
                entry.selected=true;
                return UdpDispatchRoute{*outbound,candidate};
            }
            if (outbound.error()!=UdpRouteError::blocked && outbound.error()!=UdpRouteError::invalid_target)
                return std::unexpected(UdpDispatchError::route);
        }
        return std::unexpected(UdpDispatchError::no_candidate);
    }
    auto UdpDispatcher::pending_packet(std::uint64_t token) const noexcept -> UdpAccepted const* {
        auto it=pending_.find(token);return it==pending_.end() ? nullptr : &it->second.packet;
    }
    auto UdpDispatcher::complete_selected(std::uint64_t token,std::span<UdpPeer const> candidates,Clock::time_point now)
        -> std::expected<void,UdpDispatchError> {
        if(!advance(now))return std::unexpected(UdpDispatchError::time_reversed);
        auto node=pending_.extract(token);if(node.empty())return std::unexpected(UdpDispatchError::stale);
        auto& entry=node.mapped();bytes_-=entry.bytes;
        if(now>=entry.deadline)return std::unexpected(UdpDispatchError::timeout);
        if(!entry.selected)return std::unexpected(UdpDispatchError::route);
        if(candidates.size()>64)return std::unexpected(UdpDispatchError::limit);
        for(auto const& candidate:candidates) {
            auto result=server_.forward_selected(entry.packet,candidate);
            if (result) {
                auto const& accepted=entry.packet;
                delivered({accepted.packet.session_id,accepted.generation,accepted.owner},true,accepted.packet.payload.size());
                return {};
            }
            if(auto error=std::get_if<UdpRouteError>(&result.error());error && *error==UdpRouteError::invalid_target)continue;
            return std::unexpected(UdpDispatchError::session);
        }
        return std::unexpected(UdpDispatchError::no_candidate);
    }
    auto UdpDispatcher::inspect_selected(std::uint64_t token,UdpPeer candidate,Clock::time_point now)
        -> std::expected<UdpTunnelTicket,UdpDispatchError> {
        if (!advance(now)) return std::unexpected(UdpDispatchError::time_reversed);
        auto it=pending_.find(token);
        if (it==pending_.end()) return std::unexpected(UdpDispatchError::stale);
        auto const& entry=it->second;
        if (now>=entry.deadline) return std::unexpected(UdpDispatchError::timeout);
        if (!entry.selected) return std::unexpected(UdpDispatchError::route);
        if (!server_.current(entry.packet)) return std::unexpected(UdpDispatchError::session);
        auto target=server_.validate_selected(entry.packet,candidate);
        if (!target) return std::unexpected(UdpDispatchError::route);
        auto const& accepted=entry.packet;
        return UdpTunnelTicket{{accepted.packet.session_id,accepted.generation,accepted.owner},*target,accepted.source};
    }
    auto UdpDispatcher::take_selected(std::uint64_t token,UdpPeer candidate,Clock::time_point now)
        -> std::expected<UdpTunnelPacket,UdpDispatchError> {
        if (!advance(now)) return std::unexpected(UdpDispatchError::time_reversed);
        auto node=pending_.extract(token);
        if (node.empty()) return std::unexpected(UdpDispatchError::stale);
        auto& entry=node.mapped();bytes_-=entry.bytes;
        if (now>=entry.deadline) return std::unexpected(UdpDispatchError::timeout);
        if (!entry.selected) return std::unexpected(UdpDispatchError::route);
        if (!server_.current(entry.packet)) return std::unexpected(UdpDispatchError::session);
        auto target=server_.validate_selected(entry.packet,candidate);
        if (!target) return std::unexpected(UdpDispatchError::route);
        auto& accepted=entry.packet;
        return UdpTunnelPacket{{accepted.packet.session_id,accepted.generation,accepted.owner},*target,std::move(accepted.packet.payload)};
    }
    auto UdpDispatcher::retire(UdpSessionHandle const& session,Clock::time_point now) noexcept -> bool {
        if (!server_.retire(session,now)) return false;
        for (auto it=pending_.begin();it!=pending_.end();) {
            auto const& entry=it->second;
            if (entry.packet.generation==session.generation && entry.packet.owner==session.owner) {
                bytes_-=entry.bytes;
                it=pending_.erase(it);
            } else ++it;
        }
        return true;
    }

    auto UdpDispatcher::cancel(std::uint64_t token) noexcept -> bool {
        auto it=pending_.find(token);
        if (it==pending_.end()) return false;
        bytes_-=it->second.bytes; pending_.erase(it); return true;
    }
    auto UdpDispatcher::expire(Clock::time_point now,std::uint64_t wall) -> std::expected<std::size_t,UdpDispatchError> {
        if (!advance(now)) return std::unexpected(UdpDispatchError::time_reversed);
        auto sessions=server_.expire(now,wall);
        if (!sessions) return std::unexpected(UdpDispatchError::session);
        std::size_t count=0;
        for (auto it=pending_.begin();it!=pending_.end();) {
            if (now>=it->second.deadline) { bytes_-=it->second.bytes; it=pending_.erase(it); ++count; }
            else ++it;
        }
        return count;
    }
}
