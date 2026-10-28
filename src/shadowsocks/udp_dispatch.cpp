module nexus.shadowsocks.udp_dispatch;
import std;
namespace nexus::shadowsocks {
    auto UdpDispatcher::advance(Clock::time_point now) noexcept -> bool {
        if (last_ && now<*last_) return false;
        last_=now; return true;
    }
    auto UdpDispatcher::begin(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> wire,UdpPeer peer,
        Clock::time_point now,std::uint64_t wall,Clock::time_point deadline) -> std::expected<UdpPending,UdpDispatchError> {
        if (!advance(now)) return std::unexpected(UdpDispatchError::time_reversed);
        if (deadline<=now) return std::unexpected(UdpDispatchError::timeout);
        auto packet=server_.receive(psk,wire,peer,now,wall);
        if (!packet) return std::unexpected(UdpDispatchError::session);
        if (!server_.preflight(*packet)) return std::unexpected(UdpDispatchError::route);
        auto size=packet->packet.address.size()+packet->packet.payload.size();
        if (pending_.size()>=count_limit_ || size>byte_limit_-bytes_) return std::unexpected(UdpDispatchError::full);
        if (exhausted_) return std::unexpected(UdpDispatchError::exhausted);
        auto token=next_;
        // Copy before inserting; failed allocation leaves counters unchanged.
        UdpPending result{token,packet->packet.address};
        pending_.emplace(token,Entry{std::move(*packet),deadline,size});
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
        if (candidates.size()>64) return std::unexpected(UdpDispatchError::limit);
        for (auto const& candidate:candidates) {
            auto result=server_.forward(entry.packet,candidate);
            if (result) return {};
            if (auto e=std::get_if<UdpRouteError>(&result.error())) {
                if (*e==UdpRouteError::blocked || *e==UdpRouteError::invalid_target) continue;
                return std::unexpected(UdpDispatchError::route);
            }
            return std::unexpected(UdpDispatchError::session);
        }
        return std::unexpected(UdpDispatchError::no_candidate);
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
