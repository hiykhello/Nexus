export module hysteria2.udp_receiver;
import std;
import hysteria2.udp;
import hysteria2.sessions;
import hysteria2.fragments;

export namespace hysteria2 {
    // The existing reassembler supplies all fragmentation ownership. This
    // composition adds role-based admission and physical-session notifications;
    // a full completed-packet queue applies bounded unreliable receive dropping.
    template<class Observer,std::size_t Sessions=64,std::size_t Packets=16,std::size_t Ready=1>
    class UdpReceiver {
        Observer& observer_;
        UdpSessions<Sessions> sessions_;
        UdpReassembler<UdpSessions<Sessions>,Packets,Ready> fragments_;
        bool remote_admission_,closed_=false;
        auto closed(UdpSessionHandle owner,std::uint32_t id) noexcept -> void {
            static_assert(noexcept(observer_.session_closed(owner,id)));observer_.session_closed(owner,id);
        }
    public:
        UdpReceiver(Observer& observer,bool remote_admission,std::chrono::milliseconds idle=std::chrono::minutes(5),
            std::size_t fragment_bytes=1024*1024,std::chrono::milliseconds fragment_lifetime=std::chrono::seconds(5),
            UdpMemoryBudget* budget=&default_udp_memory_budget())
            :observer_(observer),sessions_(idle),fragments_(sessions_,fragment_bytes,max_udp_payload,fragment_lifetime,budget),remote_admission_(remote_admission) {}
        UdpReceiver(UdpReceiver const&)=delete;
        auto operator=(UdpReceiver const&) -> UdpReceiver& = delete;
        ~UdpReceiver() { close(); }
        auto open(std::uint32_t id,UdpClock::time_point now) noexcept -> std::expected<UdpSessionHandle,UdpSessionError> {
            if (closed_) return std::unexpected(UdpSessionError::expired);
            auto result=sessions_.acquire(id,now);if(!result)return std::unexpected(result.error());
            if(result->created){
                static_assert(noexcept(observer_.session_created(result->handle,id)));
                if(!observer_.session_created(result->handle,id)){sessions_.release(result->handle);return std::unexpected(UdpSessionError::full);}
            }return result->handle;
        }
        auto receive(std::span<std::uint8_t const> wire,UdpClock::time_point now) noexcept -> ReassemblyStatus {
            if(closed_)return ReassemblyStatus::closed;
            if(!expire(now))return ReassemblyStatus::clock;
            auto packet=parse_udp_packet(wire);if(!packet)return ReassemblyStatus::malformed;
            auto owner=sessions_.find(packet->session,now);
            if(!owner){if(!remote_admission_)return ReassemblyStatus::session;auto opened=open(packet->session,now);if(!opened)return ReassemblyStatus::full;owner=*opened;}
            else if(!sessions_.touch(*owner,now))return ReassemblyStatus::session;
            return fragments_.feed(*owner,*packet,now);
        }
        auto packet(UdpClock::time_point now) const noexcept -> std::optional<ReassembledPacket> { return fragments_.packet(now); }
        auto consume() noexcept -> bool { return fragments_.consume(); }
        auto live(UdpSessionHandle owner,UdpClock::time_point now) const noexcept -> bool { return !closed_ && sessions_.live(owner,now); }
        auto id(UdpSessionHandle owner) const noexcept -> std::optional<std::uint32_t> { return sessions_.id(owner); }
        auto release(UdpSessionHandle owner,UdpClock::time_point now) noexcept -> bool {
            auto id=sessions_.id(owner);if(!id || !sessions_.release(owner))return false;
            closed(owner,*id);fragments_.prune(now);return true;
        }
        auto expire(UdpClock::time_point now) noexcept -> bool {
            sessions_.expire(now,[&](auto owner,auto id) noexcept {closed(owner,id);});return fragments_.prune(now);
        }
        auto expiry() const noexcept -> std::optional<UdpClock::time_point> {
            auto session=sessions_.expiry(),fragment=fragments_.expiry();if(!session)return fragment;if(!fragment)return session;return std::min(*session,*fragment);
        }
        auto close() noexcept -> void {
            if(std::exchange(closed_,true))return;
            fragments_.close();sessions_.close([&](auto owner,auto id) noexcept {closed(owner,id);});
        }
        auto buffered_bytes() const noexcept -> std::size_t { return fragments_.buffered_bytes(); }
        auto pending_packets() const noexcept -> std::size_t { return fragments_.pending_packets(); }
        auto size() const noexcept -> std::size_t { return sessions_.size(); }
    };
}
