export module ss_udp.ordered_sniff;
import std;
import nexus.compat;
import shadowsocks.udp_dispatch;
import ss_udp.ordered_route;
import sniff.udp_quic;

export namespace shadowsocks::detail {
    // One serialized executor owns admission, DNS callbacks and replay. Packet
    // storage remains in the dispatcher; this owner retains only tokens and
    // decisions. A flow is admitted before any rule or DNS action can suspend.
    class OrderedUdpSniffOwner {
        using Clock=std::chrono::steady_clock;
    public:
        struct Ready {std::uint64_t token;std::shared_ptr<OrderedUdpDecision> decision;Clock::time_point deadline;};
    private:
        struct Key {
            std::array<std::uint8_t,8> session{};
            std::uint64_t generation=0;
            UdpServerSessions const* owner=nullptr;
            UdpPeer source{}; // Includes the listener index as well as address/port.
            std::vector<std::uint8_t> target;
            auto operator==(Key const&) const -> bool = default;
        };
        enum class State {ready,active,waiting};
        struct Member {Ready item;std::size_t bytes;bool scanned=false,participated=false;};
        struct Flow {
            Key key;
            std::vector<Member> members;
            std::size_t bytes=0;
            State state=State::ready;
            Clock::time_point until{};
        };
        UdpDispatcher& dispatcher_;
        std::chrono::milliseconds timeout_;
        std::vector<Flow> flows_;
        std::size_t count_=0;
        bool stopped_=false;
        static constexpr std::size_t max_flows_=32,max_members_=8,max_count_=64,max_bytes_=256*1024;

        static auto reset(Flow& flow) noexcept -> void {
            flow.state=State::ready;
            for(auto& member:flow.members) {member.scanned=false;member.participated=false;}
        }
        auto erase(Flow& flow,std::size_t index) -> void {
            flow.bytes-=flow.members[index].bytes;--count_;
            flow.members.erase(flow.members.begin()+index);
            if(!index)reset(flow);
        }
        auto finish(Flow& flow,sniff::QuicProbeResult const& result) -> void {
            auto& head=flow.members.front().item;
            if(!head.decision->finish_sniff(result)) {
                (void)dispatcher_.cancel(head.token);flow.state=State::ready;return;
            }
            for(std::size_t i=1;i<flow.members.size();++i) {
                auto& member=flow.members[i];
                if(member.participated && !member.item.decision->remember_sniff(result))
                    (void)dispatcher_.cancel(member.item.token);
            }
            flow.state=State::ready;
        }
        auto scan(Flow& flow) -> void {
            for(std::size_t i=1;i<flow.members.size() && flow.state==State::waiting;++i) {
                auto& member=flow.members[i];if(member.scanned)continue;
                member.scanned=true;
                auto packet=dispatcher_.pending_packet(member.item.token);if(!packet)continue;
                auto result=flow.members.front().item.decision->feed_sniff(packet->packet.payload);
                if(result.status==sniff::QuicProbeStatus::unrelated)continue;
                member.participated=true;
                if(result.status==sniff::QuicProbeStatus::matched)finish(flow,result);
                else if(result.status==sniff::QuicProbeStatus::unknown)finish(flow,{});
            }
        }
        auto prune(Flow& flow,Clock::time_point now) -> void {
            bool lost_fragment=false;
            auto current=dispatcher_.current({flow.key.session,flow.key.generation,flow.key.owner});
            for(std::size_t i=0;i<flow.members.size();) {
                auto const& member=flow.members[i];
                if(!current || now>=member.item.deadline || !dispatcher_.pending_packet(member.item.token)) {
                    lost_fragment|=i!=0 && member.participated;
                    (void)dispatcher_.cancel(member.item.token);erase(flow,i);
                } else ++i;
            }
            // The probe cannot subtract an authenticated fragment. If its
            // token disappears, finish unknown instead of retaining stale input.
            if(lost_fragment && flow.state==State::waiting)finish(flow,{});
        }
    public:
        OrderedUdpSniffOwner(UdpDispatcher& dispatcher,std::chrono::milliseconds timeout)
            :dispatcher_(dispatcher),timeout_(timeout) {}
        OrderedUdpSniffOwner(OrderedUdpSniffOwner const&)=delete;
        auto operator=(OrderedUdpSniffOwner const&) -> OrderedUdpSniffOwner& = delete;
        // Transfer every authenticated token before advancing its decision.
        // Failure leaves cancellation to the caller. Limits include active DNS
        // and ready packets, so waiting or replay cannot evade the flow budget.
        [[nodiscard]] auto submit(std::uint64_t token,std::shared_ptr<OrderedUdpDecision> decision,
                                  Clock::time_point deadline,Clock::time_point now) -> bool {
            if(stopped_ || !decision || deadline<=now)return false;
            tick(now);
            auto packet=dispatcher_.pending_packet(token);if(!packet)return false;
            if(!dispatcher_.current({packet->packet.session_id,packet->generation,packet->owner}))return false;
            Key key{packet->packet.session_id,packet->generation,packet->owner,packet->source,packet->packet.address};
            auto bytes=packet->packet.address.size()+packet->packet.payload.size();
            for(auto& flow:flows_) {
                if(!(flow.key==key))continue;
                if(std::ranges::any_of(flow.members,[token](auto const& member){return member.item.token==token;}))return false;
                if(count_>=max_count_ || flow.members.size()>=max_members_ || bytes>max_bytes_-flow.bytes) {
                    if(flow.state==State::waiting)finish(flow,{});
                    return false;
                }
                flow.members.push_back({{token,std::move(decision),deadline},bytes});flow.bytes+=bytes;++count_;
                if(flow.state==State::waiting)scan(flow);
                return true;
            }
            if(count_>=max_count_ || flows_.size()>=max_flows_ || bytes>max_bytes_)return false;
            Flow flow{std::move(key),{},bytes};flow.members.push_back({{token,std::move(decision),deadline},bytes});
            flows_.push_back(std::move(flow));++count_;return true;
        }
        // A completed DNS callback may have transferred its token here before
        // the resolver removes its operation. Do not restart that token until
        // busy reports false. Only one decision per flow can be active.
        [[nodiscard]] auto pop(Clock::time_point now,nexus::function_ref<bool(std::uint64_t)> busy) -> std::optional<Ready> {
            if(stopped_)return {};
            tick(now);
            for(auto& flow:flows_)if(flow.state==State::ready && !busy(flow.members.front().item.token)) {
                flow.state=State::active;return flow.members.front().item;
            }
            return {};
        }
        [[nodiscard]] auto wait(std::uint64_t token,Clock::time_point now) -> bool {
            if(stopped_)return false;
            tick(now);
            for(auto& flow:flows_)if(flow.members.front().item.token==token) {
                auto& head=flow.members.front().item;
                if(flow.state!=State::active || !head.decision->waiting_sniff())return false;
                head.deadline=std::min(head.deadline,head.decision->limit());
                flow.state=State::waiting;flow.until=std::min(head.deadline,now+timeout_);
                if(now>=flow.until)finish(flow,{});else scan(flow);
                return true;
            }
            return false;
        }
        // The caller consumed, canceled or transferred the active head. In
        // particular, a sender may still own its dispatcher token: do not cancel.
        [[nodiscard]] auto complete(std::uint64_t token) -> bool {
            for(std::size_t i=0;i<flows_.size();++i) {
                auto& flow=flows_[i];
                if(flow.members.front().item.token!=token)continue;
                if(flow.state!=State::active)return false;
                erase(flow,0);if(flow.members.empty())flows_.erase(flows_.begin()+i);
                return true;
            }
            return false;
        }
        auto tick(Clock::time_point now) -> void {
            if(stopped_)return;
            for(std::size_t i=0;i<flows_.size();) {
                auto& flow=flows_[i];prune(flow,now);
                if(flow.members.empty()) {flows_.erase(flows_.begin()+i);continue;}
                if(flow.state==State::waiting) {
                    if(now>=flow.until)finish(flow,{});else scan(flow);
                }
                ++i;
            }
        }
        auto stop() noexcept -> void {
            if(stopped_)return;stopped_=true;
            for(auto& flow:flows_)for(auto& member:flow.members)(void)dispatcher_.cancel(member.item.token);
            flows_.clear();count_=0;
        }
        [[nodiscard]] auto empty() const noexcept -> bool {return flows_.empty();}
        ~OrderedUdpSniffOwner() {stop();}
    };
}
