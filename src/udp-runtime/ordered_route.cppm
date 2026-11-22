export module ss_udp.ordered_route;
import std;
import rules;
import dns.message;
import shadowsocks.udp_dispatch;
import sniff.udp_quic;

export namespace shadowsocks::detail {
    enum class OrderedUdpStop { resolve,sniff_wait,route,reject,uncertain,error };
    struct OrderedUdpStep {OrderedUdpStop stop;std::size_t outbound=0;};
    // The immutable program must outlive this owner. Packet-derived input is
    // captured at construction, so cancellation may release the packet while
    // DNS is pending. Input views make this object nonmovable.
    class OrderedUdpRoute {
        using Clock=std::chrono::steady_clock;
        rules::RouteProgram const& program_;
        Clock::time_point received_,limit_=Clock::time_point::max();
        rules::ProgramCursor cursor_;
        rules::ProgramInput input_;
        std::string target_,sniffed_,inbound_;
        std::array<std::uint8_t,16> source_{};
        std::optional<rules::Protocol> packet_protocol_;
        bool has_sniffed_=false,sniff_complete_=false;
        std::array<rules::ProgramAddress,64> addresses_{};
        std::array<UdpPeer,64> peers_{};
        std::size_t address_count_=0;
        bool resolved_=false,valid_=false;
        std::optional<rules::ProgramStep> pending_;
        std::unique_ptr<sniff::QuicProbe> probe_;
    public:
        OrderedUdpRoute(UdpAccepted const& packet,rules::RouteProgram const& program,std::optional<std::string_view> inbound,
                        Clock::time_point received=Clock::now())
            :program_(program),received_(received) {
            auto const& address=packet.packet.address;
            if(address.empty() || (packet.source.family!=4 && packet.source.family!=6) || !packet.source.port)return;
            auto size=address[0]==1 ? 4u : address[0]==4 ? 16u : address[0]==3 && address.size()>=2 ? unsigned(address[1]) : 0u;
            auto offset=address[0]==3 ? 2u : 1u;
            if(!size || address.size()!=offset+size+2)return;
            auto port=static_cast<std::uint16_t>((unsigned(address[offset+size])<<8)|address[offset+size+1]);if(!port)return;
            input_.port=port;input_.network=rules::Network::udp;
            if(inbound){inbound_.assign(*inbound);input_.inbound=inbound_;}
            input_.auth_user=packet.auth_user;
            input_.source_port=packet.source.port;
            source_=packet.source.address;
            input_.source_ip_bytes=std::span(source_).first(packet.source.family==4 ? 4 : 16);
            if(address[0]==3) {
                target_.assign(reinterpret_cast<char const*>(address.data()+offset),size);
                if(!rules::valid_domain(target_))return;
                input_.explicit_domain=target_;
            } else {
                rules::ProgramAddress candidate{};candidate.size=static_cast<std::uint8_t>(size);
                std::copy_n(address.begin()+offset,size,candidate.bytes.begin());addresses_[0]=candidate;address_count_=1;resolved_=true;
                peers_[0]={size==4 ? std::uint8_t{4} : std::uint8_t{6},candidate.bytes,port};
                input_.candidates=std::span(addresses_).first(1);
                input_.domain_absent[static_cast<std::size_t>(rules::DomainSource::explicit_target)]=true;
            }
            auto query=dns::parse_query(packet.packet.payload);
            if(query) {
                packet_protocol_=rules::Protocol::dns;
                if(rules::valid_domain(query->question.name)) {
                    sniffed_=std::move(query->question.name);has_sniffed_=true;
                }
            } else if(sniff::stun_datagram(packet.packet.payload)) {
                packet_protocol_=rules::Protocol::stun;
            } else {
                auto quic=sniff::sniff_quic_datagram(packet.packet.payload);
                if (quic.status==sniff::QuicProbeStatus::matched) {
                    packet_protocol_=rules::Protocol::quic;
                    if (quic.domain) {
                        sniffed_=std::move(*quic.domain);has_sniffed_=true;
                    }
                }
            }
            valid_=true;
        }
        OrderedUdpRoute(OrderedUdpRoute const&)=delete;
        auto operator=(OrderedUdpRoute const&) -> OrderedUdpRoute& = delete;
        [[nodiscard]] auto limit() const noexcept -> Clock::time_point {return limit_;}
        [[nodiscard]] auto domain() const noexcept -> std::optional<std::string_view> {return input_.explicit_domain;}
        [[nodiscard]] auto inbound() const noexcept -> std::optional<std::string_view> {return input_.inbound;}
        [[nodiscard]] auto port() const noexcept -> std::optional<std::uint16_t> {return input_.port;}
        [[nodiscard]] auto resolved() const noexcept -> bool {return resolved_;}
        [[nodiscard]] auto candidates() const noexcept -> std::span<UdpPeer const> {
            return std::span(peers_).first(address_count_);
        }
        [[nodiscard]] auto poll(bool skip_unknown,std::size_t fallback,std::span<std::uint8_t const> payload={},bool collect_quic=false) -> OrderedUdpStep {
            if(!valid_ || pending_)return {OrderedUdpStop::error};
            for(;;) {
                auto result=cursor_.poll(program_,input_);if(!result)return {OrderedUdpStop::error};
                if(result->kind==rules::ProgramPreflightKind::uncertain) {
                    if(!skip_unknown)return {OrderedUdpStop::uncertain};
                    if(!cursor_.skip_unknown(result->rule_index))return {OrderedUdpStop::error};
                    continue;
                }
                if(result->kind==rules::ProgramPreflightKind::exhausted)return {OrderedUdpStop::route,fallback};
                auto step=*result->step;
                if (auto timeout=step.action.connect_timeout_ms) {
                    limit_=std::min(limit_,received_+std::chrono::milliseconds(timeout));
                    if (Clock::now()>=limit_) return {OrderedUdpStop::error};
                }
                switch(step.action.kind) {
                case rules::ProgramActionKind::bypass:
                case rules::ProgramActionKind::hijack_dns:return {OrderedUdpStop::error};
                case rules::ProgramActionKind::route_options:
                    if (!cursor_.complete(step)) return {OrderedUdpStop::error};
                    break;
                case rules::ProgramActionKind::reject:return {OrderedUdpStop::reject};
                case rules::ProgramActionKind::route:return {OrderedUdpStop::route,step.action.outbound};
                case rules::ProgramActionKind::resolve:
                    if(input_.explicit_domain){pending_=step;return {OrderedUdpStop::resolve};}
                    if(!cursor_.complete(step))return {OrderedUdpStop::error};break;
                case rules::ProgramActionKind::sniff: {
                    input_.sniffed_domain.reset();
                    input_.protocol=packet_protocol_;
                    if (packet_protocol_==rules::Protocol::stun)
                        input_.domain_absent[static_cast<std::size_t>(rules::DomainSource::sniffed)]=true;
                    if(has_sniffed_)input_.sniffed_domain=sniffed_;
                    else if(collect_quic && !sniff_complete_ && !packet_protocol_) {
                        auto probe=sniff::make_quic_probe();
                        if(probe && probe->feed(payload).status==sniff::QuicProbeStatus::waiting) {
                            pending_=step;probe_=std::move(probe);return {OrderedUdpStop::sniff_wait};
                        }
                    }
                    sniff_complete_=true;
                    if(!cursor_.complete(step))return {OrderedUdpStop::error};break;
                }
                }
            }
        }
        // Called after DNS completes; empty is a known empty set, distinct
        // from unresolved. An invalid replacement does not alter the input.
    private:
        [[nodiscard]] auto set_candidates(std::span<UdpPeer const> candidates,bool explicit_action) noexcept -> bool {
            if(!valid_ || candidates.size()>addresses_.size() ||
                (explicit_action ? !pending_ : (pending_.has_value() || resolved_ || !input_.explicit_domain)))return false;
            if(explicit_action && pending_->action.kind!=rules::ProgramActionKind::resolve)return false;
            std::array<rules::ProgramAddress,64> next{};
            std::array<UdpPeer,64> peers{};
            for(std::size_t i=0;i<candidates.size();++i) {
                auto const& peer=candidates[i];
                if((peer.family!=4 && peer.family!=6) || peer.port!=*input_.port ||
                    (peer.family==4 && std::ranges::any_of(std::span(peer.address).subspan(4),[](auto b){return b!=0;})))return false;
                next[i].size=peer.family==4 ? 4 : 16;next[i].bytes=peer.address;peers[i]=peer;
            }
            if(explicit_action && !cursor_.complete(*pending_))return false;
            pending_.reset();addresses_=next;peers_=peers;address_count_=candidates.size();resolved_=true;
            input_.candidates=std::span(addresses_).first(address_count_);return true;
        }
    public:
        [[nodiscard]] auto supply(std::span<UdpPeer const> candidates) noexcept -> bool {
            return set_candidates(candidates,true);
        }
        // The selected outbound still needs an address when no resolve action
        // preceded the terminal decision. Do not advance the program cursor.
        [[nodiscard]] auto supply_implicit(std::span<UdpPeer const> candidates) noexcept -> bool {
            return set_candidates(candidates,false);
        }
        // Each call inspects synchronously; neither the probe nor the cursor
        // borrows a dispatcher's packet while waiting for the next fragment.
        [[nodiscard]] auto feed_sniff(std::span<std::uint8_t const> payload) -> sniff::QuicProbeResult {
            if(!pending_ || pending_->action.kind!=rules::ProgramActionKind::sniff || !probe_)
                return {sniff::QuicProbeStatus::unknown,{}};
            return probe_->feed(payload);
        }
        [[nodiscard]] auto finish_sniff(sniff::QuicProbeResult result) -> bool {
            if(!pending_ || pending_->action.kind!=rules::ProgramActionKind::sniff || !probe_ ||
               (result.domain && !rules::valid_domain(*result.domain)))return false;
            if(!cursor_.complete(*pending_))return false;
            pending_.reset();
            probe_.reset();
            (void)remember_sniff(std::move(result));
            input_.protocol=packet_protocol_;
            input_.sniffed_domain=has_sniffed_ ? std::optional<std::string_view>{sniffed_} : std::nullopt;
            return true;
        }
        // A later packet that participated in the head packet's probe keeps
        // the result until its own cursor reaches sniff, including unknown.
        [[nodiscard]] auto remember_sniff(sniff::QuicProbeResult result) -> bool {
            if(pending_ || (result.domain && !rules::valid_domain(*result.domain)))return false;
            if (result.status==sniff::QuicProbeStatus::matched) packet_protocol_=rules::Protocol::quic;
            sniff_complete_=true;
            has_sniffed_=result.domain.has_value();
            sniffed_=result.domain ? std::move(*result.domain) : std::string{};
            return true;
        }
    };

    // Coordinates program actions with DNS. A terminal route is reported
    // before implicit resolution so the caller can reject a block outbound
    // without making a DNS query. The caller owns this state until its token
    // is consumed or canceled.
    class OrderedUdpDecision {
        using Clock=std::chrono::steady_clock;
        OrderedUdpRoute route_;
        bool skip_unknown_;
        std::size_t fallback_;
        enum class Wait { none,explicit_action,implicit,sniff } wait_=Wait::none;
        std::optional<std::size_t> selected_;
    public:
        OrderedUdpDecision(UdpAccepted const& packet,rules::RouteProgram const& program,
                           std::optional<std::string_view> inbound,bool skip_unknown,std::size_t fallback,
                           Clock::time_point received=Clock::now())
            :route_(packet,program,inbound,received),skip_unknown_(skip_unknown),fallback_(fallback) {}
        [[nodiscard]] auto limit() const noexcept -> Clock::time_point {return route_.limit();}
        [[nodiscard]] auto next(std::span<std::uint8_t const> payload={},bool collect_quic=false) -> OrderedUdpStep {
            if(wait_!=Wait::none)return {OrderedUdpStop::error};
            if(selected_)return {OrderedUdpStop::route,*selected_};
            auto step=route_.poll(skip_unknown_,fallback_,payload,collect_quic);
            if(step.stop==OrderedUdpStop::resolve)wait_=Wait::explicit_action;
            else if(step.stop==OrderedUdpStop::sniff_wait)wait_=Wait::sniff;
            else if(step.stop==OrderedUdpStop::route)selected_=step.outbound;
            return step;
        }
        [[nodiscard]] auto needs_resolution() const noexcept -> bool {
            return selected_.has_value() && !route_.resolved();
        }
        [[nodiscard]] auto resolve_selected() noexcept -> bool {
            if(wait_!=Wait::none || !needs_resolution())return false;
            wait_=Wait::implicit;return true;
        }
        [[nodiscard]] auto supply(std::span<UdpPeer const> candidates) noexcept -> bool {
            auto ok=wait_==Wait::explicit_action ? route_.supply(candidates) :
                    wait_==Wait::implicit ? route_.supply_implicit(candidates) : false;
            if(ok)wait_=Wait::none;
            return ok;
        }
        [[nodiscard]] auto candidates() const noexcept -> std::span<UdpPeer const> {return route_.candidates();}
        [[nodiscard]] auto inbound() const noexcept -> std::optional<std::string_view> {return route_.inbound();}
        [[nodiscard]] auto waiting_sniff() const noexcept -> bool {return wait_==Wait::sniff;}
        [[nodiscard]] auto feed_sniff(std::span<std::uint8_t const> payload) -> sniff::QuicProbeResult {
            if(wait_!=Wait::sniff)return {sniff::QuicProbeStatus::unknown,{}};
            return route_.feed_sniff(payload);
        }
        [[nodiscard]] auto finish_sniff(sniff::QuicProbeResult result) -> bool {
            if(wait_!=Wait::sniff || !route_.finish_sniff(std::move(result)))return false;
            wait_=Wait::none;return true;
        }
        [[nodiscard]] auto remember_sniff(sniff::QuicProbeResult result) -> bool {
            return wait_==Wait::none && route_.remember_sniff(std::move(result));
        }
    };
}
