// Private accounting state for one authenticated SS-2022 UDP key owner.
#pragma once
    class UdpListenerTraffic {
        struct Flow {
            UdpSessionHandle handle;
            proxy::TrafficRegistration traffic;
        };
        std::span<proxy::Server* const> listeners_;
        std::vector<Flow> flows_;
        UdpDispatcher& dispatcher_;

        auto find(UdpSessionHandle handle) noexcept {
            return std::ranges::find_if(flows_,[&](Flow const& flow) {
                return flow.handle.generation==handle.generation && flow.handle.owner==handle.owner;
            });
        }
        auto admit(UdpSessionHandle handle,UdpPeer peer) noexcept -> void {
            auto* listener=listeners_[peer.ingress];
            if (!listener || find(handle)!=flows_.end()) return;
            if (flows_.size()==flows_.capacity()) prune();
            if (flows_.size()==flows_.capacity()) return;
            auto traffic=listener->track_traffic(proxy::TrafficProtocol::shadowsocks_udp,proxy::ConnectPath::datagrams,
                net::UdpEndpoint{peer.family,peer.address,peer.port},0,true);
            flows_.push_back({handle,std::move(traffic)});
        }
        auto deliver(UdpSessionHandle handle,bool upstream,std::size_t bytes) noexcept -> void {
            auto flow=find(handle);
            if (flow!=flows_.end()) flow->traffic.count(upstream,bytes);
        }
    public:
        UdpListenerTraffic(UdpDispatcher& dispatcher,std::span<proxy::Server* const> listeners,std::size_t capacity)
            : listeners_(listeners),dispatcher_(dispatcher) {
            flows_.reserve(capacity);
            dispatcher_.observe_traffic({this,
                [](void* self,UdpSessionHandle handle,UdpPeer peer) noexcept {
                    static_cast<UdpListenerTraffic*>(self)->admit(handle,peer);
                },
                [](void* self,UdpSessionHandle handle,bool upstream,std::size_t bytes) noexcept {
                    static_cast<UdpListenerTraffic*>(self)->deliver(handle,upstream,bytes);
                }});
        }
        ~UdpListenerTraffic() {dispatcher_.observe_traffic({});}
        auto maintain(std::chrono::steady_clock::time_point now) noexcept -> void {
            for (auto& flow : flows_) if (flow.traffic.close_requested())
                (void)dispatcher_.retire(flow.handle,now);
            prune();
        }
        auto prune() noexcept -> void {
            std::erase_if(flows_,[&](Flow const& flow) {return !dispatcher_.current(flow.handle);});
        }
    };
