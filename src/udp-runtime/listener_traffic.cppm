// Private accounting state for one authenticated SS-2022 UDP key owner.
export module ss_udp.listener_traffic;
import std;
import net.udp_socket;
import relay;
import shadowsocks.udp_dispatch;

export namespace shadowsocks::detail {
    class UdpListenerTraffic {
        struct Flow {
            UdpSessionHandle handle;
            relay::TrafficRegistration traffic;
        };
        std::span<relay::Server* const> listeners_;
        std::vector<Flow> flows_;
        UdpDispatcher& dispatcher_;
        std::shared_ptr<relay::ShadowsocksDynamicUser> dynamic_user_;

        auto find(UdpSessionHandle handle) noexcept {
            return std::ranges::find_if(flows_, [&](Flow const& flow) {
                return flow.handle.generation == handle.generation && flow.handle.owner == handle.owner;
            });
        }
        auto admit(UdpSessionHandle handle, UdpPeer peer) noexcept -> void {
            auto* listener = peer.ingress < listeners_.size() ? listeners_[peer.ingress] : nullptr;
            if ((!listener && !dynamic_user_) || find(handle) != flows_.end()) return;
            if (flows_.size() == flows_.capacity()) prune();
            if (flows_.size() == flows_.capacity()) return;
            relay::TrafficRegistration traffic;
            if (listener) traffic = listener->track_traffic(relay::TrafficProtocol::shadowsocks_udp,
                relay::ConnectPath::datagrams, net::UdpEndpoint{peer.family, peer.address, peer.port}, 0, true);
            if (dynamic_user_) dynamic_user_->udp_sessions.fetch_add(1, std::memory_order_relaxed);
            flows_.push_back({handle, std::move(traffic)});
        }
        auto deliver(UdpSessionHandle handle, bool upstream, std::size_t bytes) noexcept -> void {
            auto flow = find(handle);
            if (flow != flows_.end()) flow->traffic.count(upstream, bytes);
            if (dynamic_user_) dynamic_user_->record_datagram(upstream, bytes);
        }
    public:
        UdpListenerTraffic(UdpDispatcher& dispatcher, std::span<relay::Server* const> listeners, std::size_t capacity,
            std::shared_ptr<relay::ShadowsocksDynamicUser> dynamic_user = {})
            : listeners_(listeners), dispatcher_(dispatcher), dynamic_user_(std::move(dynamic_user)) {
            flows_.reserve(capacity);
            dispatcher_.observe_traffic({this,
                [](void* self, UdpSessionHandle handle, UdpPeer peer) noexcept {
                    static_cast<UdpListenerTraffic*>(self)->admit(handle, peer);
                },
                [](void* self, UdpSessionHandle handle, bool upstream, std::size_t bytes) noexcept {
                    static_cast<UdpListenerTraffic*>(self)->deliver(handle, upstream, bytes);
                }});
        }
        ~UdpListenerTraffic() {
            dispatcher_.observe_traffic({});
            if (dynamic_user_ && !flows_.empty())
                dynamic_user_->udp_sessions.fetch_sub(static_cast<std::uint32_t>(flows_.size()), std::memory_order_relaxed);
        }
        auto maintain(std::chrono::steady_clock::time_point now) noexcept -> void {
            bool kick = dynamic_user_ && !dynamic_user_->admits();
            for (auto& flow : flows_) if (kick || flow.traffic.close_requested())
                (void)dispatcher_.retire(flow.handle, now);
            prune();
        }
        auto prune() noexcept -> void {
            auto n = std::erase_if(flows_, [&](Flow const& flow) { return !dispatcher_.current(flow.handle); });
            if (dynamic_user_ && n > 0)
                dynamic_user_->udp_sessions.fetch_sub(static_cast<std::uint32_t>(n), std::memory_order_relaxed);
        }
    };
}
