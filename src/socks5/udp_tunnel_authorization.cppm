export module socks5.udp_tunnel_authorization;
export import socks5.udp_route;
export import net.udp_authorization;
import std;

export namespace socks5 {
    using UdpTunnelReply=net::UdpReplyAuthorization;
    [[nodiscard]] constexpr auto udp_authorization_status(net::UdpAuthorizationError error) noexcept -> Status {
        switch (error) {
        case net::UdpAuthorizationError::closed: return Status::association_closed;
        case net::UdpAuthorizationError::busy: return Status::send_in_progress;
        case net::UdpAuthorizationError::invalid_address: return Status::invalid_address;
        case net::UdpAuthorizationError::stale: return Status::stale_send;
        case net::UdpAuthorizationError::exhausted: return Status::token_exhausted;
        }
        return Status::invalid_address;
    }
    class UdpTunnelAuthorization {
        net::UdpAuthorization authorization_;
    public:
        [[nodiscard]] auto begin(UdpPeer peer) noexcept -> std::expected<std::uint64_t,Status> {
            auto result=authorization_.begin(udp_endpoint(peer));
            if (!result) return std::unexpected(udp_authorization_status(result.error()));
            return *result;
        }
        [[nodiscard]] auto finish(std::uint64_t token,bool success) noexcept -> std::expected<void,Status> {
            auto result=authorization_.finish(token,success);
            if (!result) return std::unexpected(udp_authorization_status(result.error()));
            return {};
        }
        [[nodiscard]] auto classify(UdpPeer peer) const noexcept -> UdpTunnelReply { return authorization_.classify(udp_endpoint(peer)); }
        [[nodiscard]] auto accepts(UdpPeer peer) const noexcept -> bool { return authorization_.accepts(udp_endpoint(peer)); }
        auto close() noexcept -> void { authorization_.close(); }
    };
}
