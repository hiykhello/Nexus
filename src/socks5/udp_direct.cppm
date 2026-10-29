export module nexus.socks5.udp_direct;
export import nexus.socks5.udp_route;
import nexus.rules;
import std;

export namespace nexus::socks5 {
    using UdpDirectError = std::variant<UdpRouteError,Status,std::error_code>;
    struct UdpDirectReply { UdpPeer client; std::vector<std::uint8_t> wire; };
    // Linux nonblocking single-owner socket. Association and policy outlive it.
    // Caller serializes access, drives poll, and closes it with the control session.
    class UdpDirect {
        UdpAssociation& association_;
        rules::RouteMatcher const& policy_;
        int fd_ = -1;
        bool closed_ = false;
    public:
        UdpDirect(UdpAssociation& association, rules::RouteMatcher const& policy) noexcept
            : association_(association), policy_(policy) {}
        ~UdpDirect();
        UdpDirect(UdpDirect const&)=delete;
        auto operator=(UdpDirect const&) -> UdpDirect& = delete;
        [[nodiscard]] auto send(UdpDatagram const& packet,UdpPeer candidate) -> std::expected<void,UdpDirectError>;
        // One received datagram per call; unauthorized or oversized replies are discarded.
        [[nodiscard]] auto poll() -> std::expected<std::optional<UdpDirectReply>,UdpDirectError>;
        auto close() noexcept -> void;
    };
}
