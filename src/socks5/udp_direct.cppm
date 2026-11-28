export module socks5.udp_direct;
export import socks5.udp_route;
export import net.udp_socket;
import rules;
import std;
import net.udp_dial;
import platform.socket_options;

export namespace socks5 {
    using UdpDirectError = std::variant<UdpRouteError,Status,std::error_code>;
    struct UdpDirectReply { UdpPeer client; std::vector<std::uint8_t> wire; std::size_t payload_size; };
    struct UdpSocketPacket { UdpPeer source; std::size_t size; bool valid; };
    // SOCKS address adapter for the protocol-independent datagram socket.
    // Peek does not consume, including on allocation failure.
    class UdpSocket {
        net::UdpDialSockets socket_;
    public:
        explicit UdpSocket(platform::SocketBinding const* binding=nullptr) noexcept : socket_(binding) {}
        UdpSocket(UdpSocket const&)=delete;
        auto operator=(UdpSocket const&) -> UdpSocket& = delete;
        [[nodiscard]] auto send(UdpPeer target,std::span<std::uint8_t const> data,
            std::chrono::steady_clock::time_point deadline=std::chrono::steady_clock::time_point::max())
            -> std::expected<void,std::error_code> {
            return socket_.send(udp_endpoint(target),data,deadline);
        }
        [[nodiscard]] auto peek(std::span<std::uint8_t> buffer) -> std::expected<std::optional<UdpSocketPacket>,std::error_code> {
            auto packet=socket_.peek(buffer);
            if (!packet) return std::unexpected(packet.error());
            if (!*packet) return std::optional<UdpSocketPacket>{};
            auto const& value=**packet;
            return std::optional{UdpSocketPacket{udp_peer(value.source),value.size,value.valid}};
        }
        [[nodiscard]] auto consume() -> std::expected<std::optional<std::size_t>,std::error_code> { return socket_.consume(); }
        [[nodiscard]] auto native_handles() const noexcept -> std::array<int,2> { return socket_.native_handles(); }
        auto close() noexcept -> void { socket_.close(); }
    };
    // Linux nonblocking single-owner socket. Association and policy outlive it.
    // Caller serializes access, drives poll, and closes it with the control session.
    // If the association was closed first, the next send/poll also closes the socket.
    class UdpDirect {
        UdpAssociation& association_;
        rules::RouteProgram const& policy_;
        std::optional<std::string_view> auth_user_;
        UdpSocket socket_;
        bool closed_ = false;
    public:
        UdpDirect(UdpAssociation& association, rules::RouteProgram const& policy,std::optional<std::string_view> auth_user={},platform::SocketBinding const* binding=nullptr) noexcept
            : association_(association), policy_(policy), auth_user_(auth_user),socket_(binding) {}
        ~UdpDirect();
        UdpDirect(UdpDirect const&)=delete;
        auto operator=(UdpDirect const&) -> UdpDirect& = delete;
        [[nodiscard]] auto send(UdpDatagram const& packet,UdpPeer candidate,
            std::chrono::steady_clock::time_point deadline=std::chrono::steady_clock::time_point::max()) -> std::expected<void,UdpDirectError>;
        // Selected direct route: still validates the target and commits reply
        // authorization only after the datagram has been sent successfully.
        [[nodiscard]] auto send_selected(UdpDatagram const& packet,UdpPeer candidate,
            std::chrono::steady_clock::time_point deadline=std::chrono::steady_clock::time_point::max()) -> std::expected<void,UdpDirectError>;
        // One received datagram per call; unauthorized or oversized replies are discarded.
        // If supplied, consumed reports whether a datagram was removed from the socket.
        [[nodiscard]] auto poll(bool* consumed=nullptr) -> std::expected<std::optional<UdpDirectReply>,UdpDirectError>;
        auto close() noexcept -> void;
        [[nodiscard]] auto native_handles() const noexcept -> std::array<int,2> { return socket_.native_handles(); }
    };
}
