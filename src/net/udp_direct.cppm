export module net.udp_direct;
export import net.udp_route;
export import net.udp_authorization;
import rules;
import std;
import net.udp_dial;
import platform.socket_options;

export namespace net {
    using UdpDirectError=std::variant<UdpRouteError,UdpAuthorizationError,std::error_code>;
    struct UdpDirectReply { UdpEndpoint source; std::size_t size; };
    // Single-owner endpoint. Packet bytes remain with the caller through a
    // retry; sends, polling, and close are serialized by its executor.
    class UdpDirect {
        rules::RouteProgram const& policy_;
        UdpDialSockets socket_;
        UdpAuthorization authorization_;
        bool closed_=false;
    public:
        explicit UdpDirect(rules::RouteProgram const& policy,platform::SocketBinding const* binding=nullptr) noexcept : policy_(policy),socket_(binding) {}
        UdpDirect(UdpDirect const&)=delete;
        auto operator=(UdpDirect const&) -> UdpDirect& = delete;
        [[nodiscard]] auto send(UdpTarget target,UdpEndpoint candidate,std::span<std::uint8_t const> payload,UdpEndpoint const* source=nullptr,std::optional<std::string_view> auth_user={},
            std::optional<std::chrono::steady_clock::time_point> deadline={})
            -> std::expected<void,UdpDirectError>;
        [[nodiscard]] auto send_selected(UdpTarget,UdpEndpoint,std::span<std::uint8_t const>,
            std::optional<std::chrono::steady_clock::time_point> deadline={}) -> std::expected<void,UdpDirectError>;
        // At most one datagram is consumed. Successful bytes occupy the first
        // size bytes; dropped reports a consumed but untrusted datagram.
        [[nodiscard]] auto poll(std::span<std::uint8_t> buffer,bool* dropped=nullptr)
            -> std::expected<std::optional<UdpDirectReply>,UdpDirectError>;
        [[nodiscard]] auto native_handles() const noexcept -> std::array<int,2>;
        auto close() noexcept -> void;
    };
}
