export module net.udp_dial;
import std;
export import net.udp_socket;
import platform.socket_options;

export namespace net {
    // The immutable binding profile outlives this owner. Two sockets are needed
    // only when explicit family-specific source addresses are configured; the
    // empty policy keeps the existing single dual-stack socket behavior.
    class UdpDialSockets {
        std::array<UdpSocket,2> sockets_;
        platform::SocketBinding const* binding_=nullptr;
        std::error_code failure_;
        std::uint8_t next_=0;
        std::int8_t peeked_=-1;
        bool closed_=false;
        auto split() const noexcept -> bool;
        auto prepare(std::size_t index,std::uint8_t family,platform::SocketBinding const* binding,
            platform::SocketDeadline deadline) -> std::expected<void,std::error_code>;
        auto send_first(std::size_t index,UdpEndpoint target,std::span<std::uint8_t const> bytes,
            platform::SocketDeadline deadline) -> std::expected<void,std::error_code>;
    public:
        explicit UdpDialSockets(platform::SocketBinding const* binding=nullptr) noexcept : binding_(binding) {}
        UdpDialSockets(UdpDialSockets const&)=delete;
        auto operator=(UdpDialSockets const&) -> UdpDialSockets& = delete;
        [[nodiscard]] auto send(UdpEndpoint target,std::span<std::uint8_t const> bytes,
            platform::SocketDeadline deadline=platform::SocketDeadline::max()) -> std::expected<void,std::error_code>;
        [[nodiscard]] auto peek(std::span<std::uint8_t> bytes) -> std::expected<std::optional<UdpPacket>,std::error_code>;
        [[nodiscard]] auto consume() -> std::expected<std::optional<std::size_t>,std::error_code>;
        [[nodiscard]] auto receive(std::span<std::uint8_t> bytes) -> std::expected<std::optional<UdpPacket>,std::error_code>;
        auto close() noexcept -> void;
        [[nodiscard]] auto native_handles() const noexcept -> std::array<int,2> {
            return {sockets_[0].native_handle(),sockets_[1].native_handle()};
        }
        [[nodiscard]] auto local_endpoints() const -> std::array<std::optional<UdpEndpoint>,2> {
            std::array<std::optional<UdpEndpoint>,2> out{};
            for (std::size_t i=0;i<2;++i)
                if (auto ep=sockets_[i].local_endpoint()) out[i]=*ep;
            return out;
        }
    };
}
