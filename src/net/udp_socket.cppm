export module net.udp_socket;
import std;

export namespace net {
    struct UdpEndpoint {
        // Family is 4 or 6; IPv4 uses the first four bytes and zeros the rest.
        std::uint8_t family=0;
        std::array<std::uint8_t,16> address{};
        std::uint16_t port=0;
        auto operator==(UdpEndpoint const&) const -> bool = default;
    };
    struct UdpPacket { UdpEndpoint source; std::size_t size; bool valid; };

    // Single-owner Linux nonblocking dual-stack datagram socket. Policy and
    // authorization belong to the caller. A peek never removes a packet;
    // receive removes one packet without requiring a preceding peek.
    class UdpSocket {
        int fd_=-1;
        bool closed_=false;
        auto receive_impl(std::span<std::uint8_t> buffer,int flags)
            -> std::expected<std::optional<UdpPacket>,std::error_code>;
    public:
        UdpSocket()=default;
        ~UdpSocket();
        UdpSocket(UdpSocket const&)=delete;
        auto operator=(UdpSocket const&) -> UdpSocket& = delete;
        [[nodiscard]] auto open(bool ipv6_only=false,std::string const& network_namespace={}) -> std::expected<void,std::error_code>;
        [[nodiscard]] auto bind(UdpEndpoint local) -> std::expected<void,std::error_code>;
        [[nodiscard]] auto local_endpoint() const -> std::expected<UdpEndpoint,std::error_code>;
        [[nodiscard]] auto native_handle() const noexcept -> int { return fd_; }
        [[nodiscard]] auto send(UdpEndpoint target,std::span<std::uint8_t const> data)
            -> std::expected<void,std::error_code>;
        [[nodiscard]] auto peek(std::span<std::uint8_t> buffer)
            -> std::expected<std::optional<UdpPacket>,std::error_code>;
        [[nodiscard]] auto receive(std::span<std::uint8_t> buffer)
            -> std::expected<std::optional<UdpPacket>,std::error_code>;
        [[nodiscard]] auto consume() -> std::expected<std::optional<std::size_t>,std::error_code>;
        // Release a candidate before committing this owner to a peer.
        auto discard() noexcept -> void;
        auto close() noexcept -> void;
    };
}
