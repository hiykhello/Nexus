module;
#include <proxy/proxy_macros.h>

export module masque.ip_server;
import std;
import proxy.v4;
import masque.connect_ip;
import masque.ip_control;

export namespace masque {
    inline constexpr std::size_t ip_server_mtu = 1280;
    enum class IpServerWrite { sent, blocked, failed };

    PRO_DEF_MEM_DISPATCH(IpServerOpen, open);
    PRO_DEF_MEM_DISPATCH(IpServerClose, close);
    PRO_DEF_MEM_DISPATCH(IpServerHealthy, healthy);
    PRO_DEF_MEM_DISPATCH(IpServerRead, read);
    PRO_DEF_MEM_DISPATCH(IpServerWriteDispatch, write);
    PRO_DEF_MEM_DISPATCH(IpServerAddresses, addresses);
    PRO_DEF_MEM_DISPATCH(IpServerRoutes, routes);

    // The listener owns the port. At most one authenticated CONNECT-IP
    // request can acquire it, and only that request can send or receive.
    struct IpServerPortFacade : pro::facade_builder
        ::add_convention<IpServerOpen, bool() noexcept>
        ::add_convention<IpServerClose, void() noexcept>
        ::add_convention<IpServerHealthy, bool() const noexcept>
        ::add_convention<IpServerRead, std::optional<std::size_t>(std::span<std::uint8_t>) noexcept>
        ::add_convention<IpServerWriteDispatch, IpServerWrite(std::span<std::uint8_t const>) noexcept>
        ::add_convention<IpServerAddresses, std::span<AddressEntry const>() const noexcept>
        ::add_convention<IpServerRoutes, std::span<RouteEntry const>() const noexcept>
        ::build {};

    using IpServerPort = pro::proxy<IpServerPortFacade>;

    class IpServerStream {
        struct Impl;
        std::unique_ptr<Impl> impl_;
    public:
        IpServerStream(IpServerPort&, ConnectIpScope);
        IpServerStream(IpServerStream const&) = delete;
        ~IpServerStream();
        auto start() noexcept -> bool;
        auto stop() noexcept -> void;
        auto withdraw() noexcept -> void;
        auto failed() const noexcept -> bool;
        auto feed(std::span<std::uint8_t const>) noexcept -> bool;
        auto datagram(std::span<std::uint8_t const>) noexcept -> bool;
        auto poll() noexcept -> bool;
        auto take_uploaded() noexcept -> std::size_t;
        auto output(std::span<std::uint8_t>,std::size_t* payload_size=nullptr) -> std::size_t;
    };
}
