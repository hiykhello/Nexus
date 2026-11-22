export module masque.ip_server;
import std;
import masque.connect_ip;
import masque.ip_control;

export namespace masque {
    // The listener owns the port. At most one authenticated CONNECT-IP
    // request can acquire it, and only that request can send or receive.
    class IpServerPort {
    public:
        static constexpr std::size_t mtu = 1280;
        enum class Write { sent, blocked, failed };
        virtual ~IpServerPort() = default;
        virtual auto open() noexcept -> bool = 0;
        virtual auto close() noexcept -> void = 0;
        virtual auto healthy() const noexcept -> bool = 0;
        virtual auto read(std::span<std::uint8_t>) noexcept -> std::optional<std::size_t> = 0;
        virtual auto write(std::span<std::uint8_t const>) noexcept -> Write = 0;
        virtual auto addresses() const noexcept -> std::span<AddressEntry const> = 0;
        virtual auto routes() const noexcept -> std::span<RouteEntry const> = 0;
    };

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
