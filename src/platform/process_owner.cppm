export module platform.process_owner;
import std;
import platform.ip_address;

export namespace platform {
    struct ProcessOwner {
        std::uint32_t pid = 0;
        std::uint32_t uid = 0;
        std::string executable;
    };

    struct SocketTuple {
        bool is_udp = false;
        IpAddress local_ip{};
        std::uint16_t local_port = 0;
        IpAddress remote_ip{};
        std::uint16_t remote_port = 0;
    };

    [[nodiscard]] auto lookup_socket_owner(SocketTuple const& tuple) -> std::optional<ProcessOwner>;
}
