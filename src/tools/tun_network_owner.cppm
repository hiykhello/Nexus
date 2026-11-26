export module cli.tun_network_owner;
import std;
import packet.tun_linux;
import packet.tun_network_types;
import packet.tun_default_policy;

export namespace cli::tun_enabled {
    struct StrictTunHeader {
        std::array<char,16> name{};
        std::array<char,46> dns_stub{};
        packet::TunNetworkOptions network{};
        packet::TunDefaultOptions policy{};
        std::uint32_t exclude_count=0, include_count=0;
        bool multi_queue=false, vnet_hdr=false;
        packet::TunRedirectOptions redirect;
    };

    struct StrictTunRequest {
        std::array<char,16> name{};
        std::array<char,46> dns_stub{};
        packet::TunNetworkOptions network{};
        std::vector<packet::TunAddress> excludes{};
        std::vector<packet::TunAddress> includes{};
        packet::TunDefaultOptions policy{};
        bool multi_queue=false, vnet_hdr=false;
        packet::TunRedirectOptions redirect;
    };

    // The proxy borrows the TUN queue. The child retains the device and owns
    // all kernel mutations until the control socket closes.
    class StrictTunOwner {
        int socket_=-1;
        int pid_=-1;
        mutable std::mutex io_mutex_;
    public:
        StrictTunOwner()=default;
        StrictTunOwner(StrictTunOwner const&)=delete;
        auto operator=(StrictTunOwner const&) -> StrictTunOwner& = delete;
        ~StrictTunOwner();
        auto start(StrictTunRequest const&) -> std::expected<packet::LinuxTun,std::string>;
        auto update_routes(std::span<packet::TunAddress const> excludes,
            std::span<packet::TunAddress const> includes) -> std::expected<void,std::string>;
        auto healthy() const noexcept -> bool;
        auto stop() noexcept -> bool;
    };

    auto run_strict_tun_owner() -> int;
}
