export module cli.tun_network_owner;
import std;
import packet.tun_linux;
import packet.tun_network_types;
import packet.tun_default_policy;

export namespace cli::tun_enabled {
    struct StrictTunRequest {
        std::array<char,16> name{};
        std::array<char,46> dns_stub{};
        packet::TunNetworkOptions network{};
        std::array<packet::TunAddress,packet::max_tun_excludes> excludes{};
        std::array<packet::TunAddress,packet::max_tun_excludes> includes{};
        packet::TunDefaultOptions policy{};
        std::uint8_t exclude_count=0, include_count=0;
        bool multi_queue=false;
        packet::TunRedirectOptions redirect;
    };

    // The proxy borrows the TUN queue. The child retains the device and owns
    // all kernel mutations until the control socket closes.
    class StrictTunOwner {
        int socket_=-1;
        int pid_=-1;
    public:
        StrictTunOwner()=default;
        StrictTunOwner(StrictTunOwner const&)=delete;
        auto operator=(StrictTunOwner const&) -> StrictTunOwner& = delete;
        ~StrictTunOwner();
        auto start(StrictTunRequest const&) -> std::expected<packet::LinuxTun,std::string>;
        auto healthy() const noexcept -> bool;
        auto stop() noexcept -> bool;
    };

    auto run_strict_tun_owner() -> int;
}
