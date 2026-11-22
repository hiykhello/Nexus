export module cli.tun_host;
import std;
import config;
import proxy;
import packet.tun_network_types;
export import packet.tun_linux;

export namespace cli::tun_enabled {
    class TunHost {
        struct Impl;
        std::unique_ptr<Impl> impl_;
    public:
        TunHost(proxy::Server& routing_source, config::TunInbound options,bool supervise_strict_network=false,
            packet::TunRedirectOptions redirect={});
        ~TunHost();
        TunHost(TunHost const&) = delete;
        auto operator=(TunHost const&) -> TunHost& = delete;

        [[nodiscard]] auto start() -> std::expected<std::string, std::string>;
        // Uses an already configured TUN descriptor. The address and route
        // configuration belongs to the embedding host.
        [[nodiscard]] auto start(packet::LinuxTun device) -> std::expected<std::string,std::string>;
        [[nodiscard]] auto healthy() const noexcept -> bool;
        [[nodiscard]] auto queue_outbound_probe(std::shared_ptr<proxy::OutboundProbe>) -> bool;
        [[nodiscard]] auto failure() const -> std::optional<std::string>;
        auto stop() noexcept -> void;
    };
}
