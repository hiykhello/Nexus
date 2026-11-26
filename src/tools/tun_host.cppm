export module cli.tun_host;
import std;
import config;
import relay;
import packet.tun_network_types;
export import packet.tun_device;
export import platform.tun_bridge;

export namespace cli::tun_enabled {
    class TunHost {
        struct Impl;
        std::unique_ptr<Impl> impl_;
    public:
        TunHost(relay::Server& routing_source, config::TunInbound options,bool supervise_strict_network=false,
            packet::TunRedirectOptions redirect={});
        ~TunHost();
        TunHost(TunHost const&) = delete;
        auto operator=(TunHost const&) -> TunHost& = delete;

        [[nodiscard]] auto start() -> std::expected<std::string, std::string>;
        // Uses an already configured TUN descriptor. The address and route
        // configuration belongs to the embedding host.
        [[nodiscard]] auto start(packet::PlatformTun device) -> std::expected<std::string,std::string>;
        [[nodiscard]] auto start(std::shared_ptr<platform::ExternalTunBridge> bridge)
            -> std::expected<std::string, std::string>;
        [[nodiscard]] auto healthy() const noexcept -> bool;
        [[nodiscard]] auto queue_outbound_probe(std::shared_ptr<relay::OutboundProbe>) -> bool;
        [[nodiscard]] auto failure() const -> std::optional<std::string>;
        [[nodiscard]] auto update_route_sets(config::TunInbound const& next_tun) -> std::expected<void, std::string>;
        auto begin_drain() noexcept -> void;
        [[nodiscard]] auto drained() const noexcept -> bool;
        auto stop() noexcept -> void;
    };

    [[nodiscard]] auto update_active_tun_host_route_sets(relay::Server const* server,
        config::TunInbound const& next_tun) -> std::expected<bool, std::string>;
}
