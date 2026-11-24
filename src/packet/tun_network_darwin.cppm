export module packet.tun_network_darwin;
export import packet.tun_network_plan;
import std;

export namespace packet {
    [[nodiscard]] auto plan_darwin_tun_network(TunRoutePlanInput const& input,
        std::string_view ifname = {}) -> std::expected<TunRoutePlan, std::string>;

    class DarwinTunNetwork {
        struct Impl;
        std::unique_ptr<Impl> impl_;
    public:
        DarwinTunNetwork();
        ~DarwinTunNetwork();
        DarwinTunNetwork(DarwinTunNetwork&&) noexcept;
        auto operator=(DarwinTunNetwork&&) noexcept -> DarwinTunNetwork&;
        DarwinTunNetwork(DarwinTunNetwork const&) = delete;
        auto operator=(DarwinTunNetwork const&) -> DarwinTunNetwork& = delete;

        [[nodiscard]] auto start(std::string_view ifname, TunRoutePlan const& plan)
            -> std::expected<void, std::error_code>;
        auto stop() noexcept -> void;
        [[nodiscard]] auto active() const noexcept -> bool;
    };
}
