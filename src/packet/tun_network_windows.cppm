export module packet.tun_network_windows;
export import packet.tun_network_plan;
import std;

export namespace packet {
    [[nodiscard]] auto plan_windows_tun_network(TunRoutePlanInput const& input)
        -> std::expected<TunRoutePlan, std::string>;

    class WindowsTunNetwork {
        struct Impl;
        std::unique_ptr<Impl> impl_;
    public:
        WindowsTunNetwork();
        ~WindowsTunNetwork();
        WindowsTunNetwork(WindowsTunNetwork&&) noexcept;
        auto operator=(WindowsTunNetwork&&) noexcept -> WindowsTunNetwork&;
        WindowsTunNetwork(WindowsTunNetwork const&) = delete;
        auto operator=(WindowsTunNetwork const&) -> WindowsTunNetwork& = delete;

        [[nodiscard]] auto start(std::uint64_t adapter_luid, TunRoutePlan const& plan)
            -> std::expected<void, std::error_code>;
        auto stop() noexcept -> void;
        [[nodiscard]] auto active() const noexcept -> bool;
    };
}
