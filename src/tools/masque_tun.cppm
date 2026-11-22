export module cli.masque_tun;
import std;
import config;
import proxy;

export namespace cli::tun_enabled {
    class MasqueTunHost {
        struct Impl;
        std::unique_ptr<Impl> impl_;
    public:
        MasqueTunHost(config::TunInbound options, config::MasqueOutbound outbound, std::optional<std::string> lower_host);
        ~MasqueTunHost();
        MasqueTunHost(MasqueTunHost const&) = delete;
        auto operator=(MasqueTunHost const&) -> MasqueTunHost& = delete;
        auto start(proxy::Server&) -> std::expected<std::string, std::string>;
        auto healthy() const noexcept -> bool;
        auto failure() const -> std::optional<std::string>;
        auto stop() noexcept -> void;
    };
}
