export module cli.tun_enabled;
import std;
import config;
import relay;
import cli.tun_host;
import cli.masque_tun;
import packet.tun_network_types;
export import cli.tun_network_owner;

export namespace cli::tun_enabled {
    class Runtime {
        struct Entry {
            config::TunInbound config;
            std::unique_ptr<TunHost> host;
            std::unique_ptr<MasqueTunHost> masque;
            bool device_adopted = false;
            packet::TunRedirectOptions redirect;
        };
        std::vector<std::optional<Entry>> entries_;
        std::optional<std::string> failure_;
    public:
        Runtime() = default;
        Runtime(Runtime const&) = delete;
        auto operator=(Runtime const&) -> Runtime& = delete;
        ~Runtime();
        auto resize(std::size_t) -> void;
        auto configure(std::size_t, config::InboundConfig const&, config::Config const&) -> std::expected<void, std::string>;
        auto start(std::size_t, relay::Server&) -> std::expected<std::string, std::string>;
        [[nodiscard]] auto queue_outbound_probe(std::size_t,std::shared_ptr<relay::OutboundProbe>) -> bool;
        auto healthy() const noexcept -> bool;
        auto owns_host_dns() const noexcept -> bool {
            return std::ranges::any_of(entries_,[](auto const& entry) {return entry && entry->config.host_dns_resolved;});
        }
        auto failure() const -> std::optional<std::string>;
        auto begin_drain() noexcept -> void;
        [[nodiscard]] auto drained() const noexcept -> bool;
        auto stop() noexcept -> void;
    };
}
