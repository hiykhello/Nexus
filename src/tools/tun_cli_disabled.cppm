export module cli.tun_disabled;
import std;
import config;
import proxy;

export namespace cli::tun_disabled {
    class Runtime {
    public:
        auto resize(std::size_t) noexcept -> void {}
        auto configure(std::size_t, config::InboundConfig const& entry, config::Config const&) -> std::expected<void, std::string> {
            if (entry.tun) return std::unexpected("TUN inbound is unavailable in this build");
            return {};
        }
        auto start(std::size_t, proxy::Server&) -> std::expected<std::string, std::string> {
            return std::unexpected("TUN inbound is unavailable in this build");
        }
        auto owns_host_dns() const noexcept -> bool {return false;}
        auto healthy() const noexcept -> bool { return true; }
        [[nodiscard]] auto queue_outbound_probe(std::size_t,std::shared_ptr<proxy::OutboundProbe>) noexcept -> bool {return false;}
        auto failure() const -> std::optional<std::string> { return {}; }
        auto stop() noexcept -> void {}
    };
}
