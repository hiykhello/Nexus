export module cli.tuic_disabled;
import std;
import config;
import proxy;

export namespace cli::tuic_disabled {
    class Runtime {
    public:
        auto resize(std::size_t) noexcept -> void {}
        auto configure(std::size_t, config::InboundConfig const& entry) -> std::expected<void, std::string> {
            if (entry.tuic) return std::unexpected("TUIC is unavailable in this build");
            return {};
        }
        auto start(std::size_t, proxy::Server&, std::uint16_t, bool, unsigned) -> std::expected<std::uint16_t, std::string> {
            return std::unexpected("TUIC is unavailable in this build");
        }
        auto healthy() const noexcept -> bool { return true; }
        [[nodiscard]] auto queue_outbound_probe(std::size_t,std::shared_ptr<proxy::OutboundProbe>) noexcept -> bool {return false;}
        auto failure() const -> std::optional<std::string> { return {}; }
        auto stop() noexcept -> void {}
    };
}
