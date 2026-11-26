export module cli.tuic_disabled;
import std;
import config;
import relay;
import cli.cert_reloader;
import logging.cli;

export namespace cli::tuic_disabled {
    class Runtime {
    public:
        auto resize(std::size_t) noexcept -> void {}
        auto configure(std::size_t, config::InboundConfig const& entry, std::shared_ptr<void> const& = {},
            cli::CertReloaderHub* = nullptr, logging::Runtime const* = nullptr) -> std::expected<void, std::string> {
            if (entry.tuic) return std::unexpected("TUIC is unavailable in this build");
            return {};
        }
        auto start(std::size_t, relay::Server&, std::uint16_t, bool, unsigned) -> std::expected<std::uint16_t, std::string> {
            return std::unexpected("TUIC is unavailable in this build");
        }
        auto healthy() const noexcept -> bool { return true; }
        [[nodiscard]] auto queue_outbound_probe(std::size_t,std::shared_ptr<relay::OutboundProbe>) noexcept -> bool {return false;}
        auto failure() const -> std::optional<std::string> { return {}; }
        auto stop() noexcept -> void {}
    };
}
