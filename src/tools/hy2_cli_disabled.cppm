export module cli.hy2_disabled;
import std;
import config;
import proxy;
export namespace cli::hy2_disabled {
    class Runtime {
    public:
        auto resize(std::size_t) noexcept -> void {}
        auto configure_outbound(config::Config const&) -> std::expected<void,std::string> {return {};}
        auto configure(std::size_t,config::InboundConfig const& entry) -> std::expected<void,std::string> {
            if(entry.hysteria2)return std::unexpected("Hysteria2 is unavailable in this build");return {};
        }
        auto start(std::size_t,proxy::Server&,std::uint16_t,bool,unsigned) -> std::expected<std::uint16_t,std::string> {
            return std::unexpected("Hysteria2 is unavailable in this build");
        }
        auto healthy()const noexcept -> bool {return true;}
        [[nodiscard]] auto queue_outbound_probe(std::size_t,std::shared_ptr<proxy::OutboundProbe>) noexcept -> bool {return false;}
        auto failure()const ->std::optional<std::string>{return {};}
        auto stop()noexcept ->void {}
    };
}
