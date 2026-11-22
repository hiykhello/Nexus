export module cli.masque_disabled;
import std;
import config;
import proxy;
export namespace cli::masque_disabled {
    class Runtime {
    public:
        explicit Runtime(bool) noexcept {}
        auto resize(std::size_t) noexcept -> void {}
        auto configure(std::size_t,config::InboundConfig const& entry) -> std::expected<void,std::string> {
            if(entry.masque)return std::unexpected("MASQUE is unavailable in this build");return {};
        }
        auto start(std::size_t,proxy::Server&,std::uint16_t,unsigned) -> std::expected<std::uint16_t,std::string> {return std::unexpected("MASQUE is unavailable in this build");}
        auto healthy() const noexcept -> bool {return true;}
        auto failure() const -> std::optional<std::string> {return {};}
        auto stop() noexcept -> void {}
    };
}
