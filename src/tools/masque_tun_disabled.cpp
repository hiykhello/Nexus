module cli.masque_tun;
import std;
import config;
import relay;

namespace cli::tun_enabled {
    struct MasqueTunHost::Impl {};
    MasqueTunHost::MasqueTunHost(config::TunInbound, config::MasqueOutbound, std::optional<std::string>) {}
    MasqueTunHost::~MasqueTunHost() = default;
    auto MasqueTunHost::start(relay::Server&) -> std::expected<std::string, std::string> {
        return std::unexpected("MASQUE CONNECT-IP endpoint is unavailable in this build");
    }
    auto MasqueTunHost::healthy() const noexcept -> bool { return true; }
    auto MasqueTunHost::failure() const -> std::optional<std::string> { return {}; }
    auto MasqueTunHost::stop() noexcept -> void {}
}
