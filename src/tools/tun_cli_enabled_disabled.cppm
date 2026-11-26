export module cli.tun_enabled;
import std;
import config;
import relay;
import cli.tun_disabled;
export namespace cli::tun_enabled {
    using Runtime = tun_disabled::Runtime;
    inline auto run_strict_tun_owner() -> int {return 2;}
    [[nodiscard]] inline auto update_active_tun_route_sets(relay::Server const*, config::TunInbound const&)
        -> std::expected<bool, std::string> { return false; }
}
