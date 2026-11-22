module cli.tun_resolved;
import std;
import packet.tun_network;

namespace cli::tun_enabled {
    auto start_tun_resolved(packet::TunNetworkLease<>&,std::string_view,
        TunResolvedLease::Clock::time_point,TunResolvedLease::Clock::time_point)
        -> std::expected<std::unique_ptr<TunResolvedLease>,TunResolvedError> {
        return std::unexpected(TunResolvedError::rejected);
    }
}
