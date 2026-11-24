module cli.tun_resolved;
import std;
import packet.tun_network;

namespace cli::tun_enabled {
    auto start_tun_resolved(packet::TunNetworkLease<>&,std::string_view,
        TunResolvedClock::time_point,TunResolvedClock::time_point)
        -> std::expected<TunResolvedLease,TunResolvedError> {
        return std::unexpected(TunResolvedError::rejected);
    }
}
