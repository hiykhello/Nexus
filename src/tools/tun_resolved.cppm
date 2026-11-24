module;
#include <proxy/proxy_macros.h>

export module cli.tun_resolved;
import std;
import proxy.v4;
import packet.tun_network;

export namespace cli::tun_enabled {
    using TunResolvedClock=std::chrono::steady_clock;
    PRO_DEF_MEM_DISPATCH(TunResolvedPoll,poll);
    PRO_DEF_MEM_DISPATCH(TunResolvedStop,stop);

    struct TunResolvedFacade : pro::facade_builder
        ::add_convention<TunResolvedPoll,bool(TunResolvedClock::time_point,TunResolvedClock::time_point)>
        ::add_convention<TunResolvedStop,bool(TunResolvedClock::time_point) noexcept>
        ::build {};

    using TunResolvedLease=pro::proxy<TunResolvedFacade>;

    enum class TunResolvedError { rejected, cleanup_failed };
    auto start_tun_resolved(packet::TunNetworkLease<>& network,std::string_view address,
        TunResolvedClock::time_point deadline,TunResolvedClock::time_point rollback_deadline)
        -> std::expected<TunResolvedLease,TunResolvedError>;
}
