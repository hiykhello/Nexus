export module cli.tun_resolved;
import std;
import packet.tun_network;

export namespace cli::tun_enabled {
    class TunResolvedLease {
    public:
        using Clock=std::chrono::steady_clock;
        virtual ~TunResolvedLease()=default;
        virtual auto poll(Clock::time_point now,Clock::time_point deadline) -> bool=0;
        virtual auto stop(Clock::time_point deadline) noexcept -> bool=0;
    };

    enum class TunResolvedError { rejected, cleanup_failed };
    auto start_tun_resolved(packet::TunNetworkLease<>& network,std::string_view address,
        TunResolvedLease::Clock::time_point deadline,TunResolvedLease::Clock::time_point rollback_deadline)
        -> std::expected<std::unique_ptr<TunResolvedLease>,TunResolvedError>;
}
