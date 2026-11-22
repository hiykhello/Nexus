module cli.tun_resolved;
import std;
import packet.tun_network;
import dns.local_config;
import endpoint.host_dns_types;
import endpoint.resolved_dns;

namespace cli::tun_enabled {
    namespace {
        class ResolvedLease final : public TunResolvedLease {
        public:
            endpoint::ResolvedHostDns<> resolver;
            auto poll(Clock::time_point now,Clock::time_point deadline) -> bool override {
                return resolver.poll(now,deadline).has_value();
            }
            auto stop(Clock::time_point deadline) noexcept -> bool override {
                auto result=resolver.stop(deadline);
                return result.restored || result.preserved;
            }
        };
    }

    auto start_tun_resolved(packet::TunNetworkLease<>& network,std::string_view address,
        TunResolvedLease::Clock::time_point deadline,TunResolvedLease::Clock::time_point rollback_deadline)
        -> std::expected<std::unique_ptr<TunResolvedLease>,TunResolvedError> {
        auto parsed=dns::parse_local_address(address);
        if (!parsed) return std::unexpected(TunResolvedError::rejected);
        auto lease=std::make_unique<ResolvedLease>();
        endpoint::HostDnsOptions options{endpoint::HostDnsBackend::resolved,{*parsed},1};
        if (!lease->resolver.start(network,options,true,deadline,rollback_deadline,true))
            return std::unexpected(lease->stop(rollback_deadline) ?
                TunResolvedError::rejected : TunResolvedError::cleanup_failed);
        return lease;
    }
}
