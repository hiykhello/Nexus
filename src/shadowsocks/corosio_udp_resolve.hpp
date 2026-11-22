// Private implementation: import std, nexus.dns.message, nexus.dns.cache and
// nexus.shadowsocks.udp_dispatch before including. Owner, dispatcher, context
// and cache must live until the task completes, including cancellation.
#pragma once
#ifndef NEXUS_DNS_USE_MODULES
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#endif

namespace shadowsocks::detail {
#ifdef NEXUS_DNS_USE_MODULES
    namespace udp_io=nex::corosio;
    namespace udp_capy=nex::capy;
#else
    namespace udp_io=boost::corosio;
    namespace udp_capy=boost::capy;
#endif
#ifdef NEXUS_TEST_DNS_GROUP
    using UdpDnsCache=dns_hp_experiment::GroupBinding;
#else
    using UdpDnsCache=dns::AddressCache;
#endif
    using UdpDnsResolver=dns::detail::BasicDualAddressResolver<UdpDnsCache>;
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
    using UdpDnsRefresh=dns::detail::BasicRefreshOwner<UdpDnsCache>;
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
    inline auto udp_coordinated_strategy(dns::detail::AddressStrategy value) -> dns_hp_experiment::CoordinatedStrategy {
        using Source=dns::detail::AddressStrategy;
        using Target=dns_hp_experiment::CoordinatedStrategy;
        switch (value) {
        case Source::prefer_ipv4: return Target::prefer_ipv4;
        case Source::prefer_ipv6: return Target::prefer_ipv6;
        case Source::ipv4_only: return Target::ipv4_only;
        case Source::ipv6_only: return Target::ipv6_only;
        }
        std::terminate();
    }
#endif
    struct UdpResolveHop { std::string host; std::uint16_t port; std::uint64_t view; bool tcp_only; };
    enum class UdpResolveError { state, invalid_target, dns, dispatch, canceled };
    class UdpResolveOperation {
        UdpDispatcher& dispatcher_;
        udp_io::io_context& context_;
        UdpDnsCache& cache_;
        UdpDnsCache::Reader* reader_;
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
        UdpDnsRefresh* refresh_;
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
        dns_hp_experiment::CoordinatorOwner* coordinator_;
        dns_hp_experiment::ViewBinding* views_;
        bool optimistic_;
        std::optional<dns_hp_experiment::CoordinatorQuery> resolver_;
#else
        std::unique_ptr<UdpDnsResolver> resolver_;
#endif
        std::unique_ptr<dns::detail::LocalAddressResolver> local_resolver_;
        std::shared_ptr<dns::LocalSnapshot const> local_snapshot_;
        std::size_t* local_rotation_;
        UdpPending pending_;
        std::vector<UdpResolveHop> hops_;
        dns::detail::AddressStrategy strategy_;
        bool tcp_only_,disable_cache_,edns_;
        bool started_=false, canceled_=false, finished_=false;
    public:
        UdpResolveOperation(UdpDispatcher& dispatcher, udp_io::io_context& context,
            UdpDnsCache& cache,UdpPending pending,bool tcp_only=false,
            dns::detail::AddressStrategy strategy=dns::detail::AddressStrategy::prefer_ipv4,
            bool disable_cache=false,bool edns=false,std::vector<UdpResolveHop> hops={},
            std::shared_ptr<dns::LocalSnapshot const> local_snapshot={},std::size_t* local_rotation=nullptr,
            UdpDnsCache::Reader* reader=nullptr
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
            ,UdpDnsRefresh* refresh=nullptr
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
            ,dns_hp_experiment::CoordinatorOwner* coordinator=nullptr,dns_hp_experiment::ViewBinding* views=nullptr,bool optimistic=false
#endif
            )
            : dispatcher_(dispatcher),context_(context),cache_(cache),reader_(reader),
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
              refresh_(refresh),
#endif
#ifdef NEXUS_TEST_DNS_COORDINATOR
              coordinator_(coordinator),views_(views),optimistic_(optimistic),
#endif
              pending_(std::move(pending)),hops_(std::move(hops)),
              strategy_(strategy),tcp_only_(tcp_only),disable_cache_(disable_cache),edns_(edns),
              local_snapshot_(std::move(local_snapshot)),local_rotation_(local_rotation) {}
        UdpResolveOperation(UdpResolveOperation const&)=delete;
        auto operator=(UdpResolveOperation const&) -> UdpResolveOperation& = delete;
        ~UdpResolveOperation() { if (!finished_) cancel(); }
        // Serialized on the same executor as run(); cancellation removes the
        // token immediately but the object remains alive until completion.
        auto cancel() noexcept -> void {
            canceled_=true; if (resolver_) resolver_->cancel(); if (local_resolver_) local_resolver_->cancel(); (void)dispatcher_.cancel(pending_.token);
        }
        auto query(std::vector<udp_io::endpoint> const& upstreams,std::uint64_t view,bool tcp,
                   std::string const& name,std::chrono::steady_clock::time_point deadline)
            -> udp_capy::task<std::expected<std::vector<dns::Address>,dns::detail::ResolveError>> {
            if (upstreams.size()==1 && upstreams.front().port()==0) {
                if (canceled_) co_return std::unexpected(dns::detail::ResolveError::canceled);
                if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(dns::detail::ResolveError::timeout);
                if (!local_snapshot_) co_return std::unexpected(dns::detail::ResolveError::state);
                auto rotation=local_snapshot_->config.rotate && local_rotation_ ? (*local_rotation_)++ : 0;
                local_resolver_=std::make_unique<dns::detail::LocalAddressResolver>(context_,local_snapshot_->config,local_snapshot_->hosts,strategy_,rotation);
                auto addresses=co_await local_resolver_->resolve(name,deadline);
                local_resolver_.reset();
                if (canceled_) co_return std::unexpected(dns::detail::ResolveError::canceled);
                co_return addresses;
            }
            for (auto const& upstream:upstreams) {
                if (canceled_) co_return std::unexpected(dns::detail::ResolveError::canceled);
#ifdef NEXUS_TEST_DNS_COORDINATOR
                if (!coordinator_ || !views_ || !reader_ || !view)
                    co_return std::unexpected(dns::detail::ResolveError::state);
                auto bound=views_->view(static_cast<std::size_t>(view-1),upstream);
                if (!bound) co_return std::unexpected(bound.error()==dns_hp_experiment::ViewRegistry::Error::limit ||
                    bound.error()==dns_hp_experiment::ViewRegistry::Error::allocation ? dns::detail::ResolveError::limit : dns::detail::ResolveError::state);
                resolver_.emplace(*coordinator_,reader_,udp_coordinated_strategy(strategy_),tcp,disable_cache_,edns_,optimistic_);
                auto result=co_await resolver_->resolve(upstream,*bound,name,deadline);
                resolver_.reset();
                if (canceled_) co_return std::unexpected(dns::detail::ResolveError::canceled);
                if (result) co_return std::move(*result);
                if (result.error()!=dns_hp_experiment::CoordinatedError::transport)
                    co_return std::unexpected(dns::detail::ResolveError::state);
#else
                resolver_=std::make_unique<UdpDnsResolver>(context_,cache_,tcp,strategy_,disable_cache_,edns_,
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
                    refresh_,
#else
                    nullptr,
#endif
                    reader_);
                auto result=co_await resolver_->resolve(upstream,view,name,deadline);
                resolver_.reset();
                if (canceled_) co_return std::unexpected(dns::detail::ResolveError::canceled);
                if (result || result.error()!=dns::detail::ResolveError::transport) co_return result;
#endif
            }
            co_return std::unexpected(dns::detail::ResolveError::transport);
        }
        auto run(udp_io::endpoint upstream,std::uint64_t view,std::chrono::steady_clock::time_point deadline)
            -> udp_capy::task<std::expected<void,UdpResolveError>> {
            if (started_) co_return std::unexpected(UdpResolveError::state);
            started_=true;
            if (canceled_) { finished_=true; co_return std::unexpected(UdpResolveError::canceled); }
            auto const& a=pending_.address;
            if (a.size()<5 || a[0]!=3 || !a[1] || a.size()!=static_cast<std::size_t>(a[1])+4) {
                (void)dispatcher_.cancel(pending_.token); finished_=true;
                co_return std::unexpected(UdpResolveError::invalid_target);
            }
            std::string name(a.begin()+2,a.end()-2);
            auto port=static_cast<std::uint16_t>((static_cast<unsigned>(a[a.size()-2])<<8)|a.back());
            std::vector<udp_io::endpoint> upstreams{upstream};
            auto tcp=tcp_only_;
            for (auto const& hop:hops_) {
                auto resolved=co_await query(upstreams,view,tcp,hop.host,deadline);
                if (canceled_) { finished_=true; co_return std::unexpected(UdpResolveError::canceled); }
                if (!resolved) { (void)dispatcher_.cancel(pending_.token); finished_=true; co_return std::unexpected(UdpResolveError::dns); }
                upstreams.clear();
                for (auto const& address:*resolved) {
                    if (address.size==4) {
                        udp_io::ipv4_address::bytes_type bytes{}; std::copy_n(address.bytes.begin(),4,bytes.begin());
                        upstreams.emplace_back(udp_io::ipv4_address(bytes),hop.port);
                    } else if (address.size==16) {
                        udp_io::ipv6_address::bytes_type bytes{}; std::ranges::copy(address.bytes,bytes.begin());
                        upstreams.emplace_back(udp_io::ipv6_address(bytes),hop.port);
                    } else { (void)dispatcher_.cancel(pending_.token); finished_=true; co_return std::unexpected(UdpResolveError::dns); }
                }
                view=hop.view; tcp=hop.tcp_only;
            }
            auto result=co_await query(upstreams,view,tcp,name,deadline);
            if (canceled_) { finished_=true; co_return std::unexpected(UdpResolveError::canceled); }
            if (!result) {
                (void)dispatcher_.cancel(pending_.token); finished_=true;
                co_return std::unexpected(UdpResolveError::dns);
            }
            std::vector<UdpPeer> candidates; candidates.reserve(result->size());
            for (auto const& address:*result) {
                if (address.size!=4 && address.size!=16) {
                    (void)dispatcher_.cancel(pending_.token); finished_=true;
                    co_return std::unexpected(UdpResolveError::dns);
                }
                candidates.push_back({address.size==4 ? std::uint8_t{4} : std::uint8_t{6},address.bytes,port});
            }
            auto sent=dispatcher_.complete(pending_.token,candidates,std::chrono::steady_clock::now());
            finished_=true;
            if (!sent) co_return std::unexpected(UdpResolveError::dispatch);
            co_return std::expected<void,UdpResolveError>{};
        }
    };
}
