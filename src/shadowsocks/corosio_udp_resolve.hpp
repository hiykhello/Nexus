// Private implementation: import std, nexus.dns.message, nexus.dns.cache and
// nexus.shadowsocks.udp_dispatch before including. Owner, dispatcher, context
// and cache must live until the task completes, including cancellation.
#pragma once
#include "../dns/corosio_dual_resolve.hpp"
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/resolver.hpp>

namespace nexus::shadowsocks::detail {
    struct UdpResolveHop { std::string host; std::uint16_t port; std::uint64_t view; bool tcp_only; };
    enum class UdpResolveError { state, invalid_target, dns, dispatch, canceled };
    class UdpResolveOperation {
        UdpDispatcher& dispatcher_;
        boost::corosio::io_context& context_;
        dns::AddressCache& cache_;
        std::unique_ptr<dns::detail::DualAddressResolver> resolver_;
        std::unique_ptr<boost::corosio::resolver> system_resolver_;
        UdpPending pending_;
        std::vector<UdpResolveHop> hops_;
        dns::detail::AddressStrategy strategy_;
        bool tcp_only_,disable_cache_,edns_;
        bool started_=false, canceled_=false, finished_=false;
    public:
        UdpResolveOperation(UdpDispatcher& dispatcher, boost::corosio::io_context& context,
            dns::AddressCache& cache,UdpPending pending,bool tcp_only=false,
            dns::detail::AddressStrategy strategy=dns::detail::AddressStrategy::prefer_ipv4,
            bool disable_cache=false,bool edns=false,std::vector<UdpResolveHop> hops={})
            : dispatcher_(dispatcher),context_(context),cache_(cache),pending_(std::move(pending)),hops_(std::move(hops)),
              strategy_(strategy),tcp_only_(tcp_only),disable_cache_(disable_cache),edns_(edns) {}
        UdpResolveOperation(UdpResolveOperation const&)=delete;
        auto operator=(UdpResolveOperation const&) -> UdpResolveOperation& = delete;
        ~UdpResolveOperation() { if (!finished_) cancel(); }
        // Serialized on the same executor as run(); cancellation removes the
        // token immediately but the object remains alive until completion.
        auto cancel() noexcept -> void {
            canceled_=true; if (resolver_) resolver_->cancel(); if (system_resolver_) system_resolver_->cancel(); (void)dispatcher_.cancel(pending_.token);
        }
        auto query(std::vector<boost::corosio::endpoint> const& upstreams,std::uint64_t view,bool tcp,
                   std::string const& name,std::chrono::steady_clock::time_point deadline)
            -> boost::capy::task<std::expected<std::vector<dns::Address>,dns::detail::ResolveError>> {
            if (upstreams.size()==1 && upstreams.front().port()==0) {
                if (canceled_) co_return std::unexpected(dns::detail::ResolveError::canceled);
                if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(dns::detail::ResolveError::timeout);
                system_resolver_=std::make_unique<boost::corosio::resolver>(context_);
                auto [error,ips]=co_await system_resolver_->resolve(name);
                system_resolver_.reset();
                if (canceled_) co_return std::unexpected(dns::detail::ResolveError::canceled);
                if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(dns::detail::ResolveError::timeout);
                if (error || ips.empty()) co_return std::unexpected(dns::detail::ResolveError::transport);
                if (ips.size()>64) co_return std::unexpected(dns::detail::ResolveError::limit);
                std::vector<dns::Address> addresses;
                for (auto const& ip:ips) {
                    dns::Address address{};
                    if (ip.is_v4()) {
                        if (strategy_==dns::detail::AddressStrategy::ipv6_only) continue;
                        auto bytes=ip.to_v4().to_bytes(); std::ranges::copy(bytes,address.bytes.begin()); address.size=4;
                    } else if (ip.is_v6()) {
                        if (strategy_==dns::detail::AddressStrategy::ipv4_only || ip.to_v6().scope_id()!=0) continue;
                        auto bytes=ip.to_v6().to_bytes(); std::ranges::copy(bytes,address.bytes.begin()); address.size=16;
                    } else continue;
                    addresses.push_back(address);
                }
                if (addresses.empty()) co_return std::unexpected(dns::detail::ResolveError::no_data);
                auto preferred=strategy_==dns::detail::AddressStrategy::prefer_ipv6 ? 16u : 4u;
                std::stable_partition(addresses.begin(),addresses.end(),[preferred](auto const& a) { return a.size==preferred; });
                co_return addresses;
            }
            for (auto const& upstream:upstreams) {
                if (canceled_) co_return std::unexpected(dns::detail::ResolveError::canceled);
                resolver_=std::make_unique<dns::detail::DualAddressResolver>(context_,cache_,tcp,strategy_,disable_cache_,edns_);
                auto result=co_await resolver_->resolve(upstream,view,name,deadline);
                resolver_.reset();
                if (canceled_) co_return std::unexpected(dns::detail::ResolveError::canceled);
                if (result || result.error()!=dns::detail::ResolveError::transport) co_return result;
            }
            co_return std::unexpected(dns::detail::ResolveError::transport);
        }
        auto run(boost::corosio::endpoint upstream,std::uint64_t view,std::chrono::steady_clock::time_point deadline)
            -> boost::capy::task<std::expected<void,UdpResolveError>> {
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
            std::vector<boost::corosio::endpoint> upstreams{upstream};
            auto tcp=tcp_only_;
            for (auto const& hop:hops_) {
                auto resolved=co_await query(upstreams,view,tcp,hop.host,deadline);
                if (canceled_) { finished_=true; co_return std::unexpected(UdpResolveError::canceled); }
                if (!resolved) { (void)dispatcher_.cancel(pending_.token); finished_=true; co_return std::unexpected(UdpResolveError::dns); }
                upstreams.clear();
                for (auto const& address:*resolved) {
                    if (address.size==4) {
                        boost::corosio::ipv4_address::bytes_type bytes{}; std::copy_n(address.bytes.begin(),4,bytes.begin());
                        upstreams.emplace_back(boost::corosio::ipv4_address(bytes),hop.port);
                    } else if (address.size==16) {
                        boost::corosio::ipv6_address::bytes_type bytes{}; std::ranges::copy(address.bytes,bytes.begin());
                        upstreams.emplace_back(boost::corosio::ipv6_address(bytes),hop.port);
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
