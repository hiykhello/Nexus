// Private implementation: import std, nexus.dns.message and nexus.dns.cache first.
#pragma once
#include "corosio_cached_resolve.hpp"

namespace nexus::dns::detail {
    enum class AddressStrategy { prefer_ipv4, prefer_ipv6, ipv4_only, ipv6_only };
    // A single owner/executor retains this object and its cache until completion.
    // Selected address families share one deadline; a transport or protocol
    // failure fails the operation instead of returning incomplete addresses.
    class DualAddressResolver {
        boost::corosio::io_context& context_;
        AddressCache& cache_;
        std::unique_ptr<CachedAddressResolver> active_;
        bool started_=false, canceled_=false, tcp_only_=false, disable_cache_=false, edns_=false;
        AddressStrategy strategy_;
    public:
        DualAddressResolver(boost::corosio::io_context& context, AddressCache& cache, bool tcp_only=false,
                            AddressStrategy strategy=AddressStrategy::prefer_ipv4, bool disable_cache=false, bool edns=false)
            : context_(context), cache_(cache), tcp_only_(tcp_only), disable_cache_(disable_cache), edns_(edns), strategy_(strategy) {}
        auto cancel() noexcept -> void { canceled_=true; if (active_) active_->cancel(); }
        auto resolve(boost::corosio::endpoint upstream, std::uint64_t view, std::string name,
                     std::chrono::steady_clock::time_point deadline)
            -> boost::capy::task<std::expected<std::vector<Address>,ResolveError>> {
            if (started_) co_return std::unexpected(ResolveError::state);
            started_=true;
            if (canceled_) co_return std::unexpected(ResolveError::canceled);
            std::vector<Address> addresses;
            std::optional<std::string> canonical;
            bool no_data_seen=false;
            auto types = strategy_==AddressStrategy::prefer_ipv6 || strategy_==AddressStrategy::ipv6_only ?
                std::array<std::uint16_t,2>{28,1} : std::array<std::uint16_t,2>{1,28};
            auto count = strategy_==AddressStrategy::ipv4_only || strategy_==AddressStrategy::ipv6_only ? 1u : 2u;
            for (unsigned i=0;i<count;++i) {
                auto type=types[i];
                active_=std::make_unique<CachedAddressResolver>(context_,cache_,tcp_only_,disable_cache_,edns_);
                auto result=co_await active_->resolve(upstream,view,{name,type},deadline);
                active_.reset();
                if (canceled_) co_return std::unexpected(ResolveError::canceled);
                if (!result) {
                    if (result.error()==ResolveError::no_data) { no_data_seen=true; continue; }
                    if (result.error()==ResolveError::name_not_found && (!addresses.empty() || no_data_seen))
                        co_return std::unexpected(ResolveError::protocol);
                    co_return std::unexpected(result.error());
                }
                if (canonical && *canonical!=result->canonical_name) co_return std::unexpected(ResolveError::protocol);
                canonical=result->canonical_name;
                if (result->addresses.size()>64-addresses.size()) co_return std::unexpected(ResolveError::limit);
                addresses.insert(addresses.end(),result->addresses.begin(),result->addresses.end());
            }
            if (addresses.empty()) co_return std::unexpected(ResolveError::no_data);
            co_return addresses;
        }
    };
}
