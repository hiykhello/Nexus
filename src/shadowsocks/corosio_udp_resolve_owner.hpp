// Private implementation. Include after the imports required by
// corosio_udp_resolve.hpp. The owner and its dependencies must live until drained().
#pragma once
#include <boost/capy/ex/run_async.hpp>
#include "corosio_udp_resolve.hpp"

namespace nexus::shadowsocks::detail {
    struct UdpResolveOptions {
        bool tcp_only=false;
        dns::detail::AddressStrategy strategy=dns::detail::AddressStrategy::prefer_ipv4;
        bool disable_cache=false;
        bool edns=false;
    };
    enum class UdpResolveStartError { stopped, full, expired, duplicate };
    class UdpResolveOwner {
        using Clock=std::chrono::steady_clock;
        struct Entry { std::unique_ptr<UdpResolveOperation> operation; Clock::time_point deadline; };
        UdpDispatcher& dispatcher_;
        boost::corosio::io_context& context_;
        dns::AddressCache& cache_;
        std::map<std::uint64_t,Entry> active_;
        std::size_t limit_;
        bool stopped_=false;
        std::size_t succeeded_=0,failed_=0;
        // The active entry owns the operation until run finishes. Completion
        // erases it only after the awaited operation has returned or unwound.
        auto run(UdpResolveOperation& operation,boost::corosio::endpoint upstream,
                 std::uint64_t view,Clock::time_point deadline) -> boost::capy::task<> {
            auto result=co_await operation.run(upstream,view,deadline);
            if (result) ++succeeded_; else ++failed_;
        }
        auto done(std::uint64_t token,bool exception) noexcept -> void {
            auto it=active_.find(token);
            if (it==active_.end()) return;
            if (exception) { ++failed_; it->second.operation->cancel(); }
            active_.erase(it);
        }
    public:
        UdpResolveOwner(UdpDispatcher& dispatcher,boost::corosio::io_context& context,dns::AddressCache& cache,std::size_t limit)
            : dispatcher_(dispatcher),context_(context),cache_(cache),limit_(limit) {}
        UdpResolveOwner(UdpResolveOwner const&)=delete;
        auto operator=(UdpResolveOwner const&) -> UdpResolveOwner& = delete;
        // Every method and completion must run on the same executor. On failure
        // to start, the supplied pending token is canceled before return.
        [[nodiscard]] auto start(UdpPending pending,boost::corosio::endpoint upstream,std::uint64_t view,
            Clock::time_point now,Clock::time_point deadline,
            dns::detail::AddressStrategy strategy=dns::detail::AddressStrategy::prefer_ipv4,
            bool tcp_only=false,bool disable_cache=false,bool edns=false,std::vector<UdpResolveHop> hops={})
            -> std::expected<void,UdpResolveStartError> {
            auto token=pending.token;
            auto reject=[&](UdpResolveStartError error) -> std::expected<void,UdpResolveStartError> {
                (void)dispatcher_.cancel(token); return std::unexpected(error);
            };
            if (active_.contains(token)) return std::unexpected(UdpResolveStartError::duplicate);
            if (stopped_) return reject(UdpResolveStartError::stopped);
            if (active_.size()>=limit_) return reject(UdpResolveStartError::full);
            if (deadline<=now) return reject(UdpResolveStartError::expired);
            std::unique_ptr<UdpResolveOperation> operation;
            try { operation=std::make_unique<UdpResolveOperation>(dispatcher_,context_,cache_,std::move(pending),tcp_only,strategy,disable_cache,edns,std::move(hops)); }
            catch (...) { (void)dispatcher_.cancel(token); throw; }
            auto [it,inserted]=active_.emplace(token,Entry{std::move(operation),deadline});
            if (!inserted) return reject(UdpResolveStartError::full);
            try {
                boost::capy::run_async(context_.get_executor(),[this,token] { done(token,false); },
                    [this,token](std::exception_ptr) noexcept { done(token,true); })(run(*it->second.operation,upstream,view,deadline));
            } catch (...) { it->second.operation->cancel(); active_.erase(it); throw; }
            return {};
        }
        auto cancel_expired(Clock::time_point now) noexcept -> void {
            for (auto& [token,entry]:active_) if (entry.deadline<=now) entry.operation->cancel();
        }
        auto stop() noexcept -> void {
            stopped_=true;
            for (auto& [token,entry]:active_) entry.operation->cancel();
        }
        [[nodiscard]] auto drained() const noexcept -> bool { return active_.empty(); }
        [[nodiscard]] auto active() const noexcept -> std::size_t { return active_.size(); }
        [[nodiscard]] auto succeeded() const noexcept -> std::size_t { return succeeded_; }
        [[nodiscard]] auto failed() const noexcept -> std::size_t { return failed_; }
    };
}
