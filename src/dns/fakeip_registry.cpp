module dns.fakeip_registry;
import std;
import dns.fakeip;
import dns.fakeip_target;
import dns.fakeip_response;
namespace dns {
    auto FakeIpRegistry::add(std::uint32_t first,std::uint32_t last,std::unique_ptr<FakeIpPool> pool)
        -> std::expected<void,FakeIpRegistryError> {
        if (first>last || (pool && (pool->first_address()<first || pool->last_address()>last)))
            return std::unexpected(FakeIpRegistryError::invalid);
        for (auto const& range:ranges_)
            if (first<=range.last && range.first<=last) return std::unexpected(FakeIpRegistryError::overlap);
        if (ranges_.size()>=limit_) return std::unexpected(FakeIpRegistryError::full);
        auto active=pool!=nullptr;
        ranges_.push_back({first,last,std::move(pool),active,{}, {}});
        return {};
    }
    auto FakeIpRegistry::add_quarantined(std::uint32_t first,std::uint32_t last,
        std::uint32_t alloc_first,std::uint32_t alloc_last,std::chrono::seconds ttl,
        std::chrono::seconds grace,Clock::time_point start,Clock::duration interval)
        -> std::expected<void,FakeIpRegistryError> {
        if (interval<=Clock::duration::zero() || start>Clock::time_point::max()-interval)
            return std::unexpected(FakeIpRegistryError::invalid);
        auto pool=FakeIpPool::create(alloc_first,alloc_last,ttl,grace);
        if (!pool) return std::unexpected(FakeIpRegistryError::invalid);
        // The old configuration may require a longer interval; the current
        // protection period is a minimum, not evidence about historical TTLs.
        if (interval<std::chrono::duration_cast<Clock::duration>(ttl+grace))
            return std::unexpected(FakeIpRegistryError::invalid);
        auto result=add(first,last,std::move(*pool));
        if (!result) return result;
        ranges_.back().quarantine_start=start;
        ranges_.back().quarantine_end=start+interval;
        return {};
    }
    auto FakeIpRegistry::respond(std::uint32_t first,std::span<std::uint8_t const> query,
        std::uint64_t view,std::chrono::steady_clock::time_point now,std::optional<FakeIpIpv6Range> ipv6)
        -> std::expected<std::unique_ptr<FakeIpResponse>,std::variant<FakeIpRegistryError,FakeIpDnsError>> {
        using Error=std::variant<FakeIpRegistryError,FakeIpDnsError>;
        auto it=std::ranges::find(ranges_,first,&Range::first);
        if (it==ranges_.end()) return std::unexpected(Error{FakeIpRegistryError::missing});
        if (!it->active) return std::unexpected(Error{FakeIpRegistryError::inactive});
        if (it->quarantine_start && now<*it->quarantine_start) return std::unexpected(Error{FakeIpRegistryError::clock});
        if (it->quarantine_end && now<*it->quarantine_end) return std::unexpected(Error{FakeIpRegistryError::quarantine});
        auto result=fakeip_response(*it->pool,query,view,now,ipv6);
        if (!result) return std::unexpected(Error{result.error()});
        return std::move(*result);
    }
    auto FakeIpRegistry::retire(std::uint32_t first) -> std::expected<void,FakeIpRegistryError> {
        auto it=std::ranges::find(ranges_,first,&Range::first);
        if (it==ranges_.end()) return std::unexpected(FakeIpRegistryError::missing);
        if (!it->active) return std::unexpected(FakeIpRegistryError::inactive);
        it->active=false;
        return {};
    }
    auto FakeIpRegistry::contains(std::uint32_t address) const noexcept -> bool {
        return std::ranges::any_of(ranges_,[address](auto const& range) {
            return address>=range.first && address<=range.last;
        });
    }
    auto FakeIpRegistry::acquire(std::uint32_t address,std::uint64_t view,std::chrono::steady_clock::time_point now)
        -> std::expected<std::unique_ptr<FakeIpTarget>,FakeIpRegistryError> {
        for (auto const& range:ranges_) {
            if (address<range.first || address>range.last) continue;
            if (!range.active || !range.pool || !range.pool->contains(address)) return std::unexpected(FakeIpRegistryError::unknown);
            if (range.quarantine_start && now<*range.quarantine_start) return std::unexpected(FakeIpRegistryError::clock);
            if (range.quarantine_end && now<*range.quarantine_end) return std::unexpected(FakeIpRegistryError::unknown);
            auto target=acquire_fakeip_target(*range.pool,address,view,now);
            if (target && *target) return std::move(*target);
            if (target) return std::unexpected(FakeIpRegistryError::unknown);
            switch (target.error()) {
                case FakeIpTargetError::unknown: return std::unexpected(FakeIpRegistryError::unknown);
                case FakeIpTargetError::wrong_view: return std::unexpected(FakeIpRegistryError::wrong_view);
                case FakeIpTargetError::clock: return std::unexpected(FakeIpRegistryError::clock);
                case FakeIpTargetError::capacity: return std::unexpected(FakeIpRegistryError::capacity);
                case FakeIpTargetError::stale: return std::unexpected(FakeIpRegistryError::stale);
            }
        }
        return std::unique_ptr<FakeIpTarget>{};
    }
    auto FakeIpRegistry::flush_unpinned() noexcept -> std::size_t {
        std::size_t flushed=0;
        for (auto& range:ranges_) {
            if (range.active && range.pool) flushed+=range.pool->flush_unpinned();
        }
        return flushed;
    }
}
