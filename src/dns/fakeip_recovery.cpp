module dns.fakeip_recovery;
import std;
import dns.fakeip_shared;
import dns.fakeip_registry;
namespace dns {
    auto update_fakeip_history(FakeIpRecoveryPool current,std::span<FakeIpHistoricalRange const> history)
        -> std::expected<std::vector<FakeIpHistoricalRange>,FakeIpRecoveryError> {
        using Seconds=std::chrono::seconds;
        if (history.size()>256) return std::unexpected(FakeIpRecoveryError::too_many_ranges);
        if (current.first>current.last || current.alloc_first<current.first || current.alloc_last>current.last ||
            current.alloc_first>current.alloc_last ||
            static_cast<std::uint64_t>(current.alloc_last)-current.alloc_first+1>65536 ||
            current.ttl<=Seconds::zero() || current.grace<Seconds::zero() ||
            current.ttl.count()>Seconds::max().count()-current.grace.count())
            return std::unexpected(FakeIpRecoveryError::invalid);
        auto protection=current.ttl+current.grace;
        if (protection>std::chrono::duration_cast<Seconds>(std::chrono::steady_clock::duration::max()))
            return std::unexpected(FakeIpRecoveryError::interval_overflow);
        std::vector<FakeIpHistoricalRange> entries(history.begin(),history.end());
        for (auto const& entry:entries)
            if (entry.first>entry.last || entry.protection<=Seconds::zero())
                return std::unexpected(FakeIpRecoveryError::invalid);
        entries.push_back({current.first,current.last,protection});
        std::ranges::sort(entries,{},&FakeIpHistoricalRange::first);
        std::vector<FakeIpHistoricalRange> merged;
        for (auto const& entry:entries) {
            if (!merged.empty() && static_cast<std::uint64_t>(entry.first)<=static_cast<std::uint64_t>(merged.back().last)+1) {
                merged.back().last=std::max(merged.back().last,entry.last);
                merged.back().protection=std::max(merged.back().protection,entry.protection);
            } else merged.push_back(entry);
        }
        if (merged.size()>256) return std::unexpected(FakeIpRecoveryError::too_many_ranges);
        return merged;
    }

    auto recover_fakeip(FakeIpRecoveryPool current,std::span<FakeIpHistoricalRange const> history,
        std::chrono::seconds transit,std::chrono::steady_clock::time_point start,std::shared_ptr<void> lifetime)
        -> std::expected<std::shared_ptr<FakeIpShared>,FakeIpRecoveryError> {
        using Clock=std::chrono::steady_clock;
        using Seconds=std::chrono::seconds;
        if (history.size()>256) return std::unexpected(FakeIpRecoveryError::too_many_ranges);
        if (current.first>current.last || current.alloc_first<current.first || current.alloc_last>current.last ||
            current.alloc_first>current.alloc_last || current.ttl<=Seconds::zero() || current.grace<Seconds::zero() ||
            transit<Seconds::zero() || current.ttl.count()>Seconds::max().count()-current.grace.count())
            return std::unexpected(FakeIpRecoveryError::invalid);
        auto maximum=current.ttl+current.grace;
        struct Range { std::uint32_t first,last; };
        std::vector<Range> ranges;
        ranges.reserve(history.size()*2);
        for (auto const& item:history) {
            if (item.first>item.last || item.protection<=Seconds::zero())
                return std::unexpected(FakeIpRecoveryError::invalid);
            maximum=std::max(maximum,item.protection);
            // Keep the historical portion outside the current pool reserved.
            if (item.first<current.first)
                ranges.push_back({item.first,std::min(item.last,static_cast<std::uint32_t>(current.first-1))});
            if (item.last>current.last)
                ranges.push_back({std::max(item.first,static_cast<std::uint32_t>(current.last+1)),item.last});
        }
        if (maximum.count()>Seconds::max().count()-transit.count())
            return std::unexpected(FakeIpRecoveryError::interval_overflow);
        auto interval=maximum+transit;
        if (interval>std::chrono::duration_cast<Seconds>(Clock::duration::max()))
            return std::unexpected(FakeIpRecoveryError::interval_overflow);
        std::ranges::sort(ranges,{},&Range::first);
        std::vector<Range> merged;
        for (auto range:ranges) {
            if (!merged.empty() && static_cast<std::uint64_t>(range.first)<=static_cast<std::uint64_t>(merged.back().last)+1)
                merged.back().last=std::max(merged.back().last,range.last);
            else merged.push_back(range);
        }
        auto owner=std::make_shared<FakeIpShared>(merged.size()+1,std::move(lifetime),current.ipv6);
        for (auto range:merged)
            if (!owner->reserve(range.first,range.last)) return std::unexpected(FakeIpRecoveryError::registry);
        if (!owner->add_quarantined(current.first,current.last,current.alloc_first,current.alloc_last,
                                    current.ttl,current.grace,start,interval) || !owner->seal())
            return std::unexpected(FakeIpRecoveryError::registry);
        return owner;
    }
}
