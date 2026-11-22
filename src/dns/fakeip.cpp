module dns.fakeip;
import std;
namespace dns {
    namespace {
        auto name(std::string_view input) -> std::optional<std::string> {
            if (input.ends_with('.')) input.remove_suffix(1);
            if (input.empty() || input.size()>253) return {};
            std::string result; result.reserve(input.size());
            std::size_t label=0;
            for (unsigned char c:input) {
                if (c=='.') { if (!label || label>63) return {}; label=0; result.push_back('.'); continue; }
                if (!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-')) return {};
                ++label; result.push_back(c>='A' && c<='Z' ? static_cast<char>(c+('a'-'A')) : static_cast<char>(c));
            }
            if (!label || label>63) return {};
            return result;
        }
    }
    FakeIpPool::FakeIpPool(std::uint32_t first,std::size_t count,std::chrono::seconds ttl,std::chrono::seconds grace)
        : first_(first),entries_(count),ttl_(ttl),grace_(grace) {}
    auto FakeIpPool::create(std::uint32_t first,std::uint32_t last,std::chrono::seconds ttl,std::chrono::seconds grace)
        -> std::expected<std::unique_ptr<FakeIpPool>,FakeIpError> {
        if (last<first || static_cast<std::uint64_t>(last)-first+1>65536 || ttl.count()<=0 || grace.count()<0 ||
            ttl.count()>std::chrono::seconds::max().count()-grace.count()) return std::unexpected(FakeIpError::invalid_config);
        // Avoid overflowing steady_clock duration conversion or time addition.
        auto max_seconds=std::chrono::duration_cast<std::chrono::seconds>(Clock::duration::max()).count();
        if (ttl.count()+grace.count()>max_seconds) return std::unexpected(FakeIpError::invalid_config);
        return std::unique_ptr<FakeIpPool>(new FakeIpPool(first,static_cast<std::size_t>(static_cast<std::uint64_t>(last)-first+1),ttl,grace));
    }
    auto FakeIpPool::advance(Clock::time_point now) noexcept -> bool {
        if (last_ && now<*last_) return false;
        last_=now; return true;
    }
    auto FakeIpPool::restore(std::uint32_t address,std::uint64_t view,std::string_view domain) -> bool {
        if (!contains(address) || entries_[address-first_].generation) return false;
        entries_[address-first_]=Entry{std::string(domain),view,1,{},0};
        return true;
    }
    auto FakeIpPool::publish(std::string_view domain,std::uint64_t view,Clock::time_point now)
        -> std::expected<FakeIpLease,FakeIpError> {
        auto canonical=name(domain);
        if (!canonical) return std::unexpected(FakeIpError::invalid_name);
        if (!advance(now)) return std::unexpected(FakeIpError::time_reversed);
        auto duration=std::chrono::duration_cast<Clock::duration>(ttl_+grace_);
        if (now>Clock::time_point::max()-duration) return std::unexpected(FakeIpError::time_overflow);
        auto until=now+duration;
        if (durable_assign_) {
            auto address=durable_assign_(durable_store_,*canonical,view);
            if (!address || !contains(*address)) return std::unexpected(FakeIpError::full);
            auto& entry=entries_[*address-first_];
            if (!entry.generation) entry=Entry{std::move(*canonical),view,1,until,0};
            else entry.reusable=std::max(entry.reusable,until);
            return FakeIpLease{*address,entry.generation,this};
        }
        for (std::size_t i=0;i<entries_.size();++i) {
            auto& e=entries_[i];
            if (e.generation && e.view==view && e.domain==*canonical) {
                e.reusable=std::max(e.reusable,until);
                return FakeIpLease{static_cast<std::uint32_t>(first_+i),e.generation,this};
            }
        }
        if (generation_exhausted_) return std::unexpected(FakeIpError::exhausted);
        for (std::size_t n=0;n<entries_.size();++n) {
            auto i=(cursor_+n)%entries_.size(); auto& e=entries_[i];
            if (e.generation && (e.pins || now<e.reusable)) continue;
            auto generation=next_generation_;
            if (generation==std::numeric_limits<std::uint64_t>::max()) generation_exhausted_=true;
            else ++next_generation_;
            e=Entry{std::move(*canonical),view,generation,until,0};
            cursor_=(i+1)%entries_.size();
            return FakeIpLease{static_cast<std::uint32_t>(first_+i),generation,this};
        }
        return std::unexpected(FakeIpError::full);
    }
    auto FakeIpPool::lookup(std::uint32_t address,Clock::time_point now)
        -> std::expected<std::optional<FakeIpMapping>,FakeIpError> {
        if (!advance(now)) return std::unexpected(FakeIpError::time_reversed);
        if (address<first_ || static_cast<std::uint64_t>(address)-first_>=entries_.size()) return std::optional<FakeIpMapping>{};
        auto const& e=entries_[address-first_];
        if (!e.generation) return std::optional<FakeIpMapping>{};
        return std::optional{FakeIpMapping{{address,e.generation,this},e.domain,e.view}};
    }
    auto FakeIpPool::pin(FakeIpLease lease,Clock::time_point now) -> std::expected<void,FakeIpError> {
        if (!advance(now)) return std::unexpected(FakeIpError::time_reversed);
        if (lease.owner!=this || lease.address<first_ || static_cast<std::uint64_t>(lease.address)-first_>=entries_.size()) return std::unexpected(FakeIpError::stale);
        auto& e=entries_[lease.address-first_];
        if (!e.generation || e.generation!=lease.generation) return std::unexpected(FakeIpError::stale);
        if (e.pins==std::numeric_limits<std::size_t>::max()) return std::unexpected(FakeIpError::exhausted);
        ++e.pins; return {};
    }
    auto FakeIpPool::unpin(FakeIpLease lease,Clock::time_point now) -> std::expected<void,FakeIpError> {
        if (!advance(now)) return std::unexpected(FakeIpError::time_reversed);
        if (lease.owner!=this || lease.address<first_ || static_cast<std::uint64_t>(lease.address)-first_>=entries_.size()) return std::unexpected(FakeIpError::stale);
        auto& e=entries_[lease.address-first_];
        if (!e.generation || e.generation!=lease.generation) return std::unexpected(FakeIpError::stale);
        if (!e.pins) return std::unexpected(FakeIpError::pinned);
        --e.pins; return {};
    }
    auto FakeIpPool::finish_publication(FakeIpLease lease,Clock::time_point now) -> std::expected<void,FakeIpError> {
        if (!advance(now)) return std::unexpected(FakeIpError::time_reversed);
        if (lease.owner!=this || lease.address<first_ || static_cast<std::uint64_t>(lease.address)-first_>=entries_.size()) return std::unexpected(FakeIpError::stale);
        auto& e=entries_[lease.address-first_];
        if (!e.generation || e.generation!=lease.generation) return std::unexpected(FakeIpError::stale);
        if (!e.pins) return std::unexpected(FakeIpError::pinned);
        auto duration=std::chrono::duration_cast<Clock::duration>(ttl_+grace_);
        if (now>Clock::time_point::max()-duration) return std::unexpected(FakeIpError::time_overflow);
        e.reusable=std::max(e.reusable,now+duration);
        --e.pins; return {};
    }
}
