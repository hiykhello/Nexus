module dns.fakeip;
import std;
namespace dns {
    namespace {
        auto canonicalize_to(std::string_view input,std::array<char,255>& storage) noexcept
            -> std::optional<std::string_view> {
            if (input.ends_with('.')) input.remove_suffix(1);
            if (input.empty() || input.size()>253) return {};
            std::size_t out=0, label=0;
            for (unsigned char c:input) {
                if (c=='.') { if (!label || label>63) return {}; label=0; storage[out++]='.'; continue; }
                if (!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-')) return {};
                ++label;
                storage[out++]=c>='A' && c<='Z' ? static_cast<char>(c+('a'-'A')) : static_cast<char>(c);
            }
            if (!label || label>63) return {};
            return std::string_view(storage.data(),out);
        }
    }
    auto FakeIpPool::forward_hash(std::uint64_t view,std::string_view domain) noexcept -> std::size_t {
        std::uint64_t h=14695981039346656037ull^(view*0x9e3779b97f4a7c15ull);
        for (unsigned char c:domain) { h^=c; h*=1099511628211ull; }
        h^=h>>33;
        h*=0xff51afd7ed558ccdull;
        h^=h>>33;
        return static_cast<std::size_t>(h);
    }
    auto FakeIpPool::index_find(std::uint64_t view,std::string_view domain) const noexcept
        -> std::optional<std::size_t> {
        auto const mask=index_.size()-1;
        auto slot=forward_hash(view,domain)&mask;
        for (;;) {
            auto idx=index_[slot];
            if (idx==empty_slot) return std::nullopt;
            auto const& e=entries_[idx];
            if (e.view==view && e.domain==domain) return idx;
            slot=(slot+1)&mask;
        }
    }
    auto FakeIpPool::index_insert(std::uint32_t entry_idx) noexcept -> void {
        auto const& e=entries_[entry_idx];
        auto const mask=index_.size()-1;
        auto slot=forward_hash(e.view,e.domain)&mask;
        while (index_[slot]!=empty_slot) {
            if (index_[slot]==entry_idx) return;
            slot=(slot+1)&mask;
        }
        index_[slot]=entry_idx;
    }
    auto FakeIpPool::index_erase(std::uint32_t entry_idx) noexcept -> void {
        auto const& e=entries_[entry_idx];
        auto const mask=index_.size()-1;
        auto slot=forward_hash(e.view,e.domain)&mask;
        while (index_[slot]!=empty_slot && index_[slot]!=entry_idx) slot=(slot+1)&mask;
        if (index_[slot]==empty_slot) return;
        auto hole=slot;
        for (;;) {
            slot=(slot+1)&mask;
            auto moved=index_[slot];
            if (moved==empty_slot) { index_[hole]=empty_slot; return; }
            auto const& me=entries_[moved];
            auto home=forward_hash(me.view,me.domain)&mask;
            if (((hole-home)&mask)<((slot-home)&mask)) {
                index_[hole]=moved;
                hole=slot;
            }
        }
    }
    FakeIpPool::FakeIpPool(std::uint32_t first,std::size_t count,std::chrono::seconds ttl,std::chrono::seconds grace)
        : first_(first),entries_(count),index_(std::bit_ceil(std::max<std::size_t>(count*2,8)),empty_slot),ttl_(ttl),grace_(grace) {}
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
        auto idx=static_cast<std::uint32_t>(address-first_);
        std::string owned(domain);
        entries_[idx]=Entry{std::move(owned),view,1,{},0};
        index_insert(idx);
        return true;
    }
    auto FakeIpPool::publish(std::string_view domain,std::uint64_t view,Clock::time_point now)
        -> std::expected<FakeIpLease,FakeIpError> {
        std::array<char,255> canonical_buf;
        auto canonical=canonicalize_to(domain,canonical_buf);
        if (!canonical) return std::unexpected(FakeIpError::invalid_name);
        if (!advance(now)) return std::unexpected(FakeIpError::time_reversed);
        auto duration=std::chrono::duration_cast<Clock::duration>(ttl_+grace_);
        if (now>Clock::time_point::max()-duration) return std::unexpected(FakeIpError::time_overflow);
        auto until=now+duration;
        if (durable_assign_) {
            auto address=durable_assign_(durable_store_,*canonical,view);
            if (!address || !contains(*address)) return std::unexpected(FakeIpError::full);
            auto idx=static_cast<std::uint32_t>(*address-first_);
            auto& entry=entries_[idx];
            if (!entry.generation) {
                std::string owned(*canonical);
                entry=Entry{std::move(owned),view,1,until,0};
                index_insert(idx);
            } else entry.reusable=std::max(entry.reusable,until);
            return FakeIpLease{*address,entry.generation,this};
        }
        if (auto found=index_find(view,*canonical)) {
            auto& e=entries_[*found];
            e.reusable=std::max(e.reusable,until);
            return FakeIpLease{static_cast<std::uint32_t>(first_+*found),e.generation,this};
        }
        if (generation_exhausted_) return std::unexpected(FakeIpError::exhausted);
        for (std::size_t n=0;n<entries_.size();++n) {
            auto i=(cursor_+n)%entries_.size(); auto& e=entries_[i];
            if (e.generation && (e.pins || now<e.reusable)) continue;
            std::string owned(*canonical);
            auto generation=next_generation_;
            if (generation==std::numeric_limits<std::uint64_t>::max()) generation_exhausted_=true;
            else ++next_generation_;
            if (e.generation) index_erase(static_cast<std::uint32_t>(i));
            e=Entry{std::move(owned),view,generation,until,0};
            index_insert(static_cast<std::uint32_t>(i));
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
