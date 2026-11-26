module dns.cache;
import std;
import containers.cache_index;
import dns.message;

namespace dns {
    namespace {
        auto normalize(CacheKey& key) -> bool {
            if (key.type!=1 && key.type!=28) return false;
            return canonicalize_name(key.name);
        }
        auto same(CacheKey const& a, CacheKey const& b) -> bool {
            return a.view==b.view && a.type==b.type && a.name==b.name;
        }
        auto key_hash(CacheKey const& key) noexcept -> std::size_t {
            return detail::SnapshotKeyHash{}(key);
        }
        auto valid_answer(AddressAnswer const& answer, std::uint16_t type) -> bool {
            if (answer.addresses.empty() || answer.addresses.size()>128 || answer.chain.size()>16 ||
                answer.canonical_name.size()>254 || !answer.ttl) return false;
            for (auto const& name : answer.chain) if (name.size()>254) return false;
            for (auto const& address : answer.addresses) if (address.size!=(type==1 ? 4 : 16)) return false;
            return true;
        }
        auto evict_deadline(std::uint64_t expires, bool negative, std::uint64_t stale_window_ms) noexcept -> std::uint64_t {
            if (negative || !stale_window_ms) return expires;
            if (stale_window_ms > std::numeric_limits<std::uint64_t>::max() - expires)
                return std::numeric_limits<std::uint64_t>::max();
            return expires + stale_window_ms;
        }
    }
    auto AddressCache::recompute_min_evict() noexcept -> void {
        auto min_at = std::numeric_limits<std::uint64_t>::max();
        entries_.for_each([&](Entry const& entry) {
            min_at = std::min(min_at, evict_deadline(entry.expires, entry.negative.has_value(), stale_window_ms_));
        });
        min_evict_at_ = min_at;
    }
    auto AddressCache::advance(std::uint64_t now) -> std::expected<void,CacheError> {
        if (initialized_ && now<now_) return std::unexpected(CacheError::time_reversed);
        now_=now; initialized_=true;
        if (now < min_evict_at_) return {};
        entries_.erase_if([this,now](Entry const& entry) {
            return now>=entry.expires && (entry.negative || now-entry.expires>=stale_window_ms_);
        });
        recompute_min_evict();
        return {};
    }
    auto AddressCache::lookup(CacheKey key, std::uint64_t now)
        -> std::expected<std::optional<AddressAnswer>,CacheError> {
        if (!normalize(key)) return std::unexpected(CacheError::invalid_key);
        if (snapshot_) return std::unexpected(CacheError::reader_required);
        auto const hash = key_hash(key);
        if (shared_) {
            std::shared_lock lock(mutex_);
            now=ordered(now);
            auto idx=entries_.find(hash,[&](Entry const& item) { return same(item.key,key); });
            if (!idx) return std::optional<AddressAnswer>{};
            auto const& entry=entries_.at(*idx);
            if (entry.negative || now>=entry.expires || (entry.expires-now)/1000==0)
                return std::optional<AddressAnswer>{};
            entries_.touch(*idx);
            auto answer=entry.answer;
            answer.ttl=static_cast<std::uint32_t>((entry.expires-now)/1000);
            return std::optional<AddressAnswer>(std::move(answer));
        }
        std::unique_lock lock(mutex_);
        if (auto result=advance(now); !result) return std::unexpected(result.error());
        auto idx=entries_.find(hash,[&](Entry const& item) { return same(item.key,key); });
        if (!idx) return std::optional<AddressAnswer>{};
        auto const& entry=entries_.at(*idx);
        if (entry.negative || now>=entry.expires) return std::optional<AddressAnswer>{};
        auto remaining=(entry.expires-now)/1000;
        if (!remaining) {
            if (!stale_window_ms_) entries_.erase(*idx);
            return std::optional<AddressAnswer>{};
        }
        entries_.touch(*idx);
        auto answer=entry.answer;
        answer.ttl=static_cast<std::uint32_t>(remaining);
        return std::optional<AddressAnswer>(std::move(answer));
    }
    auto AddressCache::lookup(CacheKey key, std::uint64_t now, Reader& reader)
        -> std::expected<std::optional<AddressAnswer>,CacheError> {
        if (snapshot_) {
            if (!reader.state_) throw std::invalid_argument("moved reader");
            return snapshot_->lookup(std::move(key),now,*reader.state_);
        }
        return lookup(std::move(key),now);
    }
    auto AddressCache::lookup_stale(CacheKey key, std::uint64_t now)
        -> std::expected<std::optional<StaleAddressAnswer>,CacheError> {
        if (!normalize(key)) return std::unexpected(CacheError::invalid_key);
        if (snapshot_) return std::unexpected(CacheError::reader_required);
        auto const hash = key_hash(key);
        std::unique_lock lock(mutex_); now=ordered(now);
        if (auto result=advance(now); !result) return std::unexpected(result.error());
        auto idx=entries_.find(hash,[&](Entry const& item) { return same(item.key,key); });
        if (!idx) return std::optional<StaleAddressAnswer>{};
        auto const& entry=entries_.at(*idx);
        if (entry.negative || now<entry.expires) return std::optional<StaleAddressAnswer>{};
        auto age=now-entry.expires;
        if (stale_window_ms_-age<1000) return std::optional<StaleAddressAnswer>{};
        entries_.touch(*idx);
        auto answer=entry.answer; answer.ttl=1;
        return std::optional<StaleAddressAnswer>(StaleAddressAnswer{std::move(answer),age});
    }
    auto AddressCache::lookup_stale(CacheKey key, std::uint64_t now, Reader& reader)
        -> std::expected<std::optional<StaleAddressAnswer>,CacheError> {
        if (snapshot_) {
            if (!reader.state_) throw std::invalid_argument("moved reader");
            reader.state_->validate(*snapshot_);
            return snapshot_->lookup_stale(std::move(key),now);
        }
        return lookup_stale(std::move(key),now);
    }
    auto AddressCache::lookup_negative(CacheKey key, std::uint64_t now)
        -> std::expected<std::optional<NegativeKind>,CacheError> {
        if (!normalize(key)) return std::unexpected(CacheError::invalid_key);
        if (snapshot_) return std::unexpected(CacheError::reader_required);
        auto const hash = key_hash(key);
        if (shared_) {
            std::shared_lock lock(mutex_); now=ordered(now);
            auto idx=entries_.find(hash,[&](Entry const& item) { return same(item.key,key); });
            if (!idx) return std::optional<NegativeKind>{};
            auto const& entry=entries_.at(*idx);
            if (!entry.negative || now>=entry.expires || (entry.expires-now)/1000==0)
                return std::optional<NegativeKind>{};
            entries_.touch(*idx);
            return entry.negative;
        }
        std::unique_lock lock(mutex_);
        if (auto result=advance(now); !result) return std::unexpected(result.error());
        auto idx=entries_.find(hash,[&](Entry const& item) { return same(item.key,key); });
        if (!idx) return std::optional<NegativeKind>{};
        auto const& entry=entries_.at(*idx);
        if (!entry.negative) return std::optional<NegativeKind>{};
        if ((entry.expires-now)/1000==0) { entries_.erase(*idx); return std::optional<NegativeKind>{}; }
        entries_.touch(*idx);
        return entry.negative;
    }
    auto AddressCache::lookup_negative(CacheKey key, std::uint64_t now, Reader& reader)
        -> std::expected<std::optional<NegativeKind>,CacheError> {
        if (snapshot_) {
            if (!reader.state_) throw std::invalid_argument("moved reader");
            return snapshot_->lookup_negative(std::move(key),now,*reader.state_);
        }
        return lookup_negative(std::move(key),now);
    }
    auto AddressCache::begin_query(CacheKey key) -> std::expected<CacheToken,CacheError> {
        if (snapshot_) return snapshot_->begin_query(std::move(key));
        if (!normalize(key)) return std::unexpected(CacheError::invalid_key);
        auto const hash = key_hash(key);
        std::unique_lock lock(mutex_);
        if (pending_.size()==4096) return std::unexpected(CacheError::query_limit);
        if (next_query_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(CacheError::generation_exhausted);
        if (!detail::compact_key_storage(key)) return std::unexpected(CacheError::invalid_key);
        auto query=next_query_+1;
        pending_.emplace(query,hash,Pending{std::move(key),query,{}});
        next_query_=query;
        return CacheToken{generation_,query};
    }
    auto AddressCache::refresh_current(Pending const& pending) const -> bool {
        if (!pending.refresh_revision) return true;
        auto idx=entries_.find(key_hash(pending.key),[&](Entry const& item) { return same(item.key,pending.key); });
        return idx && !entries_.at(*idx).negative && entries_.at(*idx).revision==*pending.refresh_revision;
    }
    auto AddressCache::begin_refresh(CacheKey key, std::uint64_t now, std::size_t max_registered_refreshes)
        -> std::expected<std::optional<CacheToken>,CacheError> {
        if (snapshot_) return snapshot_->begin_refresh(std::move(key),now,max_registered_refreshes);
        if (!normalize(key)) return std::unexpected(CacheError::invalid_key);
        auto const hash = key_hash(key);
        std::unique_lock lock(mutex_); now=ordered(now);
        if (auto result=advance(now); !result) return std::unexpected(result.error());
        auto idx=entries_.find(hash,[&](Entry const& item) { return same(item.key,key); });
        if (!idx) return std::optional<CacheToken>{};
        auto const& entry=entries_.at(*idx);
        if (entry.negative || now<entry.expires || stale_window_ms_-(now-entry.expires)<1000)
            return std::optional<CacheToken>{};
        if (pending_.has_key(hash,[&](Pending const& item) { return same(item.key,key); })) return std::optional<CacheToken>{};
        if (refresh_count_>=max_registered_refreshes) return std::optional<CacheToken>{};
        if (pending_.size()==4096) return std::unexpected(CacheError::query_limit);
        if (next_query_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(CacheError::generation_exhausted);
        if (!detail::compact_key_storage(key)) return std::unexpected(CacheError::invalid_key);
        auto query=next_query_+1;
        pending_.emplace(query,hash,Pending{std::move(key),query,entry.revision});
        ++refresh_count_;
        next_query_=query;
        return std::optional<CacheToken>{CacheToken{generation_,query}};
    }
    auto AddressCache::cancel_query(CacheToken token) -> std::expected<void,CacheError> {
        if (snapshot_) return snapshot_->cancel_query(token);
        std::unique_lock lock(mutex_);
        if (token.generation!=generation_) return std::unexpected(CacheError::stale_generation);
        auto pending=pending_.find_query(token.query);
        if (!pending) return std::unexpected(CacheError::stale_query);
        if (pending_.at(*pending).refresh_revision) --refresh_count_;
        pending_.erase(*pending);
        return {};
    }
    auto AddressCache::publish(CacheKey key, AddressAnswer answer, std::uint64_t now, CacheToken token)
        -> std::expected<void,CacheError> {
        if (snapshot_) return snapshot_->publish(std::move(key),std::move(answer),now,token);
        if (!normalize(key)) return std::unexpected(CacheError::invalid_key);
        if (!valid_answer(answer,key.type)) return std::unexpected(CacheError::invalid_answer);
        auto const hash = key_hash(key);
        std::unique_lock lock(mutex_); now=ordered(now);
        if (initialized_ && now<now_) return std::unexpected(CacheError::time_reversed);
        if (token.generation!=generation_) return std::unexpected(CacheError::stale_generation);
        auto pending=pending_.find_query(token.query);
        if (!pending || !same(pending_.at(*pending).key,key)) return std::unexpected(CacheError::stale_query);
        if (!capacity_) return std::unexpected(CacheError::disabled);
        auto duration=std::uint64_t(*answer.ttl)*1000;
        if (duration>std::numeric_limits<std::uint64_t>::max()-now) return std::unexpected(CacheError::invalid_answer);
        if (duration && !detail::compact_answer_storage(answer)) return std::unexpected(CacheError::invalid_answer);
        if (auto result=advance(now); !result) return result;
        if (!refresh_current(pending_.at(*pending))) return std::unexpected(CacheError::stale_query);
        if (duration==0) {
            if (auto idx=entries_.find(hash,[&](Entry const& entry) { return same(entry.key,key); }))
                entries_.erase(*idx);
        } else {
            Entry replacement{key,std::move(answer),{},now+duration,token.query};
            if (!detail::compact_key_storage(replacement.key)) return std::unexpected(CacheError::invalid_key);
            auto deadline = evict_deadline(replacement.expires, false, stale_window_ms_);
            entries_.upsert(hash, [&](Entry const& entry) { return same(entry.key,key); },
                std::move(replacement), [this,now](Entry const& entry) {
                    return now>=entry.expires && (entry.negative || now-entry.expires>=stale_window_ms_);
                });
            min_evict_at_ = std::min(min_evict_at_, deadline);
        }
        pending_.erase_key_if(hash,
            [&](std::uint64_t q, Pending const& item) { return q<=token.query && same(item.key,key); },
            [this](Pending const& item) { if (item.refresh_revision) --refresh_count_; });
        return {};
    }
    auto AddressCache::publish_negative(CacheKey key, NegativeKind kind, std::uint32_t ttl,
                                        std::uint64_t now, CacheToken token) -> std::expected<void,CacheError> {
        if (snapshot_) return snapshot_->publish_negative(std::move(key),kind,ttl,now,token);
        if (!normalize(key)) return std::unexpected(CacheError::invalid_key);
        auto const hash = key_hash(key);
        std::unique_lock lock(mutex_); now=ordered(now);
        if (initialized_ && now<now_) return std::unexpected(CacheError::time_reversed);
        if (token.generation!=generation_) return std::unexpected(CacheError::stale_generation);
        auto pending=pending_.find_query(token.query);
        if (!pending || !same(pending_.at(*pending).key,key)) return std::unexpected(CacheError::stale_query);
        if (!capacity_) return std::unexpected(CacheError::disabled);
        auto duration=std::uint64_t(ttl)*1000;
        if (duration>std::numeric_limits<std::uint64_t>::max()-now) return std::unexpected(CacheError::invalid_answer);
        if (auto result=advance(now); !result) return result;
        if (!refresh_current(pending_.at(*pending))) return std::unexpected(CacheError::stale_query);
        if (!duration) {
            if (auto idx=entries_.find(hash,[&](Entry const& entry) { return same(entry.key,key); }))
                entries_.erase(*idx);
        } else {
            Entry replacement{key,{},kind,now+duration,token.query};
            if (!detail::compact_key_storage(replacement.key)) return std::unexpected(CacheError::invalid_key);
            auto deadline = evict_deadline(replacement.expires, true, stale_window_ms_);
            entries_.upsert(hash, [&](Entry const& entry) { return same(entry.key,key); },
                std::move(replacement), [this,now](Entry const& entry) {
                    return now>=entry.expires && (entry.negative || now-entry.expires>=stale_window_ms_);
                });
            min_evict_at_ = std::min(min_evict_at_, deadline);
        }
        pending_.erase_key_if(hash,
            [&](std::uint64_t q, Pending const& item) { return q<=token.query && same(item.key,key); },
            [this](Pending const& item) { if (item.refresh_revision) --refresh_count_; });
        return {};
    }
    auto AddressCache::invalidate(CacheKey key, std::uint64_t now, CacheToken token)
        -> std::expected<void,CacheError> {
        if (snapshot_) return snapshot_->invalidate(std::move(key),now,token);
        if (!normalize(key)) return std::unexpected(CacheError::invalid_key);
        auto const hash = key_hash(key);
        std::unique_lock lock(mutex_); now=ordered(now);
        if (initialized_ && now<now_) return std::unexpected(CacheError::time_reversed);
        if (token.generation!=generation_) return std::unexpected(CacheError::stale_generation);
        auto pending=pending_.find_query(token.query);
        if (!pending || !same(pending_.at(*pending).key,key)) return std::unexpected(CacheError::stale_query);
        if (auto result=advance(now); !result) return result;
        if (!refresh_current(pending_.at(*pending))) return std::unexpected(CacheError::stale_query);
        if (auto idx=entries_.find(hash,[&](Entry const& entry) { return same(entry.key,key); }))
            entries_.erase(*idx);
        pending_.erase_key_if(hash,
            [&](std::uint64_t q, Pending const& item) { return q<=token.query && same(item.key,key); },
            [this](Pending const& item) { if (item.refresh_revision) --refresh_count_; });
        return {};
    }
    auto AddressCache::clear(std::uint64_t now) -> std::expected<void,CacheError> {
        if (snapshot_) return snapshot_->clear(now);
        std::unique_lock lock(mutex_); now=ordered(now);
        if (initialized_ && now<now_) return std::unexpected(CacheError::time_reversed);
        if (generation_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(CacheError::generation_exhausted);
        now_=now; initialized_=true; ++generation_; next_query_=0; entries_.clear(); pending_.clear(); refresh_count_=0;
        min_evict_at_=std::numeric_limits<std::uint64_t>::max();
        return {};
    }
}
