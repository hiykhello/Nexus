module shadowsocks.replay;
import std;
import platform.wall_clock;
namespace shadowsocks {
    namespace {
        auto hash_salt(std::span<std::uint8_t const> salt) noexcept -> std::uint32_t {
            std::uint64_t h = 0x9e3779b97f4a7c15ull ^ static_cast<std::uint64_t>(salt.size());
            std::uint64_t w0 = 0, w1 = 0;
            std::memcpy(&w0, salt.data(), 8);
            std::memcpy(&w1, salt.data() + 8, 8);
            h ^= w0; h *= 0xbf58476d1ce4e5b9ull;
            h ^= w1; h *= 0x94d049bb133111ebull;
            if (salt.size() == 32) {
                std::uint64_t w2 = 0, w3 = 0;
                std::memcpy(&w2, salt.data() + 16, 8);
                std::memcpy(&w3, salt.data() + 24, 8);
                h ^= w2; h *= 0xbf58476d1ce4e5b9ull;
                h ^= w3; h *= 0x94d049bb133111ebull;
            }
            h ^= h >> 32;
            return static_cast<std::uint32_t>(h);
        }
    }

    auto ReplayTable::Shard::expire_locked(std::chrono::steady_clock::time_point now) noexcept -> std::size_t {
        if (!count) return 0;
        std::size_t expired = 0;
        auto const rmask = ring.size() - 1;
        auto const bmask = buckets.size() - 1;
        while (count && now - ring[head].admitted >= std::chrono::seconds(62)) {
            auto const target = static_cast<std::uint32_t>(head + 1);
            std::size_t pos = ring[head].hash & bmask;
            while (buckets[pos] != target) pos = (pos + 1) & bmask;
            std::size_t hole = pos;
            std::size_t cur = (hole + 1) & bmask;
            while (buckets[cur] != 0) {
                auto const eidx = buckets[cur] - 1;
                std::size_t const ideal = ring[eidx].hash & bmask;
                if (((hole - ideal) & bmask) < ((cur - ideal) & bmask)) {
                    buckets[hole] = buckets[cur];
                    hole = cur;
                }
                cur = (cur + 1) & bmask;
            }
            buckets[hole] = 0;
            head = (head + 1) & rmask;
            --count;
            ++expired;
        }
        if (expired) {
            oldest_ns.store(count ? ring[head].admitted.time_since_epoch().count() : kEmptyTs, std::memory_order_release);
        }
        return expired;
    }

    auto ReplayTable::Shard::contains_locked(Salt const& key, std::uint32_t hash) const noexcept -> bool {
        if (!count) return false;
        auto const bmask = buckets.size() - 1;
        std::size_t pos = hash & bmask;
        while (buckets[pos] != 0) {
            auto const& e = ring[buckets[pos] - 1];
            if (e.hash == hash && e.salt == key) return true;
            pos = (pos + 1) & bmask;
        }
        return false;
    }

    auto ReplayTable::Shard::grow_locked() -> void {
        std::size_t const new_cap = ring.empty() ? std::size_t{8} : ring.size() * 2;
        std::vector<Entry> new_ring(new_cap);
        if (count) {
            auto const old_mask = ring.size() - 1;
            for (std::size_t i = 0; i < count; ++i)
                new_ring[i] = ring[(head + i) & old_mask];
        }
        std::vector<std::uint32_t> new_buckets(new_cap * 2, 0u);
        auto const bmask = new_buckets.size() - 1;
        for (std::size_t i = 0; i < count; ++i) {
            std::size_t pos = new_ring[i].hash & bmask;
            while (new_buckets[pos] != 0) pos = (pos + 1) & bmask;
            new_buckets[pos] = static_cast<std::uint32_t>(i + 1);
        }
        ring = std::move(new_ring);
        buckets = std::move(new_buckets);
        head = 0;
    }

    auto ReplayTable::Shard::insert_locked(Salt const& key, std::uint32_t hash, std::chrono::steady_clock::time_point admitted) -> void {
        if (count == ring.size()) grow_locked();
        auto const ts = last_admitted && admitted < *last_admitted ? *last_admitted : admitted;
        last_admitted = ts;
        auto const rmask = ring.size() - 1;
        auto const idx = (head + count) & rmask;
        ring[idx] = Entry{key, ts, hash};
        auto const bmask = buckets.size() - 1;
        std::size_t pos = hash & bmask;
        while (buckets[pos] != 0) pos = (pos + 1) & bmask;
        buckets[pos] = static_cast<std::uint32_t>(idx + 1);
        ++count;
        if (count == 1) oldest_ns.store(ts.time_since_epoch().count(), std::memory_order_release);
    }

    auto ReplayTable::check_clock_locked(std::chrono::steady_clock::time_point now, std::uint64_t wall_seconds)
        -> std::expected<void,ReplayError> {
        if (last_ && now<*last_) return std::unexpected(ReplayError::time_reversed);
        if (last_) {
            auto elapsed=std::chrono::duration_cast<std::chrono::seconds>(now-anchor_mono_).count();
            bool regressed = wall_seconds < anchor_wall_;
            std::uint64_t wall_delta = regressed ? 0 : (wall_seconds - anchor_wall_);
            auto elapsed_seconds = static_cast<std::uint64_t>(elapsed);
            // One second accounts for the phase of the whole-second wall clock.
            regressed = regressed || (elapsed_seconds > wall_delta && elapsed_seconds - wall_delta > 1);
            if (regressed) {
                if (!recovery_anchor_) {
                    recovery_anchor_ = {now, wall_seconds};
                    return std::unexpected(ReplayError::time_reversed);
                }
                auto rec_mono = std::chrono::duration_cast<std::chrono::seconds>(now - recovery_anchor_->first).count();
                if (rec_mono < 0 || wall_seconds < recovery_anchor_->second) {
                    recovery_anchor_ = {now, wall_seconds};
                    return std::unexpected(ReplayError::time_reversed);
                }
                auto rec_mono_u = static_cast<std::uint64_t>(rec_mono);
                auto rec_wall = wall_seconds - recovery_anchor_->second;
                if (rec_mono_u > rec_wall && rec_mono_u - rec_wall > 1) {
                    recovery_anchor_ = {now, wall_seconds};
                    return std::unexpected(ReplayError::time_reversed);
                }
                if (rec_mono_u < 62 || rec_wall < 62 || wall_seconds < anchor_wall_ || wall_seconds - anchor_wall_ < 62)
                    return std::unexpected(ReplayError::time_reversed);
                anchor_wall_ = wall_seconds;
                anchor_mono_ = now;
                recovery_anchor_.reset();
            } else {
                recovery_anchor_.reset();
                if (wall_delta > elapsed_seconds) { anchor_wall_ = wall_seconds; anchor_mono_ = now; }
            }
        } else { anchor_wall_=wall_seconds; anchor_mono_=now; recovery_anchor_.reset(); }
        last_=now;
        return {};
    }

    auto ReplayTable::sweep_expired(std::chrono::steady_clock::time_point now) const noexcept -> void {
        auto const cutoff_ns = (now - std::chrono::seconds(62)).time_since_epoch().count();
        for (auto& shard : shards_) {
            if (shard.oldest_ns.load(std::memory_order_acquire) > cutoff_ns) continue;
            std::lock_guard lock(shard.mutex);
            if (auto expired = shard.expire_locked(now))
                total_size_.fetch_sub(expired, std::memory_order_acq_rel);
        }
    }

    auto ReplayTable::insert_salt(std::span<std::uint8_t const> salt, std::chrono::steady_clock::time_point now)
        -> std::expected<void,ReplayError> {
        Salt key{};
        std::memcpy(key.bytes.data(), salt.data(), salt.size());
        key.size = static_cast<std::uint8_t>(salt.size());
        auto const hash = hash_salt(salt);
        auto& shard = shards_[salt[0] & (kShards - 1)];
        auto try_reserve = [&]() noexcept -> bool {
            auto cur = total_size_.load(std::memory_order_acquire);
            while (cur < capacity_) {
                if (total_size_.compare_exchange_weak(cur, cur + 1, std::memory_order_acq_rel, std::memory_order_acquire))
                    return true;
            }
            return false;
        };
        for (int pass = 0; pass < 2; ++pass) {
            {
                std::lock_guard lock(shard.mutex);
                if (auto expired = shard.expire_locked(now))
                    total_size_.fetch_sub(expired, std::memory_order_acq_rel);
                if (shard.contains_locked(key, hash)) return std::unexpected(ReplayError::duplicate);
                if (try_reserve()) {
                    try { shard.insert_locked(key, hash, now); }
                    catch (...) { total_size_.fetch_sub(1, std::memory_order_acq_rel); throw; }
                    return {};
                }
            }
            if (pass == 0 && capacity_ > 0) sweep_expired(now);
            else break;
        }
        return std::unexpected(ReplayError::full);
    }

    auto ReplayTable::admit(std::span<std::uint8_t const> salt, std::chrono::steady_clock::time_point now, std::uint64_t wall_seconds)
        -> std::expected<void,ReplayError> {
        if (salt.size()!=16 && salt.size()!=32) return std::unexpected(ReplayError::invalid_salt);
        {
            std::lock_guard lock(clock_mutex_);
            if (auto ok = check_clock_locked(now, wall_seconds); !ok) return ok;
        }
        return insert_salt(salt, now);
    }

    auto ReplayTable::admit_current(std::span<std::uint8_t const> salt, std::uint64_t timestamp)
        -> std::expected<void,ReplayError> {
        if (salt.size()!=16 && salt.size()!=32) return std::unexpected(ReplayError::invalid_salt);
        std::chrono::steady_clock::time_point now;
        {
            std::lock_guard lock(clock_mutex_);
            now = std::chrono::steady_clock::now();
            auto wall = platform::calibrated_wall_seconds();
            if (wall < 0) return std::unexpected(ReplayError::time_reversed);
            auto seconds = static_cast<std::uint64_t>(wall);
            if ((timestamp > seconds ? timestamp - seconds : seconds - timestamp) > 30)
                return std::unexpected(ReplayError::invalid_timestamp);
            if (auto ok = check_clock_locked(now, seconds); !ok) return ok;
        }
        return insert_salt(salt, now);
    }

    auto ReplayTable::size() const -> std::size_t {
        std::optional<std::chrono::steady_clock::time_point> last;
        {
            std::lock_guard lock(clock_mutex_);
            last = last_;
        }
        if (last) sweep_expired(*last);
        return total_size_.load(std::memory_order_acquire);
    }
}
