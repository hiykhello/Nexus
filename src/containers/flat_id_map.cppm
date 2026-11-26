export module containers.flat_id_map;
import std;

export namespace containers {
    // Generation-safe O(1) flat open-addressed map keyed by full 64-bit integer IDs.
    // Dense item vector gives O(active) iteration; power-of-2 bucket array uses
    // backward-shift deletion (zero tombstones, zero per-node heap allocations).
    template<class Id, class Value>
    class FlatIdMap {
        static constexpr std::uint32_t kNull = std::numeric_limits<std::uint32_t>::max();
        std::vector<std::pair<Id, Value>> items_;
        std::vector<std::uint32_t> buckets_;
        std::size_t mask_ = 0;

        static constexpr auto hash_id(Id id) noexcept -> std::size_t {
            std::uint64_t x = static_cast<std::uint64_t>(id);
            x ^= x >> 30;
            x *= 0xbf58476d1ce4e5b9ull;
            x ^= x >> 27;
            x *= 0x94d049bb133111ebull;
            return static_cast<std::size_t>(x ^ (x >> 31));
        }

        static constexpr auto next_pow2(std::size_t n) noexcept -> std::size_t {
            std::size_t p = 16;
            while (p < n) p <<= 1;
            return p;
        }

        auto insert_bucket(Id id, std::uint32_t idx) noexcept -> void {
            for (std::size_t pos = hash_id(id) & mask_; ; pos = (pos + 1) & mask_) {
                if (buckets_[pos] == kNull) { buckets_[pos] = idx; return; }
            }
        }

        auto ensure_capacity(std::size_t target) -> void {
            if (!buckets_.empty() && target * 2 <= buckets_.size()) return;
            auto bsz = next_pow2(std::max<std::size_t>(target * 2, buckets_.size() * 2));
            buckets_.assign(bsz, kNull);
            mask_ = bsz - 1;
            for (std::uint32_t i = 0; i < items_.size(); ++i) insert_bucket(items_[i].first, i);
        }

        [[nodiscard]] auto find_bucket(Id id) const noexcept -> std::size_t {
            if (buckets_.empty() || items_.empty()) return buckets_.size();
            for (std::size_t pos = hash_id(id) & mask_; ; pos = (pos + 1) & mask_) {
                auto cur = buckets_[pos];
                if (cur == kNull) return buckets_.size();
                if (items_[cur].first == id) return pos;
            }
        }

        auto erase_bucket_at(std::size_t pos) noexcept -> std::uint32_t {
            auto idx = buckets_[pos];
            std::size_t hole = pos;
            for (std::size_t scan = (hole + 1) & mask_; buckets_[scan] != kNull; scan = (scan + 1) & mask_) {
                auto cur = buckets_[scan];
                auto ideal = hash_id(items_[cur].first) & mask_;
                if (((scan - ideal) & mask_) >= ((scan - hole) & mask_)) {
                    buckets_[hole] = cur;
                    hole = scan;
                }
            }
            buckets_[hole] = kNull;
            auto const last = static_cast<std::uint32_t>(items_.size() - 1);
            if (idx != last) {
                auto moved_id = items_[last].first;
                items_[idx] = std::move(items_[last]);
                for (std::size_t p = hash_id(moved_id) & mask_; ; p = (p + 1) & mask_) {
                    if (buckets_[p] == last) { buckets_[p] = idx; break; }
                }
            }
            items_.pop_back();
            return idx;
        }

    public:
        using iterator = typename std::vector<std::pair<Id, Value>>::iterator;
        using const_iterator = typename std::vector<std::pair<Id, Value>>::const_iterator;

        auto init(std::size_t reserve_count) -> void {
            clear();
            if (!reserve_count) return;
            items_.reserve(reserve_count);
            auto bsz = next_pow2(reserve_count * 2);
            buckets_.assign(bsz, kNull);
            mask_ = bsz - 1;
        }

        [[nodiscard]] auto size() const noexcept -> std::size_t { return items_.size(); }
        [[nodiscard]] auto empty() const noexcept -> bool { return items_.empty(); }
        [[nodiscard]] auto begin() noexcept -> iterator { return items_.begin(); }
        [[nodiscard]] auto end() noexcept -> iterator { return items_.end(); }
        [[nodiscard]] auto begin() const noexcept -> const_iterator { return items_.begin(); }
        [[nodiscard]] auto end() const noexcept -> const_iterator { return items_.end(); }
        [[nodiscard]] auto contains(Id id) const noexcept -> bool { return find_bucket(id) < buckets_.size(); }

        [[nodiscard]] auto find(Id id) noexcept -> iterator {
            auto pos = find_bucket(id);
            return pos < buckets_.size() ? items_.begin() + static_cast<std::ptrdiff_t>(buckets_[pos]) : items_.end();
        }
        [[nodiscard]] auto find(Id id) const noexcept -> const_iterator {
            auto pos = find_bucket(id);
            return pos < buckets_.size() ? items_.begin() + static_cast<std::ptrdiff_t>(buckets_[pos]) : items_.end();
        }

        template<class... Args>
        auto emplace(Id id, Args&&... args) -> std::pair<iterator, bool> {
            if (auto pos = find_bucket(id); pos < buckets_.size())
                return {items_.begin() + static_cast<std::ptrdiff_t>(buckets_[pos]), false};
            ensure_capacity(items_.size() + 1);
            auto idx = static_cast<std::uint32_t>(items_.size());
            items_.emplace_back(std::piecewise_construct, std::forward_as_tuple(id),
                                std::forward_as_tuple(std::forward<Args>(args)...));
            insert_bucket(id, idx);
            return {items_.begin() + static_cast<std::ptrdiff_t>(idx), true};
        }

        auto operator[](Id id) -> Value& {
            auto it = find(id);
            if (it != end()) return it->second;
            return emplace(id).first->second;
        }

        auto erase(Id id) noexcept -> std::size_t {
            auto pos = find_bucket(id);
            if (pos >= buckets_.size()) return 0;
            (void)erase_bucket_at(pos);
            return 1;
        }

        auto erase(iterator it) noexcept -> iterator {
            if (it == items_.end()) return items_.end();
            auto pos = find_bucket(it->first);
            if (pos >= buckets_.size()) return items_.end();
            auto idx = erase_bucket_at(pos);
            return items_.begin() + static_cast<std::ptrdiff_t>(idx);
        }

        auto clear() noexcept -> void {
            items_.clear();
            std::ranges::fill(buckets_, kNull);
        }
    };
}
