export module containers.cache_index;
import std;

export namespace containers {
    // Flat fixed-slot CLOCK (Second-Chance) table with O(1) open-addressed
    // hash lookup and 1-byte atomic access bits (zero dirty writes on hot hits).
    template<class Entry>
    class ClockTable {
        static constexpr std::uint32_t kEmpty = std::numeric_limits<std::uint32_t>::max();
        static constexpr std::uint32_t kTombstone = kEmpty - 1;

        struct Slot {
            std::optional<Entry> value;
            std::size_t hash = 0;
        };

        std::size_t capacity_ = 0;
        std::size_t size_ = 0;
        std::size_t next_alloc_ = 0;
        std::size_t hand_ = 0;
        std::size_t tombstones_ = 0;
        std::size_t bucket_mask_ = 0;
        std::vector<Slot> slots_;
        std::unique_ptr<std::atomic<std::uint8_t>[]> accessed_;
        std::vector<std::uint32_t> free_list_;
        std::vector<std::uint32_t> buckets_;

        static auto next_pow2(std::size_t n) noexcept -> std::size_t {
            std::size_t p = 8;
            while (p < n) p <<= 1;
            return p;
        }

        auto insert_bucket(std::size_t hash, std::uint32_t idx) noexcept -> void {
            auto pos = hash & bucket_mask_;
            for (;;) {
                auto cur = buckets_[pos];
                if (cur == kEmpty || cur == kTombstone) {
                    if (cur == kTombstone && tombstones_) --tombstones_;
                    buckets_[pos] = idx;
                    return;
                }
                pos = (pos + 1) & bucket_mask_;
            }
        }

        auto remove_bucket(std::size_t hash, std::uint32_t idx) noexcept -> void {
            auto pos = hash & bucket_mask_;
            for (;;) {
                auto cur = buckets_[pos];
                if (cur == kEmpty) return;
                if (cur == idx) {
                    buckets_[pos] = kTombstone;
                    ++tombstones_;
                    return;
                }
                pos = (pos + 1) & bucket_mask_;
            }
        }

        auto rehash_if_needed() noexcept -> void {
            if (buckets_.empty() || tombstones_ * 4 <= buckets_.size()) return;
            std::ranges::fill(buckets_, kEmpty);
            tombstones_ = 0;
            for (std::size_t i = 0; i < next_alloc_; ++i) {
                if (slots_[i].value) insert_bucket(slots_[i].hash, static_cast<std::uint32_t>(i));
            }
        }

    public:
        explicit ClockTable(std::size_t capacity = 0) : capacity_(capacity) {
            if (!capacity_) return;
            slots_.resize(capacity_);
            accessed_ = std::make_unique<std::atomic<std::uint8_t>[]>(capacity_);
            for (std::size_t i = 0; i < capacity_; ++i) accessed_[i].store(0, std::memory_order_relaxed);
            auto bsz = next_pow2(capacity_ * 2 + 1);
            bucket_mask_ = bsz - 1;
            buckets_.assign(bsz, kEmpty);
        }

        ClockTable(ClockTable const&) = delete;
        auto operator=(ClockTable const&) -> ClockTable& = delete;
        ClockTable(ClockTable&&) noexcept = default;
        auto operator=(ClockTable&&) noexcept -> ClockTable& = default;

        [[nodiscard]] auto size() const noexcept -> std::size_t { return size_; }
        [[nodiscard]] auto capacity() const noexcept -> std::size_t { return capacity_; }
        [[nodiscard]] auto empty() const noexcept -> bool { return size_ == 0; }

        template<class Pred>
        [[nodiscard]] auto find(std::size_t hash, Pred&& matches) const noexcept -> std::optional<std::uint32_t> {
            if (buckets_.empty() || !size_) return {};
            auto pos = hash & bucket_mask_;
            for (;;) {
                auto cur = buckets_[pos];
                if (cur == kEmpty) return {};
                if (cur != kTombstone && slots_[cur].hash == hash && slots_[cur].value && matches(*slots_[cur].value))
                    return cur;
                pos = (pos + 1) & bucket_mask_;
            }
        }

        auto touch(std::uint32_t idx) const noexcept -> void {
            if (accessed_[idx].load(std::memory_order_relaxed) == 0)
                accessed_[idx].store(1, std::memory_order_relaxed);
        }

        [[nodiscard]] auto at(std::uint32_t idx) noexcept -> Entry& { return *slots_[idx].value; }
        [[nodiscard]] auto at(std::uint32_t idx) const noexcept -> Entry const& { return *slots_[idx].value; }

        auto erase(std::uint32_t idx) noexcept -> void {
            if (idx >= next_alloc_ || !slots_[idx].value) return;
            remove_bucket(slots_[idx].hash, idx);
            slots_[idx].value.reset();
            accessed_[idx].store(0, std::memory_order_relaxed);
            --size_;
            free_list_.push_back(idx);
            rehash_if_needed();
        }

        template<class MatchPred, class ExpiredPred>
        auto upsert(std::size_t hash, MatchPred&& matches, Entry entry, ExpiredPred&& is_expired) -> std::uint32_t {
            if (auto existing = find(hash, matches)) {
                slots_[*existing].value.emplace(std::move(entry));
                accessed_[*existing].store(0, std::memory_order_relaxed);
                return *existing;
            }
            if (size_ < capacity_) {
                std::uint32_t idx = 0;
                if (!free_list_.empty()) {
                    idx = free_list_.back();
                    free_list_.pop_back();
                } else {
                    idx = static_cast<std::uint32_t>(next_alloc_++);
                }
                slots_[idx].hash = hash;
                slots_[idx].value.emplace(std::move(entry));
                accessed_[idx].store(0, std::memory_order_relaxed);
                insert_bucket(hash, idx);
                ++size_;
                rehash_if_needed();
                return idx;
            }
            std::uint32_t victim = 0;
            for (std::size_t step = 0; step < capacity_ * 2 + 1; ++step) {
                auto idx = static_cast<std::uint32_t>(hand_);
                hand_ = (hand_ + 1 == capacity_) ? 0 : hand_ + 1;
                if (!slots_[idx].value) { victim = idx; break; }
                if (is_expired(*slots_[idx].value) || accessed_[idx].load(std::memory_order_relaxed) == 0) {
                    victim = idx;
                    break;
                }
                accessed_[idx].store(0, std::memory_order_relaxed);
                victim = idx;
            }
            if (slots_[victim].value) remove_bucket(slots_[victim].hash, victim);
            else ++size_;
            slots_[victim].hash = hash;
            slots_[victim].value.emplace(std::move(entry));
            accessed_[victim].store(0, std::memory_order_relaxed);
            insert_bucket(hash, victim);
            rehash_if_needed();
            return victim;
        }

        template<class Pred>
        auto erase_if(Pred&& pred) noexcept -> void {
            if (!size_) return;
            for (std::size_t i = 0; i < next_alloc_; ++i) {
                if (slots_[i].value && pred(*slots_[i].value)) {
                    remove_bucket(slots_[i].hash, static_cast<std::uint32_t>(i));
                    slots_[i].value.reset();
                    accessed_[i].store(0, std::memory_order_relaxed);
                    --size_;
                    free_list_.push_back(static_cast<std::uint32_t>(i));
                }
            }
            rehash_if_needed();
        }

        template<class Fn>
        auto for_each(Fn&& fn) const -> void {
            for (std::size_t i = 0; i < next_alloc_; ++i) {
                if (slots_[i].value) fn(*slots_[i].value);
            }
        }

        auto clear() noexcept -> void {
            for (std::size_t i = 0; i < next_alloc_; ++i) {
                slots_[i].value.reset();
                accessed_[i].store(0, std::memory_order_relaxed);
            }
            if (!buckets_.empty()) std::ranges::fill(buckets_, kEmpty);
            free_list_.clear();
            size_ = 0;
            next_alloc_ = 0;
            hand_ = 0;
            tombstones_ = 0;
        }
    };

    // Zero-node-allocation O(1) LRU table backed by a contiguous array,
    // intrusive uint32_t index doubly-linked list, and flat hash index.
    template<class Entry>
    class IntrusiveLruTable {
        static constexpr std::uint32_t kNull = std::numeric_limits<std::uint32_t>::max();
        static constexpr std::uint32_t kTombstone = kNull - 1;

        struct Node {
            std::optional<Entry> value;
            std::size_t hash = 0;
            std::uint32_t prev = kNull;
            std::uint32_t next = kNull;
        };

        std::vector<Node> nodes_;
        std::vector<std::uint32_t> buckets_;
        std::size_t bucket_mask_ = 0;
        std::size_t size_ = 0;
        std::size_t tombstones_ = 0;
        std::uint32_t head_ = kNull;
        std::uint32_t tail_ = kNull;
        std::uint32_t free_head_ = kNull;

        static auto next_pow2(std::size_t n) noexcept -> std::size_t {
            std::size_t p = 16;
            while (p < n) p <<= 1;
            return p;
        }

        auto ensure_buckets(std::size_t target) -> void {
            if (!buckets_.empty() && (size_ + tombstones_ + 1) * 2 < buckets_.size()) return;
            auto bsz = next_pow2(std::max<std::size_t>(target * 2 + 2, buckets_.size() * (size_ * 2 >= buckets_.size() ? 2 : 1)));
            buckets_.assign(bsz, kNull);
            bucket_mask_ = bsz - 1;
            tombstones_ = 0;
            for (std::uint32_t cur = head_; cur != kNull; cur = nodes_[cur].next) {
                insert_bucket(nodes_[cur].hash, cur);
            }
        }

        auto insert_bucket(std::size_t hash, std::uint32_t idx) noexcept -> void {
            auto pos = hash & bucket_mask_;
            for (;;) {
                auto cur = buckets_[pos];
                if (cur == kNull || cur == kTombstone) {
                    if (cur == kTombstone && tombstones_) --tombstones_;
                    buckets_[pos] = idx;
                    return;
                }
                pos = (pos + 1) & bucket_mask_;
            }
        }

        auto remove_bucket(std::size_t hash, std::uint32_t idx) noexcept -> void {
            if (buckets_.empty()) return;
            auto pos = hash & bucket_mask_;
            for (;;) {
                auto cur = buckets_[pos];
                if (cur == kNull) return;
                if (cur == idx) {
                    buckets_[pos] = kTombstone;
                    ++tombstones_;
                    return;
                }
                pos = (pos + 1) & bucket_mask_;
            }
        }

        auto unlink(std::uint32_t idx) noexcept -> void {
            auto p = nodes_[idx].prev;
            auto n = nodes_[idx].next;
            if (p != kNull) nodes_[p].next = n; else head_ = n;
            if (n != kNull) nodes_[n].prev = p; else tail_ = p;
            nodes_[idx].prev = kNull;
            nodes_[idx].next = kNull;
        }

        auto link_front(std::uint32_t idx) noexcept -> void {
            nodes_[idx].prev = kNull;
            nodes_[idx].next = head_;
            if (head_ != kNull) nodes_[head_].prev = idx;
            else tail_ = idx;
            head_ = idx;
        }

    public:
        IntrusiveLruTable() = default;
        explicit IntrusiveLruTable(std::size_t reserve_count) {
            if (reserve_count) {
                nodes_.reserve(reserve_count);
                ensure_buckets(reserve_count);
            }
        }

        [[nodiscard]] auto size() const noexcept -> std::size_t { return size_; }
        [[nodiscard]] auto empty() const noexcept -> bool { return size_ == 0; }
        [[nodiscard]] auto lru() const noexcept -> std::optional<std::uint32_t> {
            return tail_ == kNull ? std::optional<std::uint32_t>{} : tail_;
        }

        template<class Pred>
        [[nodiscard]] auto find(std::size_t hash, Pred&& matches) const noexcept -> std::optional<std::uint32_t> {
            if (buckets_.empty() || !size_) return {};
            auto pos = hash & bucket_mask_;
            for (;;) {
                auto cur = buckets_[pos];
                if (cur == kNull) return {};
                if (cur != kTombstone && nodes_[cur].hash == hash && nodes_[cur].value && matches(*nodes_[cur].value))
                    return cur;
                pos = (pos + 1) & bucket_mask_;
            }
        }

        [[nodiscard]] auto at(std::uint32_t idx) noexcept -> Entry& { return *nodes_[idx].value; }
        [[nodiscard]] auto at(std::uint32_t idx) const noexcept -> Entry const& { return *nodes_[idx].value; }

        auto promote(std::uint32_t idx) noexcept -> void {
            if (idx == head_) return;
            unlink(idx);
            link_front(idx);
        }

        auto insert_front(std::size_t hash, Entry entry) -> std::uint32_t {
            ensure_buckets(size_ + 1);
            std::uint32_t idx = 0;
            if (free_head_ != kNull) {
                idx = free_head_;
                free_head_ = nodes_[idx].next;
            } else {
                idx = static_cast<std::uint32_t>(nodes_.size());
                nodes_.emplace_back();
            }
            nodes_[idx].hash = hash;
            nodes_[idx].value.emplace(std::move(entry));
            link_front(idx);
            insert_bucket(hash, idx);
            ++size_;
            return idx;
        }

        auto erase(std::uint32_t idx) noexcept -> void {
            if (idx >= nodes_.size() || !nodes_[idx].value) return;
            unlink(idx);
            remove_bucket(nodes_[idx].hash, idx);
            nodes_[idx].value.reset();
            nodes_[idx].next = free_head_;
            free_head_ = idx;
            --size_;
        }

        template<class Fn>
        auto for_each(Fn&& fn) const -> void {
            for (std::uint32_t cur = head_; cur != kNull; cur = nodes_[cur].next) {
                if (nodes_[cur].value) fn(*nodes_[cur].value);
            }
        }

        auto clear() noexcept -> void {
            nodes_.clear();
            buckets_.clear();
            bucket_mask_ = 0;
            size_ = 0;
            tombstones_ = 0;
            head_ = kNull;
            tail_ = kNull;
            free_head_ = kNull;
        }
    };
}
