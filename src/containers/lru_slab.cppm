// Pointer-stable chunked dynamic slab with O(1) flat open-addressing hash index,
// O(1) intrusive doubly-linked LRU, O(1) freelist reuse, and configurable soft cap.
export module containers.lru_slab;
import std;

export namespace containers {
    template<class Key, class Value, class Hash = std::hash<Key>, class Eq = std::equal_to<>, std::size_t ChunkSize = 32>
        requires (ChunkSize >= 8 && (ChunkSize & (ChunkSize - 1)) == 0)
    class LruSlab {
        static constexpr std::uint32_t kNull = std::numeric_limits<std::uint32_t>::max();
        static constexpr std::uint32_t kTombstone = kNull - 1;
        static constexpr std::size_t kChunkMask = ChunkSize - 1;
        static constexpr std::size_t kChunkShift = std::countr_zero(ChunkSize);

        struct Node {
            std::optional<Key> key;
            std::optional<Value> value;
            std::size_t hash = 0;
            std::uint32_t prev = kNull;
            std::uint32_t next = kNull;
            bool occupied = false;
        };

        struct Chunk {
            std::array<Node, ChunkSize> nodes{};
        };

        std::vector<std::unique_ptr<Chunk>> chunks_;
        std::vector<std::uint32_t> buckets_;
        std::size_t bucket_mask_ = 0;
        std::size_t soft_cap_ = 4096;
        std::size_t size_ = 0;
        std::size_t allocated_ = 0;
        std::size_t tombstones_ = 0;
        std::size_t rehashes_ = 0;
        std::uint32_t head_ = kNull; // MRU
        std::uint32_t tail_ = kNull; // LRU
        std::uint32_t free_head_ = kNull;
        [[no_unique_address]] Hash hash_{};
        [[no_unique_address]] Eq eq_{};

        static constexpr auto next_pow2(std::size_t n) noexcept -> std::size_t {
            std::size_t p = 16;
            while (p < n) p <<= 1;
            return p;
        }

        [[nodiscard]] auto node_at(std::uint32_t idx) noexcept -> Node& {
            return chunks_[idx >> kChunkShift]->nodes[idx & kChunkMask];
        }
        [[nodiscard]] auto node_at(std::uint32_t idx) const noexcept -> Node const& {
            return chunks_[idx >> kChunkShift]->nodes[idx & kChunkMask];
        }

        auto insert_bucket(std::size_t h, std::uint32_t idx) noexcept -> void {
            auto pos = h & bucket_mask_;
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

        auto remove_bucket(std::size_t h, std::uint32_t idx) noexcept -> void {
            if (buckets_.empty()) return;
            auto pos = h & bucket_mask_;
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

        auto ensure_buckets(std::size_t target) -> bool {
            if (!buckets_.empty() && (size_ + tombstones_ + 1) * 2 < buckets_.size()) return false;
            auto desired = std::max<std::size_t>(target * 2 + 2,
                buckets_.size() * (size_ * 2 >= buckets_.size() ? 2 : 1));
            auto bsz = next_pow2(desired);
            buckets_.assign(bsz, kNull);
            bucket_mask_ = bsz - 1;
            tombstones_ = 0;
            ++rehashes_;
            for (std::uint32_t cur = head_; cur != kNull; cur = node_at(cur).next)
                insert_bucket(node_at(cur).hash, cur);
            return true;
        }

        auto unlink(std::uint32_t idx) noexcept -> void {
            auto& n = node_at(idx);
            if (n.prev != kNull) node_at(n.prev).next = n.next; else head_ = n.next;
            if (n.next != kNull) node_at(n.next).prev = n.prev; else tail_ = n.prev;
            n.prev = kNull;
            n.next = kNull;
        }

        auto link_front(std::uint32_t idx) noexcept -> void {
            auto& n = node_at(idx);
            n.prev = kNull;
            n.next = head_;
            if (head_ != kNull) node_at(head_).prev = idx; else tail_ = idx;
            head_ = idx;
        }

        [[nodiscard]] auto allocate_slot() -> std::uint32_t {
            if (free_head_ != kNull) {
                auto idx = free_head_;
                free_head_ = node_at(idx).next;
                node_at(idx).next = kNull;
                return idx;
            }
            if (allocated_ == chunks_.size() * ChunkSize)
                chunks_.push_back(std::make_unique<Chunk>());
            return static_cast<std::uint32_t>(allocated_++);
        }

    public:
        explicit LruSlab(std::size_t soft_cap = 4096) noexcept : soft_cap_(std::max<std::size_t>(soft_cap, 1)) {}
        LruSlab(LruSlab const&) = delete;
        auto operator=(LruSlab const&) -> LruSlab& = delete;
        LruSlab(LruSlab&&) noexcept = default;
        auto operator=(LruSlab&&) noexcept -> LruSlab& = default;

        [[nodiscard]] auto size() const noexcept -> std::size_t { return size_; }
        [[nodiscard]] auto empty() const noexcept -> bool { return size_ == 0; }
        [[nodiscard]] auto soft_cap() const noexcept -> std::size_t { return soft_cap_; }
        auto set_soft_cap(std::size_t cap) noexcept -> void { soft_cap_ = std::max<std::size_t>(cap, 1); }
        [[nodiscard]] auto allocated_slots() const noexcept -> std::size_t { return allocated_; }
        [[nodiscard]] auto chunk_count() const noexcept -> std::size_t { return chunks_.size(); }
        [[nodiscard]] auto rehash_count() const noexcept -> std::size_t { return rehashes_; }
        [[nodiscard]] auto lru_index() const noexcept -> std::optional<std::uint32_t> {
            return tail_ == kNull ? std::optional<std::uint32_t>{} : tail_;
        }
        [[nodiscard]] auto mru_index() const noexcept -> std::optional<std::uint32_t> {
            return head_ == kNull ? std::optional<std::uint32_t>{} : head_;
        }
        [[nodiscard]] auto occupied(std::uint32_t idx) const noexcept -> bool {
            return idx < allocated_ && node_at(idx).occupied;
        }
        [[nodiscard]] auto slot_key(std::uint32_t idx) const noexcept -> Key const& { return *node_at(idx).key; }
        [[nodiscard]] auto slot_value(std::uint32_t idx) noexcept -> Value& { return *node_at(idx).value; }
        [[nodiscard]] auto slot_value(std::uint32_t idx) const noexcept -> Value const& { return *node_at(idx).value; }

        template<class K>
        [[nodiscard]] auto find_index(K const& k) const noexcept -> std::optional<std::uint32_t> {
            if (buckets_.empty() || !size_) return {};
            auto const h = static_cast<std::size_t>(hash_(k));
            auto pos = h & bucket_mask_;
            for (;;) {
                auto cur = buckets_[pos];
                if (cur == kNull) return {};
                if (cur != kTombstone) {
                    auto const& n = node_at(cur);
                    if (n.occupied && n.hash == h && eq_(*n.key, k)) return cur;
                }
                pos = (pos + 1) & bucket_mask_;
            }
        }

        auto touch(std::uint32_t idx) noexcept -> void {
            if (idx == head_ || !occupied(idx)) return;
            unlink(idx);
            link_front(idx);
        }

        template<class K>
        [[nodiscard]] auto find_index_and_touch(K const& k) noexcept -> std::optional<std::uint32_t> {
            auto idx = find_index(k);
            if (idx) touch(*idx);
            return idx;
        }

        template<class K>
        [[nodiscard]] auto find(K const& k) noexcept -> Value* {
            auto idx = find_index(k);
            return idx ? &slot_value(*idx) : nullptr;
        }

        template<class K>
        [[nodiscard]] auto find_and_touch(K const& k) noexcept -> Value* {
            auto idx = find_index_and_touch(k);
            return idx ? &slot_value(*idx) : nullptr;
        }

        template<class K, class... Args>
        [[nodiscard]] auto emplace(K&& k, Args&&... args) -> std::optional<std::uint32_t> {
            if (auto hit = find_index_and_touch(k)) return hit;
            if (size_ >= soft_cap_) return {};
            ensure_buckets(size_ + 1);
            auto idx = allocate_slot();
            auto& n = node_at(idx);
            auto const h = static_cast<std::size_t>(hash_(k));
            n.key.emplace(std::forward<K>(k));
            try {
                n.value.emplace(std::forward<Args>(args)...);
            } catch (...) {
                n.key.reset();
                n.next = free_head_;
                free_head_ = idx;
                throw;
            }
            n.hash = h;
            n.occupied = true;
            link_front(idx);
            insert_bucket(h, idx);
            ++size_;
            return idx;
        }

        // Inserts a new entry or touches an existing one. At soft_cap_, invokes
        // on_evict(victim_idx, victim_key, victim_value), destroys & recycles the LRU slot in O(1).
        template<class K, class OnEvict, class... Args>
        [[nodiscard]] auto emplace_or_evict(K&& k, OnEvict&& on_evict, Args&&... args)
            -> std::pair<std::uint32_t, bool> {
            if (auto hit = find_index_and_touch(k)) return {*hit, false};
            if (size_ >= soft_cap_ && tail_ != kNull) {
                auto victim = tail_;
                auto& vn = node_at(victim);
                on_evict(victim, *vn.key, *vn.value);
                erase(victim);
            }
            ensure_buckets(size_ + 1);
            auto idx = allocate_slot();
            auto& n = node_at(idx);
            auto const h = static_cast<std::size_t>(hash_(k));
            n.key.emplace(std::forward<K>(k));
            try {
                n.value.emplace(std::forward<Args>(args)...);
            } catch (...) {
                n.key.reset();
                n.next = free_head_;
                free_head_ = idx;
                throw;
            }
            n.hash = h;
            n.occupied = true;
            link_front(idx);
            insert_bucket(h, idx);
            ++size_;
            return {idx, true};
        }

        // Re-binds the exact LRU slot in-place without destroying Value (preserves
        // address stability for coroutines awaiting Value's async_events).
        template<class K, class OnEvict>
        [[nodiscard]] auto rekey_lru(K&& new_key, OnEvict&& on_evict) -> std::optional<std::uint32_t> {
            if (tail_ == kNull) return {};
            auto victim = tail_;
            auto& n = node_at(victim);
            on_evict(victim, *n.key, *n.value);
            remove_bucket(n.hash, victim);
            auto const h = static_cast<std::size_t>(hash_(new_key));
            n.key.emplace(std::forward<K>(new_key));
            n.hash = h;
            if (victim != head_) {
                unlink(victim);
                link_front(victim);
            }
            if (!ensure_buckets(size_)) insert_bucket(h, victim);
            return victim;
        }

        auto erase(std::uint32_t idx) noexcept -> bool {
            if (!occupied(idx)) return false;
            auto& n = node_at(idx);
            unlink(idx);
            remove_bucket(n.hash, idx);
            n.value.reset();
            n.key.reset();
            n.occupied = false;
            n.next = free_head_;
            free_head_ = idx;
            --size_;
            return true;
        }

        template<class K>
        auto erase_key(K const& k) noexcept -> bool {
            auto idx = find_index(k);
            return idx ? erase(*idx) : false;
        }

        template<class Fn>
        auto for_each(Fn&& fn) -> void {
            for (std::uint32_t cur = head_; cur != kNull;) {
                auto nxt = node_at(cur).next;
                auto& n = node_at(cur);
                if (n.occupied) fn(cur, *n.key, *n.value);
                cur = nxt;
            }
        }

        template<class Fn>
        auto for_each_lru_to_mru(Fn&& fn) -> void {
            for (std::uint32_t cur = tail_; cur != kNull;) {
                auto prv = node_at(cur).prev;
                auto& n = node_at(cur);
                if (n.occupied) fn(cur, *n.key, *n.value);
                cur = prv;
            }
        }

        auto clear() noexcept -> void {
            for (std::uint32_t cur = head_; cur != kNull;) {
                auto nxt = node_at(cur).next;
                auto& n = node_at(cur);
                n.value.reset();
                n.key.reset();
                n.occupied = false;
                n.prev = kNull;
                n.next = free_head_;
                free_head_ = cur;
                cur = nxt;
            }
            if (!buckets_.empty()) std::ranges::fill(buckets_, kNull);
            head_ = tail_ = kNull;
            size_ = 0;
            tombstones_ = 0;
        }
    };
}
