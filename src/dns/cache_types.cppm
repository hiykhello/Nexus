export module dns.cache_types;
import std;
import dns.message;

export namespace dns {
    enum class CacheError { invalid_key, invalid_answer, time_reversed, stale_generation, stale_query, generation_exhausted, query_limit, disabled, reader_required };
    enum class NegativeKind { name_not_found, no_data };
    struct CacheKey {
        std::uint64_t view;
        std::string name;
        std::uint16_t type;
    };
    struct CacheToken { std::uint64_t generation; std::uint64_t query; };
    struct StaleAddressAnswer { AddressAnswer answer; std::uint64_t age_ms; };
}

export namespace dns::detail {
    // A valid logical length alone does not bound an rvalue's reserved storage.
    // Compact only oversized inputs; ordinary resolver results keep their buffers.
    inline auto compact_name_storage(std::string& name) -> bool {
        constexpr std::size_t limit = 254;
        if (name.capacity() <= limit) return true;
        std::string compact(name.data(), name.size());
        if (compact.capacity() > limit) return false;
        name = std::move(compact);
        return true;
    }

    inline auto compact_key_storage(CacheKey& key) -> bool { return compact_name_storage(key.name); }

    inline auto compact_answer_storage(AddressAnswer& answer) -> bool {
        if (!compact_name_storage(answer.canonical_name)) return false;
        if (answer.chain.capacity() > 16) {
            std::vector<std::string> compact(answer.chain.begin(), answer.chain.end());
            if (compact.capacity() > 16) return false;
            answer.chain = std::move(compact);
        }
        for (auto& name : answer.chain) if (!compact_name_storage(name)) return false;
        if (answer.addresses.capacity() > 128) {
            std::vector<Address> compact(answer.addresses.begin(), answer.addresses.end());
            if (compact.capacity() > 128) return false;
            answer.addresses = std::move(compact);
        }
        return true;
    }

    struct SnapshotKeyHash {
        auto operator()(CacheKey const& key) const noexcept -> std::size_t {
            auto hash = std::hash<std::string>{}(key.name);
            hash ^= std::hash<std::uint64_t>{}(key.view) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
            hash ^= std::hash<std::uint16_t>{}(key.type) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
            return hash;
        }
    };

    struct SnapshotKeyEqual {
        auto operator()(CacheKey const& a, CacheKey const& b) const noexcept -> bool {
            return a.view == b.view && a.type == b.type && a.name == b.name;
        }
    };

    // O(1) bounded dual-indexed pending table:
    //  - unique monotonic query/sequence -> slot via intrusive bucket chain
    //  - key_hash -> slot chain (supports multiple concurrent pending entries per key)
    // Lazy-allocated on first emplace so empty/snapshot caches allocate 0 bytes.
    template<class T>
    class PendingIndex {
        static constexpr std::uint32_t none = std::numeric_limits<std::uint32_t>::max();
        struct Slot {
            std::optional<T> value;
            std::uint64_t query = 0;
            std::size_t key_hash = 0;
            std::uint32_t q_prev = none, q_next = none;
            std::uint32_t k_prev = none, k_next = none;
        };
        std::vector<Slot> slots_;
        std::vector<std::uint32_t> q_heads_;
        std::vector<std::uint32_t> k_heads_;
        std::uint32_t free_head_ = none;
        std::size_t count_ = 0;

        static auto hash_query(std::uint64_t q) noexcept -> std::size_t {
            q ^= q >> 30;
            q *= 0xbf58476d1ce4e5b9ull;
            q ^= q >> 27;
            q *= 0x94d049bb133111ebull;
            q ^= q >> 31;
            return static_cast<std::size_t>(q);
        }
        auto bucket_q(std::uint64_t q) const noexcept -> std::size_t {
            return hash_query(q) & (q_heads_.size() - 1);
        }
        auto bucket_k(std::size_t h) const noexcept -> std::size_t {
            if constexpr (sizeof(std::size_t) > 4) h ^= (h >> 32);
            return (h ^ (h >> 16)) & (k_heads_.size() - 1);
        }
        auto link_q(std::uint32_t idx) noexcept -> void {
            auto bucket = bucket_q(slots_[idx].query);
            auto head = q_heads_[bucket];
            slots_[idx].q_prev = none;
            slots_[idx].q_next = head;
            if (head != none) slots_[head].q_prev = idx;
            q_heads_[bucket] = idx;
        }
        auto unlink_q(std::uint32_t idx) noexcept -> void {
            auto& s = slots_[idx];
            if (s.q_prev != none) slots_[s.q_prev].q_next = s.q_next;
            else q_heads_[bucket_q(s.query)] = s.q_next;
            if (s.q_next != none) slots_[s.q_next].q_prev = s.q_prev;
            s.q_prev = s.q_next = none;
        }
        auto link_k(std::uint32_t idx) noexcept -> void {
            auto bucket = bucket_k(slots_[idx].key_hash);
            auto head = k_heads_[bucket];
            slots_[idx].k_prev = none;
            slots_[idx].k_next = head;
            if (head != none) slots_[head].k_prev = idx;
            k_heads_[bucket] = idx;
        }
        auto unlink_k(std::uint32_t idx) noexcept -> void {
            auto& s = slots_[idx];
            if (s.k_prev != none) slots_[s.k_prev].k_next = s.k_next;
            else k_heads_[bucket_k(s.key_hash)] = s.k_next;
            if (s.k_next != none) slots_[s.k_next].k_prev = s.k_prev;
            s.k_prev = s.k_next = none;
        }
        auto ensure_buckets(std::size_t target) -> void {
            if (target <= q_heads_.size()) return;
            std::size_t sz = q_heads_.empty() ? 64 : q_heads_.size();
            while (sz < target) sz <<= 1;
            std::vector<std::uint32_t> new_q(sz, none);
            std::vector<std::uint32_t> new_k(sz, none);
            q_heads_ = std::move(new_q);
            k_heads_ = std::move(new_k);
            for (std::uint32_t i = 0; i < slots_.size(); ++i) {
                if (!slots_[i].value) continue;
                link_q(i);
                link_k(i);
            }
        }
    public:
        [[nodiscard]] auto size() const noexcept -> std::size_t { return count_; }
        [[nodiscard]] auto empty() const noexcept -> bool { return count_ == 0; }

        auto emplace(std::uint64_t query, std::size_t key_hash, T value) -> std::uint32_t {
            ensure_buckets(count_ + 1);
            std::uint32_t idx;
            if (free_head_ != none) {
                idx = free_head_;
                auto& s = slots_[idx];
                auto next_free = s.q_next;
                s.value.emplace(std::move(value));
                free_head_ = next_free;
                s.query = query;
                s.key_hash = key_hash;
            } else {
                idx = static_cast<std::uint32_t>(slots_.size());
                slots_.push_back(Slot{std::move(value), query, key_hash, none, none, none, none});
            }
            link_q(idx);
            link_k(idx);
            ++count_;
            return idx;
        }

        [[nodiscard]] auto find_query(std::uint64_t query) noexcept -> std::optional<std::uint32_t> {
            if (q_heads_.empty()) return std::nullopt;
            for (auto cur = q_heads_[bucket_q(query)]; cur != none; cur = slots_[cur].q_next)
                if (slots_[cur].query == query) return cur;
            return std::nullopt;
        }

        template<class Pred>
        [[nodiscard]] auto find_key(std::size_t key_hash, Pred&& pred) noexcept -> std::optional<std::uint32_t> {
            if (k_heads_.empty()) return std::nullopt;
            for (auto cur = k_heads_[bucket_k(key_hash)]; cur != none; cur = slots_[cur].k_next)
                if (slots_[cur].key_hash == key_hash && pred(*slots_[cur].value)) return cur;
            return std::nullopt;
        }

        template<class Pred>
        [[nodiscard]] auto has_key(std::size_t key_hash, Pred&& pred) const noexcept -> bool {
            if (k_heads_.empty()) return false;
            for (auto cur = k_heads_[bucket_k(key_hash)]; cur != none; cur = slots_[cur].k_next)
                if (slots_[cur].key_hash == key_hash && pred(*slots_[cur].value)) return true;
            return false;
        }

        [[nodiscard]] auto at(std::uint32_t idx) noexcept -> T& { return *slots_[idx].value; }
        [[nodiscard]] auto at(std::uint32_t idx) const noexcept -> T const& { return *slots_[idx].value; }

        auto rekey_query(std::uint32_t idx, std::uint64_t new_query) noexcept -> void {
            unlink_q(idx);
            slots_[idx].query = new_query;
            link_q(idx);
        }

        auto erase(std::uint32_t idx) noexcept -> void {
            unlink_q(idx);
            unlink_k(idx);
            auto& s = slots_[idx];
            s.value.reset();
            s.q_next = free_head_;
            free_head_ = idx;
            --count_;
        }

        template<class Pred, class OnErase>
        auto erase_key_if(std::size_t key_hash, Pred&& pred, OnErase&& on_erase) noexcept -> void {
            if (k_heads_.empty()) return;
            for (auto cur = k_heads_[bucket_k(key_hash)]; cur != none; ) {
                auto next = slots_[cur].k_next;
                if (slots_[cur].key_hash == key_hash && pred(slots_[cur].query, *slots_[cur].value)) {
                    on_erase(*slots_[cur].value);
                    erase(cur);
                }
                cur = next;
            }
        }

        auto clear() noexcept -> void {
            slots_.clear();
            q_heads_.clear();
            k_heads_.clear();
            free_head_ = none;
            count_ = 0;
        }
    };
}
