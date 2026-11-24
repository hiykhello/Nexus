export module dns.refresh_budget;
import std;
import dns.cache_types;

// The budget outlives every lease. Keys passed here must already be canonical.
export namespace dns::detail {
    // Tracks actual network work, independently of cache publication tokens.
    // All executor owners sharing a cache use the same budget.
    class RefreshBudget {
        using Clock = std::chrono::steady_clock;
        struct Slot { std::optional<CacheKey> key; Clock::time_point until{}; bool active = false; };
        std::mutex mutex_;
        std::vector<Slot> slots_;
        std::size_t active_ = 0;

        auto release(std::size_t index, Clock::time_point until) noexcept -> void {
            std::lock_guard lock(mutex_);
            auto& slot = slots_[index];
            slot.active = false;
            slot.until = until;
            if (until <= Clock::now()) slot.key.reset();
            --active_;
        }
    public:
        class Lease {
            friend class RefreshBudget;
            RefreshBudget* budget_ = nullptr;
            std::size_t index_ = 0;
            Clock::time_point until_{};
            Lease(RefreshBudget& budget, std::size_t index) noexcept : budget_(&budget), index_(index) {}
        public:
            Lease(Lease const&) = delete;
            auto operator=(Lease const&) -> Lease& = delete;
            Lease(Lease&& other) noexcept
                : budget_(std::exchange(other.budget_, nullptr)), index_(other.index_), until_(other.until_) {}
            auto operator=(Lease&& other) noexcept -> Lease& {
                if (this != &other) {
                    if (budget_) budget_->release(index_, until_);
                    budget_ = std::exchange(other.budget_, nullptr);
                    index_ = other.index_;
                    until_ = other.until_;
                }
                return *this;
            }
            ~Lease() { if (budget_) budget_->release(index_, until_); }
            auto delay_until(Clock::time_point until) noexcept -> void { until_ = until; }
        };

        explicit RefreshBudget(std::size_t limit) : slots_(std::min<std::size_t>(limit, 256)) {}
        RefreshBudget(RefreshBudget const&) = delete;
        auto operator=(RefreshBudget const&) -> RefreshBudget& = delete;
        [[nodiscard]] auto limit() const noexcept -> std::size_t { return slots_.size(); }
        [[nodiscard]] auto active() -> std::size_t { std::lock_guard lock(mutex_); return active_; }
        [[nodiscard]] auto acquire(CacheKey const& key) -> std::optional<Lease> {
            if (key.name.size() > 254) return {};
            std::lock_guard lock(mutex_);
            if (active_ == slots_.size()) return {};
            auto now = Clock::now();
            std::size_t free = slots_.size(), oldest = slots_.size();
            for (std::size_t i = 0; i < slots_.size(); ++i) {
                auto& slot = slots_[i];
                if (slot.key && !slot.active && slot.until <= now) slot.key.reset();
                if (!slot.key) { if (free == slots_.size()) free = i; continue; }
                if (slot.key->view == key.view && slot.key->type == key.type && slot.key->name == key.name) return {};
                if (!slot.active && (oldest == slots_.size() || slot.until < slots_[oldest].until)) oldest = i;
            }
            // Copy and bound storage before changing a slot, so allocation
            // failure preserves both the permit and any existing backoff.
            CacheKey stored = key;
            if (!compact_key_storage(stored)) return {};
            static_assert(std::is_nothrow_move_constructible_v<CacheKey>);
            // Backoff is bounded and may be evicted to make room for new work.
            if (free == slots_.size()) free = oldest;
            slots_[free].key.emplace(std::move(stored));
            slots_[free].active = true;
            ++active_;
            return Lease(*this, free);
        }
    };
}
