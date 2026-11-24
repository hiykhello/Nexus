export module relay.session_quota;
import std;
export namespace relay {
    class SessionQuota {
        // Low 32 bits track active Lease count (`used`), high 32 bits track
        // SessionQuota owner count so Leases safely outlive temporary quotas
        // with a single atomic word and zero std::shared_ptr refcount bouncing.
        struct alignas(64) State {
            static constexpr std::uint64_t kOwnerUnit = std::uint64_t{1} << 32;
            static constexpr std::uint64_t kUsedMask = 0xffffffffull;
            std::atomic<std::uint64_t> counts{kOwnerUnit};
        };
        State* state_ = nullptr;
        std::size_t limit_ = 0;
        static auto add_owner(State* state) noexcept -> void;
        static auto release_owner(State* state) noexcept -> void;
    public:
        class Lease {
            friend class SessionQuota;
            State* state_ = nullptr;
            std::size_t limit_ = 0;
            explicit Lease(State* state, std::size_t maximum) noexcept;
            static auto acquire(State* state, std::size_t maximum) noexcept -> std::optional<Lease>;
            auto release() noexcept -> void;
        public:
            Lease(Lease const&) = delete;
            auto operator=(Lease const&) -> Lease& = delete;
            Lease(Lease&& other) noexcept;
            auto operator=(Lease&& other) noexcept -> Lease&;
            ~Lease();
            // A multiplexed child shares its transport owner's process-wide
            // limit. No separate heap owner or worker-local quota is created.
            [[nodiscard]] auto try_acquire() const noexcept -> std::optional<Lease>;
        };
        explicit SessionQuota(std::size_t limit);
        SessionQuota(SessionQuota const& other) noexcept;
        SessionQuota(SessionQuota&& other) noexcept;
        auto operator=(SessionQuota const& other) noexcept -> SessionQuota&;
        auto operator=(SessionQuota&& other) noexcept -> SessionQuota&;
        ~SessionQuota();
        [[nodiscard]] auto try_acquire() const noexcept -> std::optional<Lease>;
        [[nodiscard]] auto used() const noexcept -> std::size_t;
        [[nodiscard]] auto limit() const noexcept -> std::size_t { return limit_; }
        // A published listener can apply a new limit while old leases stay charged.
        [[nodiscard]] auto with_limit(std::size_t maximum) const noexcept -> SessionQuota;
    };
}

module :private;

namespace relay {
    auto SessionQuota::add_owner(State* state) noexcept -> void {
        if (state) state->counts.fetch_add(State::kOwnerUnit, std::memory_order_relaxed);
    }
    auto SessionQuota::release_owner(State* state) noexcept -> void {
        if (state && state->counts.fetch_sub(State::kOwnerUnit, std::memory_order_acq_rel) == State::kOwnerUnit)
            delete state;
    }
    SessionQuota::Lease::Lease(State* state, std::size_t maximum) noexcept
        : state_(state), limit_(maximum) {}
    auto SessionQuota::Lease::acquire(State* state, std::size_t maximum) noexcept -> std::optional<Lease> {
        if (!state || !maximum) return {};
        auto const cap = std::min<std::uint64_t>(maximum, State::kUsedMask - 1);
        auto cur = state->counts.load(std::memory_order_relaxed);
        while ((cur & State::kUsedMask) < cap) {
            if (state->counts.compare_exchange_weak(cur, cur + 1, std::memory_order_relaxed))
                return Lease(state, maximum);
        }
        return {};
    }
    auto SessionQuota::Lease::release() noexcept -> void {
        if (auto* state = std::exchange(state_, nullptr)) {
            if (state->counts.fetch_sub(1, std::memory_order_acq_rel) == 1) delete state;
        }
    }
    SessionQuota::Lease::Lease(Lease&& other) noexcept
        : state_(std::exchange(other.state_, nullptr)), limit_(other.limit_) {}
    auto SessionQuota::Lease::operator=(Lease&& other) noexcept -> Lease& {
        if (this != &other) {
            release();
            state_ = std::exchange(other.state_, nullptr);
            limit_ = other.limit_;
        }
        return *this;
    }
    SessionQuota::Lease::~Lease() { release(); }
    auto SessionQuota::Lease::try_acquire() const noexcept -> std::optional<Lease> { return acquire(state_, limit_); }
    SessionQuota::SessionQuota(std::size_t limit) : state_(new State{}), limit_(limit) {}
    SessionQuota::SessionQuota(SessionQuota const& other) noexcept : state_(other.state_), limit_(other.limit_) {
        add_owner(state_);
    }
    SessionQuota::SessionQuota(SessionQuota&& other) noexcept
        : state_(std::exchange(other.state_, nullptr)), limit_(other.limit_) {}
    auto SessionQuota::operator=(SessionQuota const& other) noexcept -> SessionQuota& {
        if (this != &other) {
            add_owner(other.state_);
            release_owner(state_);
            state_ = other.state_;
            limit_ = other.limit_;
        }
        return *this;
    }
    auto SessionQuota::operator=(SessionQuota&& other) noexcept -> SessionQuota& {
        if (this != &other) {
            release_owner(state_);
            state_ = std::exchange(other.state_, nullptr);
            limit_ = other.limit_;
        }
        return *this;
    }
    SessionQuota::~SessionQuota() { release_owner(state_); }
    auto SessionQuota::with_limit(std::size_t maximum) const noexcept -> SessionQuota {
        auto quota = *this;
        quota.limit_ = maximum;
        return quota;
    }
    auto SessionQuota::try_acquire() const noexcept -> std::optional<Lease> {
        return Lease::acquire(state_, limit_);
    }
    auto SessionQuota::used() const noexcept -> std::size_t {
        return state_ ? static_cast<std::size_t>(state_->counts.load(std::memory_order_relaxed) & State::kUsedMask) : 0;
    }
}
