export module proxy.session_quota;
import std;
export namespace proxy {
    class SessionQuota {
        struct State {
            std::atomic<std::size_t> used{0};
        };
        std::shared_ptr<State> state_;
        std::size_t limit_;
    public:
        class Lease {
            friend class SessionQuota;
            std::shared_ptr<State> state_;
            std::size_t limit_;
            explicit Lease(std::shared_ptr<State> state,std::size_t maximum) noexcept;
            static auto acquire(std::shared_ptr<State> const& state,std::size_t maximum) noexcept -> std::optional<Lease>;
            auto release() noexcept -> void;
        public:
            Lease(Lease const&)=delete;
            auto operator=(Lease const&) -> Lease& =delete;
            Lease(Lease&& other) noexcept;
            auto operator=(Lease&& other) noexcept -> Lease&;
            ~Lease();
            // A multiplexed child shares its transport owner's process-wide
            // limit. No separate heap owner or worker-local quota is created.
            [[nodiscard]] auto try_acquire() const noexcept -> std::optional<Lease>;
        };
        explicit SessionQuota(std::size_t limit);
        [[nodiscard]] auto try_acquire() const noexcept -> std::optional<Lease>;
        [[nodiscard]] auto used() const noexcept -> std::size_t;
        [[nodiscard]] auto limit() const noexcept -> std::size_t { return limit_; }
        // A published listener can apply a new limit while old leases stay charged.
        [[nodiscard]] auto with_limit(std::size_t maximum) const noexcept -> SessionQuota;
    };
}

module :private;

namespace proxy {
    SessionQuota::Lease::Lease(std::shared_ptr<State> state,std::size_t maximum) noexcept
        : state_(std::move(state)),limit_(maximum) {}
    auto SessionQuota::Lease::acquire(std::shared_ptr<State> const& state,std::size_t maximum) noexcept -> std::optional<Lease> {
        if (!state) return {};
        auto used=state->used.load(std::memory_order_relaxed);
        while (used<maximum) {
            if (state->used.compare_exchange_weak(used,used+1,std::memory_order_relaxed)) return Lease(state,maximum);
        }
        return {};
    }
    auto SessionQuota::Lease::release() noexcept -> void {
        if (state_) {
            state_->used.fetch_sub(1,std::memory_order_relaxed);
            state_.reset();
        }
    }
    SessionQuota::Lease::Lease(Lease&& other) noexcept : state_(std::move(other.state_)),limit_(other.limit_) {}
    auto SessionQuota::Lease::operator=(Lease&& other) noexcept -> Lease& {
        if (this!=&other) { release(); state_=std::move(other.state_); limit_=other.limit_; }
        return *this;
    }
    SessionQuota::Lease::~Lease() { release(); }
    auto SessionQuota::Lease::try_acquire() const noexcept -> std::optional<Lease> { return acquire(state_,limit_); }
    SessionQuota::SessionQuota(std::size_t limit) : state_(std::make_shared<State>()),limit_(limit) {}
    auto SessionQuota::with_limit(std::size_t maximum) const noexcept -> SessionQuota {
        auto quota=*this;
        quota.limit_=maximum;
        return quota;
    }
    auto SessionQuota::try_acquire() const noexcept -> std::optional<Lease> {
        return Lease::acquire(state_,limit_);
    }
    auto SessionQuota::used() const noexcept -> std::size_t {
        return state_->used.load(std::memory_order_relaxed);
    }
}
