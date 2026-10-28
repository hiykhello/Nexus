#ifndef NEXUS_PROXY_SESSION_QUOTA_HPP
#define NEXUS_PROXY_SESSION_QUOTA_HPP
// Import std before this private header.
namespace nexus::proxy {
    class SessionQuota {
        struct State {
            inline explicit State(std::size_t maximum) : limit(maximum) {}
            std::size_t const limit;
            std::atomic<std::size_t> used{0};
        };
        std::shared_ptr<State> state_;
    public:
        class Lease {
            friend class SessionQuota;
            std::shared_ptr<State> state_;
            inline explicit Lease(std::shared_ptr<State> state) noexcept : state_(std::move(state)) {}
            inline auto release() noexcept -> void {
                if (state_) {
                    state_->used.fetch_sub(1,std::memory_order_relaxed);
                    state_.reset();
                }
            }
        public:
            Lease(Lease const&)=delete;
            auto operator=(Lease const&) -> Lease& =delete;
            inline Lease(Lease&& other) noexcept : state_(std::move(other.state_)) {}
            inline auto operator=(Lease&& other) noexcept -> Lease& {
                if (this!=&other) { release(); state_=std::move(other.state_); }
                return *this;
            }
            inline ~Lease() { release(); }
        };
        inline explicit SessionQuota(std::size_t limit) : state_(std::make_shared<State>(limit)) {}
        [[nodiscard]] inline auto try_acquire() const noexcept -> std::optional<Lease> {
            auto used=state_->used.load(std::memory_order_relaxed);
            while (used<state_->limit) {
                if (state_->used.compare_exchange_weak(used,used+1,std::memory_order_relaxed))
                    return Lease(state_);
            }
            return std::nullopt;
        }
        [[nodiscard]] inline auto used() const noexcept -> std::size_t {
            return state_->used.load(std::memory_order_relaxed);
        }
    };
}
#endif
