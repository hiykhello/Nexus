export module memory.budget;
import std;

export namespace memory {
    // Serialized on the connection's executor. The optional attached owner
    // supplies its own live charge; reservations keep this budget alive.
    class Budget {
        std::size_t limit_, reserved_=0;
        void* owner_=nullptr;
        std::size_t (*owner_usage_)(void*) noexcept = nullptr;
    public:
        explicit Budget(std::size_t limit) noexcept : limit_(limit) {}
        Budget(Budget const&)=delete;
        auto operator=(Budget const&) -> Budget& = delete;
        [[nodiscard]] auto limit() const noexcept -> std::size_t { return limit_; }
        [[nodiscard]] auto reserved() const noexcept -> std::size_t { return reserved_; }
        [[nodiscard]] auto used() const noexcept -> std::size_t;
        // The owner enforces the limit before increasing its usage. One connection
        // session can attach at a time; it must detach before destruction.
        auto attach(void* owner,std::size_t (*usage)(void*) noexcept) noexcept -> bool;
        void detach(void* owner) noexcept;
        class Reservation {
            std::shared_ptr<Budget> budget_;
            std::size_t size_=0;
            Reservation(std::shared_ptr<Budget> budget,std::size_t size) noexcept : budget_(std::move(budget)),size_(size) {}
            friend class Budget;
        public:
            Reservation(Reservation const&)=delete;
            auto operator=(Reservation const&) -> Reservation& = delete;
            Reservation(Reservation&& other) noexcept : budget_(std::move(other.budget_)),size_(std::exchange(other.size_,0)) {}
            auto operator=(Reservation&& other) noexcept -> Reservation& {
                if (this!=&other) { reset(); budget_=std::move(other.budget_); size_=std::exchange(other.size_,0); }
                return *this;
            }
            ~Reservation() { reset(); }
            void reset() noexcept;
            // Only reduce an existing reservation; growing requires a new admission.
            auto shrink(std::size_t size) noexcept -> bool;
            [[nodiscard]] auto size() const noexcept -> std::size_t { return size_; }
        };
        [[nodiscard]] static auto reserve(std::shared_ptr<Budget> budget,std::size_t size) noexcept -> std::optional<Reservation>;
    };
}

module :private;

namespace memory {
    auto Budget::used() const noexcept -> std::size_t {
        auto local=owner_ ? owner_usage_(owner_) : 0;
        return local>std::numeric_limits<std::size_t>::max()-reserved_ ? std::numeric_limits<std::size_t>::max() : reserved_+local;
    }
    auto Budget::attach(void* owner,std::size_t (*usage)(void*) noexcept) noexcept -> bool {
        if (!owner || !usage || owner_ || usage(owner)>limit_-reserved_) return false;
        owner_=owner; owner_usage_=usage; return true;
    }
    void Budget::detach(void* owner) noexcept { if (owner_==owner) { owner_=nullptr; owner_usage_=nullptr; } }
    void Budget::Reservation::reset() noexcept { if (budget_) { budget_->reserved_-=size_; budget_.reset(); size_=0; } }
    auto Budget::Reservation::shrink(std::size_t size) noexcept -> bool {
        if (size>size_) return false;
        if (budget_) budget_->reserved_-=size_-size;
        size_=size; return true;
    }
    auto Budget::reserve(std::shared_ptr<Budget> budget,std::size_t size) noexcept -> std::optional<Reservation> {
        if (!budget || !size) return {};
        auto used=budget->used();
        if (used>budget->limit_ || size>budget->limit_-used) return {};
        budget->reserved_+=size; return Reservation(std::move(budget),size);
    }
}
