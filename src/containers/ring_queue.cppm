export module containers.ring_queue;
import std;

export namespace containers {
    // The producer owns tail mutation and the consumer owns head mutation.
    // Slots belong to the producer until commit and to the consumer until consume.
    template<std::size_t Capacity>
    class SpscRingQueue {
        static_assert(std::has_single_bit(Capacity));
        alignas(64) std::atomic<std::size_t> head_{0};
        alignas(64) std::atomic<std::size_t> tail_{0};

    public:
        [[nodiscard]] auto writable(this SpscRingQueue const& self) noexcept -> std::size_t {
            auto tail = self.tail_.load(std::memory_order_relaxed);
            return Capacity - (tail - self.head_.load(std::memory_order_acquire));
        }

        [[nodiscard]] auto readable(this SpscRingQueue const& self) noexcept -> std::size_t {
            auto head = self.head_.load(std::memory_order_relaxed);
            return self.tail_.load(std::memory_order_acquire) - head;
        }

        [[nodiscard]] auto tail(this SpscRingQueue const& self) noexcept -> std::size_t {
            return self.tail_.load(std::memory_order_relaxed) % Capacity;
        }

        [[nodiscard]] auto front(this SpscRingQueue const& self) noexcept -> std::size_t {
            return self.head_.load(std::memory_order_relaxed) % Capacity;
        }

        auto commit(this SpscRingQueue& self) noexcept -> void {
            self.tail_.store(self.tail_.load(std::memory_order_relaxed) + 1, std::memory_order_release);
        }

        auto consume(this SpscRingQueue& self) noexcept -> void {
            self.head_.store(self.head_.load(std::memory_order_relaxed) + 1, std::memory_order_release);
        }
    };

    // Tracks slot order for storage supplied by the caller. An insertion
    // can prepare the tail slot before committing it. Removal never moves
    // the other occupied slots.
    template<std::size_t Capacity>
    class RingQueue {
        static_assert(Capacity>0);
        std::size_t head_=0,size_=0;
    public:
        [[nodiscard]] auto size(this RingQueue const& self) noexcept -> std::size_t {return self.size_;}
        [[nodiscard]] auto empty(this RingQueue const& self) noexcept -> bool {return self.size_==0;}
        [[nodiscard]] auto full(this RingQueue const& self) noexcept -> bool {return self.size_==Capacity;}
        // Access the tail only when there is space and the front only when
        // an item is available. The owner controls construction/destruction.
        [[nodiscard]] auto tail(this RingQueue const& self) noexcept -> std::size_t {
            return (self.head_+self.size_)%Capacity;
        }
        [[nodiscard]] auto front(this RingQueue const& self) noexcept -> std::size_t {return self.head_;}
        auto commit(this RingQueue& self) noexcept -> void {++self.size_;}
        auto consume(this RingQueue& self) noexcept -> void {
            --self.size_;
            self.head_=self.size_ ? (self.head_+1)%Capacity : 0;
        }
        auto reset(this RingQueue& self) noexcept -> void {self.head_=self.size_=0;}
    };

    // Bounded FIFO backed by RingQueue<Capacity> with inline array storage for
    // small capacities and lazy single-slab heap storage for larger capacities.
    template<class T, std::size_t Capacity, bool HeapBacked = (Capacity > 32)>
    class BoundedRing {
        static_assert(Capacity > 0);
        RingQueue<Capacity> ring_{};
        std::conditional_t<HeapBacked, std::unique_ptr<std::optional<T>[]>, std::array<std::optional<T>, Capacity>> slots_{};

        auto ensure_storage() -> void {
            if constexpr (HeapBacked) {
                if (!slots_) slots_ = std::make_unique<std::optional<T>[]>(Capacity);
            }
        }
    public:
        BoundedRing() = default;
        BoundedRing(BoundedRing const&) = delete;
        auto operator=(BoundedRing const&) -> BoundedRing& = delete;
        BoundedRing(BoundedRing&& other) noexcept : ring_(other.ring_), slots_(std::move(other.slots_)) {
            other.ring_.reset();
        }
        auto operator=(BoundedRing&& other) noexcept -> BoundedRing& {
            if (this != &other) {
                clear();
                ring_ = other.ring_;
                slots_ = std::move(other.slots_);
                other.ring_.reset();
            }
            return *this;
        }
        ~BoundedRing() { clear(); }

        [[nodiscard]] auto size() const noexcept -> std::size_t { return ring_.size(); }
        [[nodiscard]] static constexpr auto capacity() noexcept -> std::size_t { return Capacity; }
        [[nodiscard]] auto empty() const noexcept -> bool { return ring_.empty(); }
        [[nodiscard]] auto full() const noexcept -> bool { return ring_.full(); }
        [[nodiscard]] auto front() noexcept -> T& { return *slots_[ring_.front()]; }
        [[nodiscard]] auto front() const noexcept -> T const& { return *slots_[ring_.front()]; }
        [[nodiscard]] auto operator[](std::size_t index) noexcept -> T& {
            return *slots_[(ring_.front() + index) % Capacity];
        }
        [[nodiscard]] auto operator[](std::size_t index) const noexcept -> T const& {
            return *slots_[(ring_.front() + index) % Capacity];
        }
        template<class... Args>
        auto emplace_back(Args&&... args) -> bool {
            if (ring_.full()) return false;
            ensure_storage();
            slots_[ring_.tail()].emplace(std::forward<Args>(args)...);
            ring_.commit();
            return true;
        }
        auto push_back(T const& value) -> bool { return emplace_back(value); }
        auto push_back(T&& value) -> bool { return emplace_back(std::move(value)); }
        auto pop_front() noexcept -> void {
            if (ring_.empty()) return;
            slots_[ring_.front()].reset();
            ring_.consume();
        }
        auto clear() noexcept -> void {
            if constexpr (HeapBacked) {
                if (!slots_) { ring_.reset(); return; }
            }
            while (!ring_.empty()) {
                slots_[ring_.front()].reset();
                ring_.consume();
            }
        }
    };
}
