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
}
