export module quic.transport_memory;
import std;
import memory.budget;
import ngtcp2;

export namespace quic {
    struct NativeHeap {
        static auto allocate(std::size_t bytes) noexcept -> void* { return std::malloc(bytes); }
        static auto release(void* pointer) noexcept -> void { std::free(pointer); }
    };

    // Concrete non-moving allocation owner for ngtcp2 native memory blocks.
    template<class Heap = NativeHeap>
    class NativeTransportMemory {
        struct alignas(std::max_align_t) Header { std::size_t bytes; };
        memory::Budget budget_;
        std::size_t used_=0;
    public:
        explicit NativeTransportMemory(std::size_t limit) noexcept : budget_(limit) {
            (void)budget_.attach(this,[](void* owner) noexcept {
                return static_cast<NativeTransportMemory*>(owner)->used_;
            });
        }
        ~NativeTransportMemory() { if (used_) std::terminate(); }
        NativeTransportMemory(NativeTransportMemory const&) = delete;
        auto operator=(NativeTransportMemory const&) -> NativeTransportMemory& = delete;
        auto used() const noexcept -> std::size_t { return used_; }
        auto limit() const noexcept -> std::size_t { return budget_.limit(); }
        static auto allocate(std::size_t bytes, void* owner) noexcept -> void* {
            auto& self = *static_cast<NativeTransportMemory*>(owner);
            if (bytes > std::numeric_limits<std::size_t>::max() - sizeof(Header)) return nullptr;
            auto charge = std::max<std::size_t>(bytes, 1) + sizeof(Header);
            auto used=self.budget_.used();
            if (used>self.limit() || charge>self.limit()-used) return nullptr;
            auto* memory = static_cast<Header*>(Heap::allocate(charge));
            if (!memory) return nullptr;
            memory->bytes = charge;
            self.used_ += charge;
            return memory + 1;
        }
        static auto release(void* pointer, void* owner) noexcept -> void {
            if (!pointer) return;
            auto& self = *static_cast<NativeTransportMemory*>(owner);
            auto* memory = static_cast<Header*>(pointer) - 1;
            self.used_ -= memory->bytes;
            Heap::release(memory);
        }
        static auto zero(std::size_t count, std::size_t bytes, void* owner) noexcept -> void* {
            if (bytes && count > std::numeric_limits<std::size_t>::max() / bytes) return nullptr;
            auto amount = count * bytes;
            auto* memory = allocate(amount, owner);
            if (memory) std::memset(memory, 0, amount);
            return memory;
        }
        static auto resize(void* pointer, std::size_t bytes, void* owner) noexcept -> void* {
            if (!pointer) return allocate(bytes, owner);
            if (!bytes) { release(pointer, owner); return nullptr; }
            auto* memory = allocate(bytes, owner);
            if (!memory) return nullptr;
            auto old = (static_cast<Header*>(pointer) - 1)->bytes - sizeof(Header);
            std::memcpy(memory, pointer, std::min(old, bytes));
            release(pointer, owner);
            return memory;
        }
        auto transport() noexcept -> ngtcp2::ngtcp2_mem { return {this, allocate, release, zero, resize}; }
    };
}
