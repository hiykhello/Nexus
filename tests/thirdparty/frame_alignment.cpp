// Regression for Capy a1531310772ebc92b1274c5f39cb6f1f11998194.
// Exercise the public launcher with an allocator that provides precisely
// its value_type's alignment, including the allocator copies kept in frames.
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/execution_context.hpp>
#include <boost/capy/ex/frame_allocator.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <memory>
#include <new>
#include <stdexcept>

namespace capy = boost::capy;
namespace {
constexpr auto alignment = std::max(alignof(std::max_align_t),
    static_cast<std::size_t>(__STDCPP_DEFAULT_NEW_ALIGNMENT__));

auto address(void const* pointer) noexcept -> std::uintptr_t {
    // Do not let assumptions attached to an allocation fold this check.
    volatile auto value = reinterpret_cast<std::uintptr_t>(pointer);
    return value;
}

struct Arena {
    struct Block { void* pointer; std::size_t bytes; bool released = false; };
    alignas(alignment) std::array<std::byte, 16384> storage;
    std::array<Block, 64> blocks{};
    std::array<std::uintptr_t, 128> copies{}, destroyed{};
    std::size_t used = 1, allocated = 0, released = 0, copy_count = 0, destroyed_count = 0;
    unsigned live_scopes = 0, exited_scopes = 0;
    bool invalid = false;

    auto allocate(this Arena& self, std::size_t bytes, std::size_t align) -> void* {
        void* pointer = self.storage.data() + self.used;
        auto space = self.storage.size() - self.used;
        if (self.allocated == self.blocks.size() || !std::align(align, bytes, pointer, space))
            throw std::bad_alloc();
        self.used = static_cast<std::byte*>(pointer) - self.storage.data() + bytes;
        self.blocks[self.allocated++] = {pointer, bytes};
        // A byte rebind used to request only alignment 1 here. Reject before
        // constructing a coroutine at that address, avoiding undefined behavior
        // when this regression is deliberately run against the old dependency.
        if (address(pointer) % alignment) {
            self.invalid = true;
            throw std::runtime_error("misaligned frame allocation");
        }
        return pointer;
    }
    auto deallocate(this Arena& self, void* pointer, std::size_t bytes) noexcept -> void {
        for (auto& block : self.blocks) {
            if (block.pointer != pointer) continue;
            if (block.released || block.bytes != bytes) self.invalid = true;
            block.released = true;
            ++self.released;
            return;
        }
        self.invalid = true;
    }
    auto record(this Arena& self, void const* pointer, bool destruction) noexcept -> void {
        auto& count = destruction ? self.destroyed_count : self.copy_count;
        auto& log = destruction ? self.destroyed : self.copies;
        if (count == log.size()) { self.invalid = true; return; }
        log[count++] = address(pointer);
    }
    auto checked(this Arena const& self) noexcept -> bool {
        if (self.invalid || self.allocated < 3 || self.released != self.allocated ||
            self.live_scopes || self.exited_scopes != 2) return false;
        std::size_t embedded = 0;
        for (std::size_t i = 0; i < self.copy_count; ++i) {
            auto copy = self.copies[i];
            for (std::size_t j = 0; j < self.allocated; ++j) {
                auto const& block = self.blocks[j];
                auto base = address(block.pointer);
                if (copy < base || copy >= base + block.bytes) continue;
                ++embedded;
                if (copy % alignment ||
                    std::find(self.destroyed.begin(), self.destroyed.begin() + self.destroyed_count, copy) ==
                        self.destroyed.begin() + self.destroyed_count) return false;
            }
        }
        return embedded != 0;
    }
};

template<class T>
struct alignas(alignment) Allocator {
    using value_type = T;
    Arena* arena;
    explicit Allocator(Arena& value) noexcept : arena(&value) { arena->record(this, false); }
    Allocator(Allocator const& other) noexcept : arena(other.arena) { arena->record(this, false); }
    template<class U>
    Allocator(Allocator<U> const& other) noexcept : arena(other.arena) { arena->record(this, false); }
    ~Allocator() { arena->record(this, true); }
    auto allocate(this Allocator& self, std::size_t count) -> T* {
        return static_cast<T*>(self.arena->allocate(count * sizeof(T), alignof(T)));
    }
    auto deallocate(this Allocator& self, T* pointer, std::size_t count) noexcept -> void {
        self.arena->deallocate(pointer, count * sizeof(T));
    }
    template<class U>
    auto operator==(Allocator<U> const& other) const noexcept -> bool { return arena == other.arena; }
};

struct Context : capy::execution_context {
    Context() : execution_context(this) {}
};
struct Executor {
    Context* owner;
    auto context() const noexcept -> Context& { return *owner; }
    auto on_work_started() const noexcept -> void {}
    auto on_work_finished() const noexcept -> void {}
    auto dispatch(capy::continuation& value) const -> std::coroutine_handle<> { return value.h; }
    auto post(capy::continuation& value) const -> void { capy::safe_resume(value.h); }
    auto operator==(Executor const&) const -> bool = default;
};
static_assert(capy::Executor<Executor>);

struct Scope {
    Arena& arena;
    explicit Scope(Arena& state) : arena(state) { ++arena.live_scopes; }
    ~Scope() { --arena.live_scopes; ++arena.exited_scopes; }
};

[[gnu::noinline]] auto child(Arena& arena, capy::async_event& gate, bool fail) -> capy::task<int> {
    Scope scope(arena);
    alignas(alignment) std::byte local{};
    arena.invalid |= address(&local) % alignment != 0;
    auto [error] = co_await gate.wait();
    if (error) throw std::runtime_error("unexpected event cancellation");
    if (fail) throw std::runtime_error("child failure");
    co_return 42;
}
[[gnu::noinline]] auto parent(Arena& arena, capy::async_event& gate, bool fail) -> capy::task<int> {
    Scope scope(arena);
    co_return co_await child(arena, gate, fail);
}

auto check(bool fail) -> bool {
    Arena arena;
    Context context;
    capy::async_event gate;
    bool success = false, failure = false;
    bool parked = false;
    auto previous = capy::get_current_frame_allocator();
    try {
        capy::run_async(Executor{&context}, Allocator<std::byte>{arena},
            [&](int value) { success = value == 42; },
            [&](std::exception_ptr error) { failure = error != nullptr; })(parent(arena, gate, fail));
        parked = arena.live_scopes == 2 && !success && !failure && capy::get_current_frame_allocator() == previous;
        gate.set();
    } catch (std::exception const& error) {
        std::fprintf(stderr, "frame alignment: %s\n", error.what());
        return false;
    }
    auto passed = parked && success == !fail && failure == fail && capy::get_current_frame_allocator() == previous && arena.checked();
    if (!passed) std::fprintf(stderr,
        "frame alignment: fail=%d parked=%d success=%d failure=%d invalid=%d blocks=%zu released=%zu scopes=%u/%u copies=%zu/%zu\n",
        fail, parked, success, failure, arena.invalid, arena.allocated, arena.released,
        arena.live_scopes, arena.exited_scopes, arena.copy_count, arena.destroyed_count);
    return passed;
}
}

auto main() -> int {
    if (!check(false) || !check(true)) return 1;
    std::puts("Capy aligned standard allocator: suspended frames, embedded copies and success/error cleanup passed");
}
