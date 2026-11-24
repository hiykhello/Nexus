module;
#if defined(_MSC_VER) && !defined(__clang__)
#include <intrin.h>
#endif

export module utility;
import std;

export namespace utility {
    inline auto secure_zero(void* ptr, std::size_t size) noexcept -> void {
        if (!ptr || size == 0) return;
        volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
        for (std::size_t i = 0; i < size; ++i) p[i] = 0;
#if defined(_MSC_VER) && !defined(__clang__)
        _ReadWriteBarrier();
#else
        asm volatile("" : : "r"(ptr) : "memory");
#endif
    }

    template<class T, std::size_t Extent>
    inline auto secure_zero(std::span<T, Extent> buffer) noexcept -> void {
        if (!buffer.empty()) secure_zero(buffer.data(), buffer.size_bytes());
    }

#if defined(__cpp_lib_atomic_shared_ptr) && __cpp_lib_atomic_shared_ptr >= 201711L
    template<class T>
    class atomic_shared_ptr {
        std::atomic<std::shared_ptr<T>> value_{};
        std::atomic<std::uint64_t> version_{0};
    public:
        constexpr atomic_shared_ptr() noexcept = default;
        atomic_shared_ptr(std::shared_ptr<T> desired) noexcept
            : version_(desired ? 1 : 0) {
            value_.store(std::move(desired), std::memory_order_relaxed);
        }
        atomic_shared_ptr(atomic_shared_ptr const&) = delete;
        auto operator=(atomic_shared_ptr const&) -> atomic_shared_ptr& = delete;

        [[nodiscard]] auto version(std::memory_order order = std::memory_order_acquire) const noexcept -> std::uint64_t {
            return version_.load(order);
        }
        [[nodiscard]] auto load(std::memory_order order = std::memory_order_seq_cst) const noexcept -> std::shared_ptr<T> {
            return value_.load(order);
        }
        auto store(std::shared_ptr<T> desired, std::memory_order order = std::memory_order_seq_cst) noexcept -> void {
            value_.store(std::move(desired), order);
            version_.fetch_add(1, std::memory_order_release);
        }
        [[nodiscard]] auto exchange(std::shared_ptr<T> desired,
                                    std::memory_order order = std::memory_order_seq_cst) noexcept -> std::shared_ptr<T> {
            auto old = value_.exchange(std::move(desired), order);
            version_.fetch_add(1, std::memory_order_release);
            return old;
        }
        auto compare_exchange_strong(std::shared_ptr<T>& expected, std::shared_ptr<T> desired,
                                     std::memory_order success = std::memory_order_seq_cst,
                                     std::memory_order failure = std::memory_order_seq_cst) noexcept -> bool {
            if (value_.compare_exchange_strong(expected, std::move(desired), success, failure)) {
                version_.fetch_add(1, std::memory_order_release);
                return true;
            }
            return false;
        }
        auto compare_exchange_weak(std::shared_ptr<T>& expected, std::shared_ptr<T> desired,
                                   std::memory_order success = std::memory_order_seq_cst,
                                   std::memory_order failure = std::memory_order_seq_cst) noexcept -> bool {
            if (value_.compare_exchange_weak(expected, std::move(desired), success, failure)) {
                version_.fetch_add(1, std::memory_order_release);
                return true;
            }
            return false;
        }
    };
#else
    template<class T>
    class atomic_shared_ptr {
        mutable std::atomic_flag lock_{};
        std::shared_ptr<T> value_{};
        std::atomic<std::uint64_t> version_{0};

        static auto cpu_pause() noexcept -> void {
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__)
            __builtin_ia32_pause();
#elif defined(__aarch64__)
            asm volatile("yield" ::: "memory");
#endif
        }
        auto acquire() const noexcept -> void {
            unsigned spins = 0;
            while (lock_.test_and_set(std::memory_order_acquire)) {
                while (lock_.test(std::memory_order_relaxed)) {
                    if (++spins < 32) cpu_pause();
                    else { std::this_thread::yield(); spins = 0; }
                }
            }
        }
        auto release() const noexcept -> void {
            lock_.clear(std::memory_order_release);
        }
        [[nodiscard]] static auto same_ptr(std::shared_ptr<T> const& a, std::shared_ptr<T> const& b) noexcept -> bool {
            return a.get() == b.get() && !a.owner_before(b) && !b.owner_before(a);
        }

    public:
        constexpr atomic_shared_ptr() noexcept = default;
        atomic_shared_ptr(std::shared_ptr<T> desired) noexcept
            : value_(std::move(desired)), version_(value_ ? 1 : 0) {}
        atomic_shared_ptr(atomic_shared_ptr const&) = delete;
        auto operator=(atomic_shared_ptr const&) -> atomic_shared_ptr& = delete;

        [[nodiscard]] auto version(std::memory_order order = std::memory_order_acquire) const noexcept -> std::uint64_t {
            return version_.load(order);
        }
        [[nodiscard]] auto load(std::memory_order = std::memory_order_seq_cst) const noexcept -> std::shared_ptr<T> {
            acquire();
            auto copy = value_;
            release();
            return copy;
        }
        auto store(std::shared_ptr<T> desired, std::memory_order = std::memory_order_seq_cst) noexcept -> void {
            acquire();
            auto old = std::exchange(value_, std::move(desired));
            version_.fetch_add(1, std::memory_order_release);
            release();
        }
        [[nodiscard]] auto exchange(std::shared_ptr<T> desired,
                                    std::memory_order = std::memory_order_seq_cst) noexcept -> std::shared_ptr<T> {
            acquire();
            auto old = std::exchange(value_, std::move(desired));
            version_.fetch_add(1, std::memory_order_release);
            release();
            return old;
        }
        auto compare_exchange_strong(std::shared_ptr<T>& expected, std::shared_ptr<T> desired,
                                     std::memory_order = std::memory_order_seq_cst,
                                     std::memory_order = std::memory_order_seq_cst) noexcept -> bool {
            std::shared_ptr<T> dropped;
            acquire();
            if (same_ptr(value_, expected)) {
                dropped = std::exchange(value_, std::move(desired));
                version_.fetch_add(1, std::memory_order_release);
                release();
                return true;
            }
            dropped = value_;
            release();
            expected = std::move(dropped);
            return false;
        }
        auto compare_exchange_weak(std::shared_ptr<T>& expected, std::shared_ptr<T> desired,
                                   std::memory_order success = std::memory_order_seq_cst,
                                   std::memory_order failure = std::memory_order_seq_cst) noexcept -> bool {
            return compare_exchange_strong(expected, std::move(desired), success, failure);
        }
    };
#endif

    template<class Fn>
    class scope_exit {
        Fn fn_;
        bool active_ = true;
    public:
        template<class F>
            requires (!std::same_as<std::remove_cvref_t<F>, scope_exit>) && std::constructible_from<Fn, F>
        constexpr explicit scope_exit(F&& fn) noexcept(std::is_nothrow_constructible_v<Fn, F>)
            : fn_(std::forward<F>(fn)) {}
        constexpr scope_exit(scope_exit&& other) noexcept(std::is_nothrow_move_constructible_v<Fn>)
            : fn_(std::move(other.fn_)), active_(std::exchange(other.active_, false)) {}
        scope_exit(scope_exit const&) = delete;
        auto operator=(scope_exit const&) -> scope_exit& = delete;
        auto operator=(scope_exit&&) -> scope_exit& = delete;
        constexpr ~scope_exit() noexcept {
            if (active_) fn_();
        }
        constexpr auto release() noexcept -> void { active_ = false; }
    };
    template<class F>
    scope_exit(F) -> scope_exit<std::decay_t<F>>;
}
