export module nexus.compat;
export import nexus.compat.callable;
import std;

export namespace nexus {
    template<class T, std::size_t N>
    class inplace_vector {
        alignas(T) std::byte storage_[N == 0 ? 1 : sizeof(T) * N]{};
        std::size_t size_ = 0;

        [[noreturn]] static auto fail_overflow() -> void {
#if defined(__cpp_exceptions) && __cpp_exceptions >= 199711L
            throw std::bad_alloc();
#else
            std::abort();
#endif
        }
        [[noreturn]] static auto fail_range() -> void {
#if defined(__cpp_exceptions) && __cpp_exceptions >= 199711L
            throw std::out_of_range("nexus::inplace_vector::at");
#else
            std::abort();
#endif
        }
        constexpr auto slot(std::size_t i) noexcept -> T* {
            return std::launder(reinterpret_cast<T*>(storage_) + i);
        }
        constexpr auto slot(std::size_t i) const noexcept -> T const* {
            return std::launder(reinterpret_cast<T const*>(storage_) + i);
        }
    public:
        using value_type = T;
        using size_type = std::size_t;
        using difference_type = std::ptrdiff_t;
        using reference = T&;
        using const_reference = T const&;
        using pointer = T*;
        using const_pointer = T const*;
        using iterator = T*;
        using const_iterator = T const*;
        using reverse_iterator = std::reverse_iterator<iterator>;
        using const_reverse_iterator = std::reverse_iterator<const_iterator>;

        constexpr inplace_vector() noexcept = default;
        constexpr explicit inplace_vector(size_type count) { resize(count); }
        constexpr inplace_vector(size_type count, T const& value) { assign(count, value); }
        constexpr inplace_vector(std::initializer_list<T> init) { assign(init.begin(), init.end()); }
        template<std::input_iterator It>
        constexpr inplace_vector(It first, It last) { assign(first, last); }

        constexpr inplace_vector(inplace_vector const& other)
            requires std::is_trivially_copy_constructible_v<T> = default;
        constexpr inplace_vector(inplace_vector const& other) {
            for (size_type i = 0; i < other.size_; ++i) unchecked_emplace_back(*other.slot(i));
        }
        constexpr inplace_vector(inplace_vector&& other) noexcept(std::is_nothrow_move_constructible_v<T>)
            requires std::is_trivially_move_constructible_v<T> = default;
        constexpr inplace_vector(inplace_vector&& other) noexcept(std::is_nothrow_move_constructible_v<T>) {
            for (size_type i = 0; i < other.size_; ++i) unchecked_emplace_back(std::move(*other.slot(i)));
        }
        constexpr auto operator=(inplace_vector const& other) -> inplace_vector&
            requires std::is_trivially_copy_assignable_v<T> && std::is_trivially_copy_constructible_v<T> && std::is_trivially_destructible_v<T> = default;
        constexpr auto operator=(inplace_vector const& other) -> inplace_vector& {
            if (this != &other) assign(other.begin(), other.end());
            return *this;
        }
        constexpr auto operator=(inplace_vector&& other) noexcept(std::is_nothrow_move_assignable_v<T> && std::is_nothrow_move_constructible_v<T>) -> inplace_vector&
            requires std::is_trivially_move_assignable_v<T> && std::is_trivially_move_constructible_v<T> && std::is_trivially_destructible_v<T> = default;
        constexpr auto operator=(inplace_vector&& other) noexcept(std::is_nothrow_move_assignable_v<T> && std::is_nothrow_move_constructible_v<T>) -> inplace_vector& {
            if (this != &other) {
                clear();
                for (size_type i = 0; i < other.size_; ++i) unchecked_emplace_back(std::move(*other.slot(i)));
            }
            return *this;
        }
        constexpr ~inplace_vector() requires std::is_trivially_destructible_v<T> = default;
        constexpr ~inplace_vector() { clear(); }

        [[nodiscard]] static constexpr auto capacity() noexcept -> size_type { return N; }
        [[nodiscard]] static constexpr auto max_size() noexcept -> size_type { return N; }
        [[nodiscard]] constexpr auto size() const noexcept -> size_type { return size_; }
        [[nodiscard]] constexpr auto empty() const noexcept -> bool { return size_ == 0; }
        [[nodiscard]] constexpr auto data() noexcept -> pointer { return slot(0); }
        [[nodiscard]] constexpr auto data() const noexcept -> const_pointer { return slot(0); }
        [[nodiscard]] constexpr auto begin() noexcept -> iterator { return data(); }
        [[nodiscard]] constexpr auto end() noexcept -> iterator { return data() + size_; }
        [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator { return data(); }
        [[nodiscard]] constexpr auto end() const noexcept -> const_iterator { return data() + size_; }
        [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator { return begin(); }
        [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator { return end(); }
        [[nodiscard]] constexpr auto rbegin() noexcept -> reverse_iterator { return reverse_iterator(end()); }
        [[nodiscard]] constexpr auto rend() noexcept -> reverse_iterator { return reverse_iterator(begin()); }
        [[nodiscard]] constexpr auto rbegin() const noexcept -> const_reverse_iterator { return const_reverse_iterator(end()); }
        [[nodiscard]] constexpr auto rend() const noexcept -> const_reverse_iterator { return const_reverse_iterator(begin()); }

        [[nodiscard]] constexpr auto operator[](size_type i) noexcept -> reference { return *slot(i); }
        [[nodiscard]] constexpr auto operator[](size_type i) const noexcept -> const_reference { return *slot(i); }
        [[nodiscard]] constexpr auto at(size_type i) -> reference { if (i >= size_) fail_range(); return *slot(i); }
        [[nodiscard]] constexpr auto at(size_type i) const -> const_reference { if (i >= size_) fail_range(); return *slot(i); }
        [[nodiscard]] constexpr auto front() noexcept -> reference { return *slot(0); }
        [[nodiscard]] constexpr auto front() const noexcept -> const_reference { return *slot(0); }
        [[nodiscard]] constexpr auto back() noexcept -> reference { return *slot(size_ - 1); }
        [[nodiscard]] constexpr auto back() const noexcept -> const_reference { return *slot(size_ - 1); }

        constexpr auto clear() noexcept -> void {
            if constexpr (!std::is_trivially_destructible_v<T>) {
                while (size_ > 0) std::destroy_at(slot(--size_));
            } else {
                size_ = 0;
            }
        }
        constexpr auto reserve(size_type n) -> void { if (n > N) fail_overflow(); }
        template<class... Args>
        constexpr auto unchecked_emplace_back(Args&&... args) -> reference {
            T* out = std::construct_at(slot(size_), std::forward<Args>(args)...);
            ++size_;
            return *out;
        }
        constexpr auto unchecked_push_back(T const& v) -> reference { return unchecked_emplace_back(v); }
        constexpr auto unchecked_push_back(T&& v) -> reference { return unchecked_emplace_back(std::move(v)); }
        template<class... Args>
        constexpr auto try_emplace_back(Args&&... args) -> pointer {
            if (size_ >= N) return nullptr;
            return std::addressof(unchecked_emplace_back(std::forward<Args>(args)...));
        }
        constexpr auto try_push_back(T const& v) -> pointer { return try_emplace_back(v); }
        constexpr auto try_push_back(T&& v) -> pointer { return try_emplace_back(std::move(v)); }
        template<class... Args>
        constexpr auto emplace_back(Args&&... args) -> reference {
            if (size_ >= N) fail_overflow();
            return unchecked_emplace_back(std::forward<Args>(args)...);
        }
        constexpr auto push_back(T const& v) -> reference { return emplace_back(v); }
        constexpr auto push_back(T&& v) -> reference { return emplace_back(std::move(v)); }
        constexpr auto pop_back() noexcept -> void {
            --size_;
            if constexpr (!std::is_trivially_destructible_v<T>) std::destroy_at(slot(size_));
        }
        constexpr auto resize(size_type count) -> void {
            if (count > N) fail_overflow();
            while (size_ > count) pop_back();
            while (size_ < count) unchecked_emplace_back();
        }
        constexpr auto resize(size_type count, T const& value) -> void {
            if (count > N) fail_overflow();
            while (size_ > count) pop_back();
            while (size_ < count) unchecked_emplace_back(value);
        }
        constexpr auto assign(size_type count, T const& value) -> void {
            if (count > N) fail_overflow();
            clear();
            for (size_type i = 0; i < count; ++i) unchecked_emplace_back(value);
        }
        template<std::input_iterator It>
        constexpr auto assign(It first, It last) -> void {
            clear();
            for (; first != last; ++first) push_back(*first);
        }
        template<std::ranges::input_range R>
        constexpr auto append_range(R&& rg) -> void {
            for (auto&& elem : rg) push_back(std::forward<decltype(elem)>(elem));
        }
        template<std::ranges::input_range R>
        constexpr auto try_append_range(R&& rg) -> std::ranges::borrowed_iterator_t<R> {
            auto it = std::ranges::begin(rg);
            auto last = std::ranges::end(rg);
            for (; it != last && size_ < N; ++it) unchecked_emplace_back(*it);
            return it;
        }
        template<std::ranges::input_range R>
        constexpr auto assign_range(R&& rg) -> void {
            clear();
            append_range(std::forward<R>(rg));
        }
        constexpr auto erase(const_iterator pos) -> iterator { return erase(pos, pos + 1); }
        constexpr auto erase(const_iterator first, const_iterator last) -> iterator {
            auto idx = static_cast<size_type>(first - cbegin());
            auto count = static_cast<size_type>(last - first);
            if (count > 0) {
                for (size_type i = idx; i + count < size_; ++i) *slot(i) = std::move(*slot(i + count));
                while (count-- > 0) pop_back();
            }
            return begin() + idx;
        }
        friend constexpr auto operator==(inplace_vector const& a, inplace_vector const& b) -> bool
            requires std::equality_comparable<T> {
            return std::ranges::equal(a, b);
        }
        friend constexpr auto operator<=>(inplace_vector const& a, inplace_vector const& b)
            requires std::three_way_comparable<T> {
            return std::lexicographical_compare_three_way(a.begin(), a.end(), b.begin(), b.end());
        }
    };
    template<class T, std::size_t N, class Pred>
    constexpr auto erase_if(inplace_vector<T, N>& c, Pred pred) -> std::size_t {
        auto it = std::remove_if(c.begin(), c.end(), pred);
        auto removed = static_cast<std::size_t>(c.end() - it);
        c.erase(it, c.end());
        return removed;
    }
    template<class T, std::size_t N, class U = T>
    constexpr auto erase(inplace_vector<T, N>& c, U const& value) -> std::size_t {
        auto it = std::remove(c.begin(), c.end(), value);
        auto removed = static_cast<std::size_t>(c.end() - it);
        c.erase(it, c.end());
        return removed;
    }

#if defined(__cpp_lib_function_ref) && __cpp_lib_function_ref >= 202306L
    template<class... S>
    using function_ref = std::function_ref<S...>;
#else
    namespace detail {
        template<bool IsConst, bool Noexcept, class R, class... Args>
        class function_ref_impl {
            union Storage {
                void* mut_obj = nullptr;
                void const* const_obj;
                void (*fn)();
            } target_{};
            using Invoke = std::conditional_t<Noexcept, R(*)(Storage, Args...) noexcept, R(*)(Storage, Args...)>;
            Invoke invoke_ = nullptr;

            template<class F>
            static constexpr bool compatible =
                !std::same_as<std::remove_cvref_t<F>, function_ref_impl> &&
                (!IsConst || std::is_invocable_r_v<R, F const&, Args...>) &&
                (IsConst || std::is_invocable_r_v<R, std::remove_reference_t<F>&, Args...>) &&
                (!Noexcept || (IsConst ? std::is_nothrow_invocable_r_v<R, F const&, Args...>
                                       : std::is_nothrow_invocable_r_v<R, std::remove_reference_t<F>&, Args...>));

            template<class Obj>
            static auto call_obj(Storage s, Args... args) noexcept(Noexcept) -> R {
                auto* p = [&]() noexcept {
                    if constexpr (std::is_const_v<Obj>) return static_cast<Obj*>(s.const_obj);
                    else return static_cast<Obj*>(s.mut_obj);
                }();
                if constexpr (std::is_void_v<R>) (void)std::invoke(*p, std::forward<Args>(args)...);
                else return static_cast<R>(std::invoke(*p, std::forward<Args>(args)...));
            }
            template<class FnPtr>
            static auto call_fn(Storage s, Args... args) noexcept(Noexcept) -> R {
                auto fn = reinterpret_cast<FnPtr>(s.fn);
                if constexpr (std::is_void_v<R>) (void)fn(std::forward<Args>(args)...);
                else return static_cast<R>(fn(std::forward<Args>(args)...));
            }
        public:
            template<class Fn>
                requires std::is_function_v<Fn> &&
                    (Noexcept ? std::is_nothrow_invocable_r_v<R, Fn*, Args...> : std::is_invocable_r_v<R, Fn*, Args...>)
            function_ref_impl(Fn* fn) noexcept : invoke_(&call_fn<Fn*>) {
                target_.fn = reinterpret_cast<void(*)()>(fn);
            }
            template<class F>
                requires (!std::is_pointer_v<std::remove_cvref_t<F>> && compatible<F>)
            function_ref_impl(F&& f) noexcept {
                using Obj = std::conditional_t<IsConst, std::remove_reference_t<F> const, std::remove_reference_t<F>>;
                if constexpr (IsConst) target_.const_obj = std::addressof(f);
                else target_.mut_obj = const_cast<std::remove_const_t<Obj>*>(std::addressof(f));
                invoke_ = &call_obj<Obj>;
            }
            function_ref_impl(function_ref_impl const&) noexcept = default;
            auto operator=(function_ref_impl const&) noexcept -> function_ref_impl& = default;
            auto operator()(Args... args) const noexcept(Noexcept) -> R {
                return invoke_(target_, std::forward<Args>(args)...);
            }
        };
    }

    template<class Sig>
    class function_ref;

    template<class R, class... Args>
    class function_ref<R(Args...)> : public detail::function_ref_impl<false, false, R, Args...> {
        using Base = detail::function_ref_impl<false, false, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
    };
    template<class R, class... Args>
    class function_ref<R(Args...) noexcept> : public detail::function_ref_impl<false, true, R, Args...> {
        using Base = detail::function_ref_impl<false, true, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
    };
    template<class R, class... Args>
    class function_ref<R(Args...) const> : public detail::function_ref_impl<true, false, R, Args...> {
        using Base = detail::function_ref_impl<true, false, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
    };
    template<class R, class... Args>
    class function_ref<R(Args...) const noexcept> : public detail::function_ref_impl<true, true, R, Args...> {
        using Base = detail::function_ref_impl<true, true, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
    };
#endif

#if defined(__cpp_lib_atomic_shared_ptr) && __cpp_lib_atomic_shared_ptr >= 201711L
    template<class T>
    using atomic_shared_ptr = std::atomic<std::shared_ptr<T>>;
#else
    template<class T>
    class atomic_shared_ptr {
        mutable std::atomic_flag lock_{};
        std::shared_ptr<T> value_{};

        auto acquire() const noexcept -> void {
            while (lock_.test_and_set(std::memory_order_acquire)) {}
        }
        auto release() const noexcept -> void {
            lock_.clear(std::memory_order_release);
        }
        [[nodiscard]] static auto same_ptr(std::shared_ptr<T> const& a, std::shared_ptr<T> const& b) noexcept -> bool {
            return a.get() == b.get() && !a.owner_before(b) && !b.owner_before(a);
        }

    public:
        constexpr atomic_shared_ptr() noexcept = default;
        atomic_shared_ptr(std::shared_ptr<T> desired) noexcept : value_(std::move(desired)) {}
        atomic_shared_ptr(atomic_shared_ptr const&) = delete;
        auto operator=(atomic_shared_ptr const&) -> atomic_shared_ptr& = delete;

        [[nodiscard]] auto load(std::memory_order = std::memory_order_seq_cst) const noexcept -> std::shared_ptr<T> {
            acquire();
            auto copy = value_;
            release();
            return copy;
        }
        auto store(std::shared_ptr<T> desired, std::memory_order = std::memory_order_seq_cst) noexcept -> void {
            acquire();
            auto old = std::exchange(value_, std::move(desired));
            release();
        }
        [[nodiscard]] auto exchange(std::shared_ptr<T> desired,
                                    std::memory_order = std::memory_order_seq_cst) noexcept -> std::shared_ptr<T> {
            acquire();
            auto old = std::exchange(value_, std::move(desired));
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
