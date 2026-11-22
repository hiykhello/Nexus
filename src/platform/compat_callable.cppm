export module nexus.compat.callable;
import std;

export namespace nexus {
#if defined(__cpp_lib_move_only_function) && __cpp_lib_move_only_function >= 202110L
    template<class... S>
    using move_only_function = std::move_only_function<S...>;
#else
    template<class Sig>
    class move_only_function;

    namespace detail {
        inline constexpr std::size_t callable_sbo_bytes = 4 * sizeof(void*);

        template<class T>
        [[nodiscard]] auto is_null_target(T const& value) noexcept -> bool {
            using U = std::decay_t<T>;
            if constexpr (std::is_pointer_v<U> || std::is_member_pointer_v<U>) {
                return value == nullptr;
            } else if constexpr (requires { typename U::nexus_callable_tag; }) {
                return !static_cast<bool>(value);
            } else {
                return false;
            }
        }

        template<bool IsConst, bool Noexcept, class R, class... Args>
        class move_only_fn_impl {
        public:
            using nexus_callable_tag = void;
        protected:
            struct Storage {
                union {
                    alignas(std::max_align_t) std::byte inline_buf[callable_sbo_bytes];
                    void* heap;
                };
                bool is_inline = false;
            };

            struct Ops {
                R (*invoke)(Storage const&, Args...) noexcept(Noexcept);
                void (*move_to)(Storage& dst, Storage& src) noexcept;
                void (*destroy)(Storage&) noexcept;
            };

            template<class F>
            static constexpr bool is_inline_target =
                sizeof(F) <= callable_sbo_bytes &&
                alignof(F) <= alignof(std::max_align_t) &&
                std::is_nothrow_move_constructible_v<F>;

            template<class F>
            static auto target_ptr(Storage const& s) noexcept -> F* {
                if constexpr (is_inline_target<F>) {
                    return std::launder(reinterpret_cast<F*>(const_cast<std::byte*>(s.inline_buf)));
                } else {
                    return static_cast<F*>(s.heap);
                }
            }

            template<class F>
            static auto do_invoke(Storage const& s, Args... args) noexcept(Noexcept) -> R {
                using InvType = std::conditional_t<IsConst, F const&, F&>;
                auto& obj = *target_ptr<F>(s);
                if constexpr (std::is_void_v<R>) {
                    (void)std::invoke(static_cast<InvType>(obj), std::forward<Args>(args)...);
                } else {
                    return static_cast<R>(std::invoke(static_cast<InvType>(obj), std::forward<Args>(args)...));
                }
            }

            template<class F>
            static auto do_move(Storage& dst, Storage& src) noexcept -> void {
                if constexpr (is_inline_target<F>) {
                    auto* p = target_ptr<F>(src);
                    std::construct_at(reinterpret_cast<F*>(dst.inline_buf), std::move(*p));
                    std::destroy_at(p);
                    dst.is_inline = true;
                } else {
                    dst.heap = std::exchange(src.heap, nullptr);
                    dst.is_inline = false;
                }
            }

            template<class F>
            static auto do_destroy(Storage& s) noexcept -> void {
                auto* p = target_ptr<F>(s);
                if constexpr (is_inline_target<F>) {
                    std::destroy_at(p);
                } else {
                    delete p;
                    s.heap = nullptr;
                }
            }

            template<class F>
            static constexpr Ops ops_for{&do_invoke<F>, &do_move<F>, &do_destroy<F>};

            template<class F>
            static constexpr bool invocable_v =
                !std::same_as<std::remove_cvref_t<F>, move_only_fn_impl> &&
                (IsConst ? (Noexcept ? std::is_nothrow_invocable_r_v<R, F const&, Args...>
                                     : std::is_invocable_r_v<R, F const&, Args...>)
                         : (Noexcept ? std::is_nothrow_invocable_r_v<R, F&, Args...>
                                     : std::is_invocable_r_v<R, F&, Args...>));

            template<class F, class T = std::decay_t<F>>
            static constexpr bool valid_callable_v =
                !std::is_base_of_v<move_only_fn_impl, T> && invocable_v<T> && std::constructible_from<T, F>;

            Storage storage_{};
            Ops const* ops_ = nullptr;

        public:
            constexpr move_only_fn_impl() noexcept = default;
            constexpr move_only_fn_impl(std::nullptr_t) noexcept {}
            move_only_fn_impl(move_only_fn_impl const&) = delete;
            auto operator=(move_only_fn_impl const&) -> move_only_fn_impl& = delete;

            move_only_fn_impl(move_only_fn_impl&& other) noexcept : ops_(std::exchange(other.ops_, nullptr)) {
                if (ops_) ops_->move_to(storage_, other.storage_);
            }

            auto operator=(move_only_fn_impl&& other) noexcept -> move_only_fn_impl& {
                if (this != &other) {
                    reset();
                    ops_ = std::exchange(other.ops_, nullptr);
                    if (ops_) ops_->move_to(storage_, other.storage_);
                }
                return *this;
            }

            auto operator=(std::nullptr_t) noexcept -> move_only_fn_impl& {
                reset();
                return *this;
            }

            template<class F, class T = std::decay_t<F>>
                requires (!std::is_base_of_v<move_only_fn_impl, T>) && invocable_v<T> && std::constructible_from<T, F>
            move_only_fn_impl(F&& fn) {
                if (is_null_target(fn)) return;
                if constexpr (is_inline_target<T>) {
                    std::construct_at(reinterpret_cast<T*>(storage_.inline_buf), std::forward<F>(fn));
                    storage_.is_inline = true;
                } else {
                    storage_.heap = new T(std::forward<F>(fn));
                    storage_.is_inline = false;
                }
                ops_ = &ops_for<T>;
            }

            ~move_only_fn_impl() { reset(); }

            auto reset() noexcept -> void {
                if (ops_) {
                    auto* old = std::exchange(ops_, nullptr);
                    old->destroy(storage_);
                }
            }

            [[nodiscard]] explicit operator bool() const noexcept { return ops_ != nullptr; }
            friend auto operator==(move_only_fn_impl const& f, std::nullptr_t) noexcept -> bool { return !f.ops_; }

            auto operator()(Args... args) noexcept(Noexcept) -> R requires (!IsConst) {
                return ops_->invoke(storage_, std::forward<Args>(args)...);
            }
            auto operator()(Args... args) const noexcept(Noexcept) -> R requires IsConst {
                return ops_->invoke(storage_, std::forward<Args>(args)...);
            }
        };
    }

    template<class R, class... Args>
    class move_only_function<R(Args...)> : public detail::move_only_fn_impl<false, false, R, Args...> {
        using Base = detail::move_only_fn_impl<false, false, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
        move_only_function(move_only_function&&) noexcept = default;
        auto operator=(move_only_function&&) noexcept -> move_only_function& = default;
        auto operator=(std::nullptr_t) noexcept -> move_only_function& { this->reset(); return *this; }
        template<class F> requires Base::template valid_callable_v<F>
        auto operator=(F&& fn) -> move_only_function& { move_only_function t(std::forward<F>(fn)); *this = std::move(t); return *this; }
    };
    template<class R, class... Args>
    class move_only_function<R(Args...) noexcept> : public detail::move_only_fn_impl<false, true, R, Args...> {
        using Base = detail::move_only_fn_impl<false, true, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
        move_only_function(move_only_function&&) noexcept = default;
        auto operator=(move_only_function&&) noexcept -> move_only_function& = default;
        auto operator=(std::nullptr_t) noexcept -> move_only_function& { this->reset(); return *this; }
        template<class F> requires Base::template valid_callable_v<F>
        auto operator=(F&& fn) -> move_only_function& { move_only_function t(std::forward<F>(fn)); *this = std::move(t); return *this; }
    };
    template<class R, class... Args>
    class move_only_function<R(Args...) const> : public detail::move_only_fn_impl<true, false, R, Args...> {
        using Base = detail::move_only_fn_impl<true, false, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
        move_only_function(move_only_function&&) noexcept = default;
        auto operator=(move_only_function&&) noexcept -> move_only_function& = default;
        auto operator=(std::nullptr_t) noexcept -> move_only_function& { this->reset(); return *this; }
        template<class F> requires Base::template valid_callable_v<F>
        auto operator=(F&& fn) -> move_only_function& { move_only_function t(std::forward<F>(fn)); *this = std::move(t); return *this; }
    };
    template<class R, class... Args>
    class move_only_function<R(Args...) const noexcept> : public detail::move_only_fn_impl<true, true, R, Args...> {
        using Base = detail::move_only_fn_impl<true, true, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
        move_only_function(move_only_function&&) noexcept = default;
        auto operator=(move_only_function&&) noexcept -> move_only_function& = default;
        auto operator=(std::nullptr_t) noexcept -> move_only_function& { this->reset(); return *this; }
        template<class F> requires Base::template valid_callable_v<F>
        auto operator=(F&& fn) -> move_only_function& { move_only_function t(std::forward<F>(fn)); *this = std::move(t); return *this; }
    };
#endif

#if defined(__cpp_lib_copyable_function) && __cpp_lib_copyable_function >= 202306L
    template<class... S>
    using copyable_function = std::copyable_function<S...>;
#else
    template<class Sig>
    class copyable_function;

    namespace detail {
        template<bool IsConst, bool Noexcept, class R, class... Args>
        class copyable_fn_impl {
        public:
            using nexus_callable_tag = void;
        protected:
            struct Storage {
                union {
                    alignas(std::max_align_t) std::byte inline_buf[callable_sbo_bytes];
                    void* heap;
                };
                bool is_inline = false;
            };

            struct Ops {
                R (*invoke)(Storage const&, Args...) noexcept(Noexcept);
                void (*copy_to)(Storage& dst, Storage const& src);
                void (*move_to)(Storage& dst, Storage& src) noexcept;
                void (*destroy)(Storage&) noexcept;
            };

            template<class F>
            static constexpr bool is_inline_target =
                sizeof(F) <= callable_sbo_bytes &&
                alignof(F) <= alignof(std::max_align_t) &&
                std::is_nothrow_move_constructible_v<F>;

            template<class F>
            static auto target_ptr(Storage const& s) noexcept -> F* {
                if constexpr (is_inline_target<F>) {
                    return std::launder(reinterpret_cast<F*>(const_cast<std::byte*>(s.inline_buf)));
                } else {
                    return static_cast<F*>(s.heap);
                }
            }

            template<class F>
            static auto do_invoke(Storage const& s, Args... args) noexcept(Noexcept) -> R {
                using InvType = std::conditional_t<IsConst, F const&, F&>;
                auto& obj = *target_ptr<F>(s);
                if constexpr (std::is_void_v<R>) {
                    (void)std::invoke(static_cast<InvType>(obj), std::forward<Args>(args)...);
                } else {
                    return static_cast<R>(std::invoke(static_cast<InvType>(obj), std::forward<Args>(args)...));
                }
            }

            template<class F>
            static auto do_copy(Storage& dst, Storage const& src) -> void {
                auto const& obj = *target_ptr<F>(src);
                if constexpr (is_inline_target<F>) {
                    std::construct_at(reinterpret_cast<F*>(dst.inline_buf), obj);
                    dst.is_inline = true;
                } else {
                    dst.heap = new F(obj);
                    dst.is_inline = false;
                }
            }

            template<class F>
            static auto do_move(Storage& dst, Storage& src) noexcept -> void {
                if constexpr (is_inline_target<F>) {
                    auto* p = target_ptr<F>(src);
                    std::construct_at(reinterpret_cast<F*>(dst.inline_buf), std::move(*p));
                    std::destroy_at(p);
                    dst.is_inline = true;
                } else {
                    dst.heap = std::exchange(src.heap, nullptr);
                    dst.is_inline = false;
                }
            }

            template<class F>
            static auto do_destroy(Storage& s) noexcept -> void {
                auto* p = target_ptr<F>(s);
                if constexpr (is_inline_target<F>) {
                    std::destroy_at(p);
                } else {
                    delete p;
                    s.heap = nullptr;
                }
            }

            template<class F>
            static constexpr Ops ops_for{&do_invoke<F>, &do_copy<F>, &do_move<F>, &do_destroy<F>};

            template<class F>
            static constexpr bool invocable_v =
                !std::same_as<std::remove_cvref_t<F>, copyable_fn_impl> &&
                (IsConst ? (Noexcept ? std::is_nothrow_invocable_r_v<R, F const&, Args...>
                                     : std::is_invocable_r_v<R, F const&, Args...>)
                         : (Noexcept ? std::is_nothrow_invocable_r_v<R, F&, Args...>
                                     : std::is_invocable_r_v<R, F&, Args...>));

            template<class F, class T = std::decay_t<F>>
            static constexpr bool valid_callable_v =
                !std::is_base_of_v<copyable_fn_impl, T> && invocable_v<T> && std::copy_constructible<T>;

            Storage storage_{};
            Ops const* ops_ = nullptr;

        public:
            constexpr copyable_fn_impl() noexcept = default;
            constexpr copyable_fn_impl(std::nullptr_t) noexcept {}

            copyable_fn_impl(copyable_fn_impl const& other) {
                if (other.ops_) {
                    other.ops_->copy_to(storage_, other.storage_);
                    ops_ = other.ops_;
                }
            }
            copyable_fn_impl(copyable_fn_impl&& other) noexcept : ops_(std::exchange(other.ops_, nullptr)) {
                if (ops_) ops_->move_to(storage_, other.storage_);
            }
            auto operator=(copyable_fn_impl const& other) -> copyable_fn_impl& {
                if (this != &other) {
                    copyable_fn_impl tmp(other);
                    *this = std::move(tmp);
                }
                return *this;
            }
            auto operator=(copyable_fn_impl&& other) noexcept -> copyable_fn_impl& {
                if (this != &other) {
                    reset();
                    ops_ = std::exchange(other.ops_, nullptr);
                    if (ops_) ops_->move_to(storage_, other.storage_);
                }
                return *this;
            }
            auto operator=(std::nullptr_t) noexcept -> copyable_fn_impl& {
                reset();
                return *this;
            }

            template<class F, class T = std::decay_t<F>>
                requires (!std::is_base_of_v<copyable_fn_impl, T>) && invocable_v<T> && std::copy_constructible<T>
            copyable_fn_impl(F&& fn) {
                if (is_null_target(fn)) return;
                if constexpr (is_inline_target<T>) {
                    std::construct_at(reinterpret_cast<T*>(storage_.inline_buf), std::forward<F>(fn));
                    storage_.is_inline = true;
                } else {
                    storage_.heap = new T(std::forward<F>(fn));
                    storage_.is_inline = false;
                }
                ops_ = &ops_for<T>;
            }

            ~copyable_fn_impl() { reset(); }

            auto reset() noexcept -> void {
                if (ops_) {
                    auto* old = std::exchange(ops_, nullptr);
                    old->destroy(storage_);
                }
            }

            [[nodiscard]] explicit operator bool() const noexcept { return ops_ != nullptr; }
            friend auto operator==(copyable_fn_impl const& f, std::nullptr_t) noexcept -> bool { return !f.ops_; }

            auto operator()(Args... args) noexcept(Noexcept) -> R requires (!IsConst) {
                return ops_->invoke(storage_, std::forward<Args>(args)...);
            }
            auto operator()(Args... args) const noexcept(Noexcept) -> R requires IsConst {
                return ops_->invoke(storage_, std::forward<Args>(args)...);
            }
        };
    }

    template<class R, class... Args>
    class copyable_function<R(Args...)> : public detail::copyable_fn_impl<false, false, R, Args...> {
        using Base = detail::copyable_fn_impl<false, false, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
        copyable_function(copyable_function const&) = default;
        copyable_function(copyable_function&&) noexcept = default;
        auto operator=(copyable_function const&) -> copyable_function& = default;
        auto operator=(copyable_function&&) noexcept -> copyable_function& = default;
        auto operator=(std::nullptr_t) noexcept -> copyable_function& { this->reset(); return *this; }
        template<class F> requires Base::template valid_callable_v<F>
        auto operator=(F&& fn) -> copyable_function& { copyable_function t(std::forward<F>(fn)); *this = std::move(t); return *this; }
    };
    template<class R, class... Args>
    class copyable_function<R(Args...) noexcept> : public detail::copyable_fn_impl<false, true, R, Args...> {
        using Base = detail::copyable_fn_impl<false, true, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
        copyable_function(copyable_function const&) = default;
        copyable_function(copyable_function&&) noexcept = default;
        auto operator=(copyable_function const&) -> copyable_function& = default;
        auto operator=(copyable_function&&) noexcept -> copyable_function& = default;
        auto operator=(std::nullptr_t) noexcept -> copyable_function& { this->reset(); return *this; }
        template<class F> requires Base::template valid_callable_v<F>
        auto operator=(F&& fn) -> copyable_function& { copyable_function t(std::forward<F>(fn)); *this = std::move(t); return *this; }
    };
    template<class R, class... Args>
    class copyable_function<R(Args...) const> : public detail::copyable_fn_impl<true, false, R, Args...> {
        using Base = detail::copyable_fn_impl<true, false, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
        copyable_function(copyable_function const&) = default;
        copyable_function(copyable_function&&) noexcept = default;
        auto operator=(copyable_function const&) -> copyable_function& = default;
        auto operator=(copyable_function&&) noexcept -> copyable_function& = default;
        auto operator=(std::nullptr_t) noexcept -> copyable_function& { this->reset(); return *this; }
        template<class F> requires Base::template valid_callable_v<F>
        auto operator=(F&& fn) -> copyable_function& { copyable_function t(std::forward<F>(fn)); *this = std::move(t); return *this; }
    };
    template<class R, class... Args>
    class copyable_function<R(Args...) const noexcept> : public detail::copyable_fn_impl<true, true, R, Args...> {
        using Base = detail::copyable_fn_impl<true, true, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
        copyable_function(copyable_function const&) = default;
        copyable_function(copyable_function&&) noexcept = default;
        auto operator=(copyable_function const&) -> copyable_function& = default;
        auto operator=(copyable_function&&) noexcept -> copyable_function& = default;
        auto operator=(std::nullptr_t) noexcept -> copyable_function& { this->reset(); return *this; }
        template<class F> requires Base::template valid_callable_v<F>
        auto operator=(F&& fn) -> copyable_function& { copyable_function t(std::forward<F>(fn)); *this = std::move(t); return *this; }
    };
#endif
}
