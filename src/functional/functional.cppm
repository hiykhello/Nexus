export module functional;
import std;
import proxy.v4;

export namespace functional {
    namespace detail {
        inline constexpr std::size_t callable_sbo_bytes = 4 * sizeof(void*);

        template<class T>
        [[nodiscard]] auto is_null_target(T const& value) noexcept -> bool {
            using U = std::decay_t<T>;
            if constexpr (std::is_pointer_v<U> || std::is_member_pointer_v<U>) {
                return value == nullptr;
            } else if constexpr (requires { typename U::functional_callable_tag; }) {
                return !static_cast<bool>(value);
            } else {
                return false;
            }
        }

        template<bool IsConst, bool Noexcept, class R, class... Args>
        struct call_overload;
        template<class R, class... Args>
        struct call_overload<false, false, R, Args...> : std::type_identity<R(Args...)> {};
        template<class R, class... Args>
        struct call_overload<false, true, R, Args...> : std::type_identity<R(Args...) noexcept> {};
        template<class R, class... Args>
        struct call_overload<true, false, R, Args...> : std::type_identity<R(Args...) const> {};
        template<class R, class... Args>
        struct call_overload<true, true, R, Args...> : std::type_identity<R(Args...) const noexcept> {};

        template<bool IsConst, bool Noexcept, class R, class... Args>
        using call_overload_t = typename call_overload<IsConst, Noexcept, R, Args...>::type;

        template<bool Noexcept, class R, class... Args>
        struct view_callable_facade : pro::facade_builder
            ::template add_convention<pro::operator_dispatch<"()">, call_overload_t<true, Noexcept, R, Args...>>
            ::template add_skill<pro::skills::slim>
            ::template support_copy<pro::constraint_level::trivial>
            ::template support_relocation<pro::constraint_level::trivial>
            ::template support_destruction<pro::constraint_level::trivial>
            ::build {};

        template<bool Copyable, bool IsConst, bool Noexcept, class R, class... Args>
        struct owning_callable_facade : pro::facade_builder
            ::template add_convention<pro::operator_dispatch<"()">, call_overload_t<IsConst, Noexcept, R, Args...>>
            ::template restrict_layout<callable_sbo_bytes, alignof(std::max_align_t)>
            ::template support_copy<Copyable ? pro::constraint_level::nontrivial : pro::constraint_level::none>
            ::template support_relocation<pro::constraint_level::nothrow>
            ::build {};

        template<class Base, bool IsConst, bool Noexcept, class R, class F, class... Args>
        concept view_callable_target =
            (!std::is_base_of_v<Base, std::remove_cvref_t<F>>) &&
            (!std::is_pointer_v<std::remove_cvref_t<F>>) &&
            (!std::is_function_v<std::remove_reference_t<F>>) &&
            (!std::is_member_pointer_v<std::remove_cvref_t<F>>) &&
            (IsConst ? (Noexcept ? std::is_nothrow_invocable_r_v<R, F const&, Args...>
                                 : std::is_invocable_r_v<R, F const&, Args...>)
                     : (Noexcept ? std::is_nothrow_invocable_r_v<R, std::remove_reference_t<F>&, Args...>
                                 : std::is_invocable_r_v<R, std::remove_reference_t<F>&, Args...>));

        template<class Base, bool Copyable, bool IsConst, bool Noexcept, class R, class F, class... Args>
        concept owning_callable_target =
            (!std::is_base_of_v<Base, std::decay_t<F>>) &&
            (!std::is_member_pointer_v<std::decay_t<F>>) &&
            (IsConst ? (Noexcept ? std::is_nothrow_invocable_r_v<R, std::decay_t<F> const&, Args...>
                                 : std::is_invocable_r_v<R, std::decay_t<F> const&, Args...>)
                     : (Noexcept ? std::is_nothrow_invocable_r_v<R, std::decay_t<F>&, Args...>
                                 : std::is_invocable_r_v<R, std::decay_t<F>&, Args...>)) &&
            std::constructible_from<std::decay_t<F>, F> &&
            (!Copyable || std::copy_constructible<std::decay_t<F>>);
    }

#if defined(__cpp_lib_function_ref) && __cpp_lib_function_ref >= 202306L
    template<class... S>
    using function_ref = std::function_ref<S...>;
#else
    namespace detail {
        template<bool IsConst, bool Noexcept, class R, class... Args>
        class function_ref_impl {
            using Facade = view_callable_facade<Noexcept, R, Args...>;
            pro::proxy<Facade> proxy_;

            template<class Obj>
            static auto make_target_ptr(Obj& obj) noexcept {
                if constexpr (IsConst) {
                    return static_cast<Obj const*>(std::addressof(obj));
                } else {
                    return std::addressof(obj);
                }
            }

        public:
            template<class Fn>
                requires std::is_function_v<Fn> &&
                    (Noexcept ? std::is_nothrow_invocable_r_v<R, Fn*, Args...> : std::is_invocable_r_v<R, Fn*, Args...>)
            function_ref_impl(Fn* fn) noexcept : proxy_(pro::make_proxy_inplace<Facade>(fn)) {}

            template<class F>
                requires view_callable_target<function_ref_impl, IsConst, Noexcept, R, F, Args...>
            function_ref_impl(F&& f) noexcept
                : proxy_(make_target_ptr(f)) {}

            function_ref_impl(function_ref_impl const&) noexcept = default;
            auto operator=(function_ref_impl const&) noexcept -> function_ref_impl& = default;

            auto operator()(Args... args) const noexcept(Noexcept) -> R {
                return (*proxy_)(std::forward<Args>(args)...);
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

    namespace detail {
        template<bool Copyable, bool IsConst, bool Noexcept, class R, class... Args>
        class owning_fn_impl {
            using Facade = owning_callable_facade<Copyable, IsConst, Noexcept, R, Args...>;
            pro::proxy<Facade> proxy_;

        public:
            using functional_callable_tag = void;

            owning_fn_impl() noexcept = default;
            owning_fn_impl(std::nullptr_t) noexcept {}
            owning_fn_impl(owning_fn_impl const&) requires Copyable = default;
            owning_fn_impl(owning_fn_impl&&) noexcept = default;
            auto operator=(owning_fn_impl const&) -> owning_fn_impl& requires Copyable = default;
            auto operator=(owning_fn_impl&&) noexcept -> owning_fn_impl& = default;

            auto operator=(std::nullptr_t) noexcept -> owning_fn_impl& {
                proxy_.reset();
                return *this;
            }

            template<class F>
                requires owning_callable_target<owning_fn_impl, Copyable, IsConst, Noexcept, R, F, Args...>
            owning_fn_impl(F&& fn) {
                if (is_null_target(fn)) return;
                proxy_ = pro::make_proxy<Facade, std::decay_t<F>>(std::forward<F>(fn));
            }

            auto reset() noexcept -> void { proxy_.reset(); }
            [[nodiscard]] explicit operator bool() const noexcept { return proxy_.has_value(); }
            friend auto operator==(owning_fn_impl const& f, std::nullptr_t) noexcept -> bool {
                return !f.proxy_.has_value();
            }

            auto operator()(Args... args) noexcept(Noexcept) -> R requires (!IsConst) {
                return (*proxy_)(std::forward<Args>(args)...);
            }
            auto operator()(Args... args) const noexcept(Noexcept) -> R requires IsConst {
                return (*proxy_)(std::forward<Args>(args)...);
            }
        };
    }

#if defined(__cpp_lib_move_only_function) && __cpp_lib_move_only_function >= 202110L
    template<class... S>
    using move_only_function = std::move_only_function<S...>;
#else
    template<class Sig>
    class move_only_function;

    template<class R, class... Args>
    class move_only_function<R(Args...)> : public detail::owning_fn_impl<false, false, false, R, Args...> {
        using Base = detail::owning_fn_impl<false, false, false, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
        move_only_function(move_only_function&&) noexcept = default;
        auto operator=(move_only_function&&) noexcept -> move_only_function& = default;
        auto operator=(std::nullptr_t) noexcept -> move_only_function& { this->reset(); return *this; }
        template<class F> requires detail::owning_callable_target<Base, false, false, false, R, F, Args...>
        auto operator=(F&& fn) -> move_only_function& { move_only_function t(std::forward<F>(fn)); *this = std::move(t); return *this; }
    };
    template<class R, class... Args>
    class move_only_function<R(Args...) noexcept> : public detail::owning_fn_impl<false, false, true, R, Args...> {
        using Base = detail::owning_fn_impl<false, false, true, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
        move_only_function(move_only_function&&) noexcept = default;
        auto operator=(move_only_function&&) noexcept -> move_only_function& = default;
        auto operator=(std::nullptr_t) noexcept -> move_only_function& { this->reset(); return *this; }
        template<class F> requires detail::owning_callable_target<Base, false, false, true, R, F, Args...>
        auto operator=(F&& fn) -> move_only_function& { move_only_function t(std::forward<F>(fn)); *this = std::move(t); return *this; }
    };
    template<class R, class... Args>
    class move_only_function<R(Args...) const> : public detail::owning_fn_impl<false, true, false, R, Args...> {
        using Base = detail::owning_fn_impl<false, true, false, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
        move_only_function(move_only_function&&) noexcept = default;
        auto operator=(move_only_function&&) noexcept -> move_only_function& = default;
        auto operator=(std::nullptr_t) noexcept -> move_only_function& { this->reset(); return *this; }
        template<class F> requires detail::owning_callable_target<Base, false, true, false, R, F, Args...>
        auto operator=(F&& fn) -> move_only_function& { move_only_function t(std::forward<F>(fn)); *this = std::move(t); return *this; }
    };
    template<class R, class... Args>
    class move_only_function<R(Args...) const noexcept> : public detail::owning_fn_impl<false, true, true, R, Args...> {
        using Base = detail::owning_fn_impl<false, true, true, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
        move_only_function(move_only_function&&) noexcept = default;
        auto operator=(move_only_function&&) noexcept -> move_only_function& = default;
        auto operator=(std::nullptr_t) noexcept -> move_only_function& { this->reset(); return *this; }
        template<class F> requires detail::owning_callable_target<Base, false, true, true, R, F, Args...>
        auto operator=(F&& fn) -> move_only_function& { move_only_function t(std::forward<F>(fn)); *this = std::move(t); return *this; }
    };
#endif

#if defined(__cpp_lib_copyable_function) && __cpp_lib_copyable_function >= 202306L
    template<class... S>
    using copyable_function = std::copyable_function<S...>;
#else
    template<class Sig>
    class copyable_function;

    template<class R, class... Args>
    class copyable_function<R(Args...)> : public detail::owning_fn_impl<true, false, false, R, Args...> {
        using Base = detail::owning_fn_impl<true, false, false, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
        copyable_function(copyable_function const&) = default;
        copyable_function(copyable_function&&) noexcept = default;
        auto operator=(copyable_function const&) -> copyable_function& = default;
        auto operator=(copyable_function&&) noexcept -> copyable_function& = default;
        auto operator=(std::nullptr_t) noexcept -> copyable_function& { this->reset(); return *this; }
        template<class F> requires detail::owning_callable_target<Base, true, false, false, R, F, Args...>
        auto operator=(F&& fn) -> copyable_function& { copyable_function t(std::forward<F>(fn)); *this = std::move(t); return *this; }
    };
    template<class R, class... Args>
    class copyable_function<R(Args...) noexcept> : public detail::owning_fn_impl<true, false, true, R, Args...> {
        using Base = detail::owning_fn_impl<true, false, true, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
        copyable_function(copyable_function const&) = default;
        copyable_function(copyable_function&&) noexcept = default;
        auto operator=(copyable_function const&) -> copyable_function& = default;
        auto operator=(copyable_function&&) noexcept -> copyable_function& = default;
        auto operator=(std::nullptr_t) noexcept -> copyable_function& { this->reset(); return *this; }
        template<class F> requires detail::owning_callable_target<Base, true, false, true, R, F, Args...>
        auto operator=(F&& fn) -> copyable_function& { copyable_function t(std::forward<F>(fn)); *this = std::move(t); return *this; }
    };
    template<class R, class... Args>
    class copyable_function<R(Args...) const> : public detail::owning_fn_impl<true, true, false, R, Args...> {
        using Base = detail::owning_fn_impl<true, true, false, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
        copyable_function(copyable_function const&) = default;
        copyable_function(copyable_function&&) noexcept = default;
        auto operator=(copyable_function const&) -> copyable_function& = default;
        auto operator=(copyable_function&&) noexcept -> copyable_function& = default;
        auto operator=(std::nullptr_t) noexcept -> copyable_function& { this->reset(); return *this; }
        template<class F> requires detail::owning_callable_target<Base, true, true, false, R, F, Args...>
        auto operator=(F&& fn) -> copyable_function& { copyable_function t(std::forward<F>(fn)); *this = std::move(t); return *this; }
    };
    template<class R, class... Args>
    class copyable_function<R(Args...) const noexcept> : public detail::owning_fn_impl<true, true, true, R, Args...> {
        using Base = detail::owning_fn_impl<true, true, true, R, Args...>;
    public:
        using Base::Base;
        using Base::operator();
        copyable_function(copyable_function const&) = default;
        copyable_function(copyable_function&&) noexcept = default;
        auto operator=(copyable_function const&) -> copyable_function& = default;
        auto operator=(copyable_function&&) noexcept -> copyable_function& = default;
        auto operator=(std::nullptr_t) noexcept -> copyable_function& { this->reset(); return *this; }
        template<class F> requires detail::owning_callable_target<Base, true, true, true, R, F, Args...>
        auto operator=(F&& fn) -> copyable_function& { copyable_function t(std::forward<F>(fn)); *this = std::move(t); return *this; }
    };
#endif
}
