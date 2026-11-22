export module tls.resumption_policy;
import std;

export namespace tls {
    // The ordinary owner stores no recovery material. Algorithms select this
    // policy at compile time; it adds neither a field nor a runtime branch.
    struct NoPsk { static constexpr bool enabled=false; };
    static_assert(sizeof(NoPsk)==1 && std::is_empty_v<NoPsk> && std::is_trivial_v<NoPsk>);
    template<class... Policies> struct RecoveryMode;
    template<> struct RecoveryMode<> {using type=NoPsk;};
    template<class Policy> struct RecoveryMode<Policy> {using type=Policy;};
    template<class... Policies> using RecoveryPolicy=typename RecoveryMode<Policies...>::type;
    template<class Policy>
    concept EarlyDataPolicy=requires { requires Policy::early_data; };

    template<class Policy>
    [[gnu::always_inline]] inline auto recovery_policy(Policy& policy) noexcept -> Policy& {return policy;}
    struct PskSteadyClock {
        static auto now() noexcept -> std::uint64_t {
            return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
        }
    };
}
