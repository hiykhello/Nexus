// Native UDP listener state and its per-configuration registry.
export module ss_udp.listener_state;
import std;
import crypto;
import platform.socket_options;
import rules;
import shadowsocks.key;
import shadowsocks.udp_dispatch;

export namespace shadowsocks::detail {
    // Retain this owner across listener replacements. All access is serialized;
    // the owner must outlive every listener and its asynchronous completions.
    class UdpListenerState {
        friend class UdpListenerRegistry;
        std::vector<std::uint8_t> key_;
        CipherMethod method_;
        UdpDispatcher dispatcher_;
        std::size_t session_limit_;
        bool attached_ = false;
        template<class Policy>
        UdpListenerState(std::span<std::uint8_t const> key, Policy policy,
                         std::size_t sessions = 64, std::size_t targets = 64, std::size_t pending = 64,
                         platform::SocketBinding const* binding = nullptr, UdpListenerReplay replay = {})
            : key_(key.begin(), key.end()),
              method_(replay.sessions ? replay.sessions->method() : CipherMethod::aes),
              dispatcher_(std::move(policy), sessions, targets, pending, 4 * 1024 * 1024, binding, std::move(replay)),
              session_limit_(sessions) {}
    public:
        ~UdpListenerState() { if (attached_) std::terminate(); crypto::cleanse(key_); }
        UdpListenerState(UdpListenerState const&) = delete;
        auto operator=(UdpListenerState const&) -> UdpListenerState& = delete;
        [[nodiscard]] auto dispatcher() noexcept -> UdpDispatcher& { return dispatcher_; }
        [[nodiscard]] auto key() const noexcept -> std::span<std::uint8_t const> { return key_; }
        [[nodiscard]] auto session_limit() const noexcept -> std::size_t { return session_limit_; }
        [[nodiscard]] auto attached() const noexcept -> bool { return attached_; }
        auto set_attached(bool value) noexcept -> void { attached_ = value; }
    };

    enum class UdpRegistryError { invalid_key, duplicate_key, full };

    // A service must use one registry for all UDP listeners. States cannot be
    // removed while the registry lives: replay protection survives replacement.
    // This does not coordinate separate registries or processes.
    class UdpListenerRegistry {
        std::vector<std::unique_ptr<UdpListenerState>> states_;
        std::size_t capacity_;
    public:
        explicit UdpListenerRegistry(std::size_t capacity) : capacity_(capacity) {}
        UdpListenerRegistry(UdpListenerRegistry const&) = delete;
        auto operator=(UdpListenerRegistry const&) -> UdpListenerRegistry& = delete;
        // All access is serialized. The returned pointer stays owned by this registry.
        [[nodiscard]] auto find(std::span<std::uint8_t const> key, CipherMethod method = CipherMethod::aes) const noexcept -> UdpListenerState* {
            for (auto const& state : states_)
                if (state->method_ == method && crypto::constant_time_equal(key, state->key_)) return state.get();
            return nullptr;
        }
        template<class Policy> requires (std::same_as<Policy, rules::Matcher> || std::same_as<Policy, rules::RouteProgram>)
        [[nodiscard]] auto reconfigure(UdpListenerState& state, Policy policy) noexcept -> bool {
            if (std::ranges::none_of(states_, [&](auto const& candidate) { return candidate.get() == &state; }) || state.attached_)
                return false;
            return state.dispatcher_.replace_policy(std::move(policy));
        }
        template<class Policy> requires (std::same_as<Policy, rules::Matcher> || std::same_as<Policy, rules::RouteProgram>)
        [[nodiscard]] auto add(std::span<std::uint8_t const> key, Policy policy,
                               std::size_t sessions = 64, std::size_t targets = 64, std::size_t pending = 64,
                               platform::SocketBinding const* binding = nullptr, UdpListenerReplay replay = {})
            -> std::expected<UdpListenerState*, UdpRegistryError> {
            auto method = replay.sessions ? replay.sessions->method() : CipherMethod::aes;
            if (key.size() != 32 && (key.size() != 16 || method != CipherMethod::aes))
                return std::unexpected(UdpRegistryError::invalid_key);
            if (find(key, method)) return std::unexpected(UdpRegistryError::duplicate_key);
            if (states_.size() >= capacity_) return std::unexpected(UdpRegistryError::full);
            auto state = std::unique_ptr<UdpListenerState>(
                new UdpListenerState(key, std::move(policy), sessions, targets, pending, binding, std::move(replay)));
            auto result = state.get();
            states_.push_back(std::move(state));
            return result;
        }
    };
}
