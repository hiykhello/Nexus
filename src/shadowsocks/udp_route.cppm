export module nexus.shadowsocks.udp_route;
import std;
import nexus.rules;
export import nexus.shadowsocks.udp_server;
export namespace nexus::shadowsocks {
    enum class UdpRouteError { invalid_target, blocked, unsupported, policy_error };
    using UdpRoutedFailure=std::variant<UdpRouteError,UdpServerFailure>;
    // Policy snapshot. Ordered routes use outbound 0 for direct and 1 for
    // block; unsupported outbounds fail closed. The caller must preflight
    // domains and resolve through configured DNS rather than trusting input.
    class UdpRoutedServer {
        std::variant<rules::Matcher,rules::RouteMatcher> policy_;
        static_assert(std::is_nothrow_move_assignable_v<decltype(policy_)>);
        UdpServer server_;
    public:
        UdpRoutedServer(rules::Matcher policy,std::size_t sessions,std::size_t targets)
            : policy_(std::move(policy)),server_(sessions,targets) {}
        UdpRoutedServer(rules::RouteMatcher policy,std::size_t sessions,std::size_t targets)
            : policy_(std::move(policy)),server_(sessions,targets) {}
        // Caller must serialize changes and cancel all in-flight work first.
        template<class Policy> requires (std::same_as<Policy,rules::Matcher> || std::same_as<Policy,rules::RouteMatcher>)
        auto replace_policy(Policy policy) noexcept -> void { policy_=std::move(policy); }
        [[nodiscard]] auto receive(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> wire,UdpPeer peer,
            std::chrono::steady_clock::time_point now,std::uint64_t wall) -> std::expected<UdpAccepted,UdpSessionError> {
            return server_.receive(psk,wire,peer,now,wall);
        }
        [[nodiscard]] auto preflight(UdpAccepted const& packet) const -> std::expected<void,UdpRouteError>;
        // Numeric addresses must match the request; for domains, the caller
        // supplies an actual resolved candidate with the requested port.
        [[nodiscard]] auto forward(UdpAccepted const& packet,UdpPeer resolved) -> std::expected<void,UdpRoutedFailure>;
        [[nodiscard]] auto poll(std::span<std::uint8_t const> psk,std::chrono::steady_clock::time_point now,std::uint64_t wall)
            -> std::expected<std::optional<UdpResponse>,UdpServerFailure> { return server_.poll(psk,now,wall); }
        [[nodiscard]] auto expire(std::chrono::steady_clock::time_point now,std::uint64_t wall)
            -> std::expected<std::size_t,UdpSessionError> { return server_.expire(now,wall); }
        auto close_relays() noexcept -> void { server_.close_relays(); }
        [[nodiscard]] auto sockets() const noexcept -> std::size_t { return server_.sockets(); }
    };
}
