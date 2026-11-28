export module shadowsocks.udp_route;
import std;
import net.principal_bytes;
import platform.socket_options;
import rules;
export import shadowsocks.udp_server;
export namespace shadowsocks {
    enum class UdpRouteError { invalid_target, blocked, unsupported, policy_error };
    using UdpRoutedFailure=std::variant<UdpRouteError,UdpServerFailure>;
    // Policy snapshot. Ordered routes use outbound 0 for direct and 1 for
    // block; unsupported outbounds fail closed. The caller must preflight
    // domains and resolve through configured DNS rather than trusting input.
    class UdpRoutedServer {
        std::variant<rules::Matcher,rules::RouteProgram> policy_;
        static_assert(std::is_nothrow_move_assignable_v<decltype(policy_)>);
        UdpServer server_;
    public:
        UdpRoutedServer(rules::Matcher policy,std::size_t sessions,std::size_t targets,platform::SocketBinding const* binding=nullptr,
            UdpListenerReplay replay={})
            : policy_(std::move(policy)),server_(sessions,targets,binding,std::move(replay)) {}
        UdpRoutedServer(rules::RouteProgram policy,std::size_t sessions,std::size_t targets,platform::SocketBinding const* binding=nullptr,
            UdpListenerReplay replay={})
            : policy_(std::move(policy)),server_(sessions,targets,binding,std::move(replay)) {}
        // Caller must serialize changes and cancel all in-flight work first.
        template<class Policy> requires (std::same_as<Policy,rules::Matcher> || std::same_as<Policy,rules::RouteProgram>)
        auto replace_policy(Policy policy) noexcept -> void { policy_=std::move(policy); }
        [[nodiscard]] auto receive(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> wire,UdpPeer peer,
            std::chrono::steady_clock::time_point now,std::uint64_t wall,bool allow_new=true,
            std::optional<UdpRequestIdentity> identity={}) -> std::expected<UdpAccepted,UdpSessionError> {
            return server_.receive(psk,wire,peer,now,wall,allow_new,identity);
        }
        [[nodiscard]] auto reserve_bytes(UdpSessionHandle const& session,bool upstream,std::size_t size,
            std::chrono::steady_clock::time_point now) const -> std::optional<net::PrincipalBytes::Reservation> {
            return server_.reserve_bytes(session,upstream,size,now);
        }
        [[nodiscard]] auto preflight(UdpAccepted const& packet,rules::RouteProgram const* policy=nullptr,bool allow_tunnel=false) const
            -> std::expected<void,UdpRouteError>;
        [[nodiscard]] auto select_outbound(UdpAccepted const&,UdpPeer,rules::RouteProgram const* policy,bool allow_tunnel=false) const
            -> std::expected<std::size_t,UdpRouteError>;
        // Numeric addresses must match the request; for domains, the caller
        // supplies an actual resolved candidate with the requested port.
        [[nodiscard]] auto forward(UdpAccepted const& packet,UdpPeer resolved,rules::RouteProgram const* policy=nullptr) -> std::expected<void,UdpRoutedFailure>;
        // Candidate is chosen by an external ordered program; validation and
        // the session's reply authorization remain owned by this server.
        [[nodiscard]] auto forward_selected(UdpAccepted const&,UdpPeer) -> std::expected<void,UdpRoutedFailure>;
        // Validates and canonicalizes a selected candidate without sending it.
        [[nodiscard]] auto validate_selected(UdpAccepted const&,UdpPeer) const -> std::expected<UdpPeer,UdpRouteError>;
        [[nodiscard]] auto current(UdpAccepted const& packet) const noexcept -> bool {return server_.current(packet);}
        [[nodiscard]] auto current(UdpSessionHandle const& session) const noexcept -> bool {return server_.current(session);}
        [[nodiscard]] auto tunnel_response(std::span<std::uint8_t const> psk,UdpSessionHandle const& session,UdpPeer source,
            std::span<std::uint8_t const> payload,std::chrono::steady_clock::time_point now,std::uint64_t wall)
            -> std::expected<std::optional<UdpResponse>,UdpSessionError> {
            return server_.tunnel_response(psk,session,source,payload,now,wall);
        }
        [[nodiscard]] auto poll(std::span<std::uint8_t const> psk,std::chrono::steady_clock::time_point now,std::uint64_t wall)
            -> std::expected<std::optional<UdpResponse>,UdpServerFailure> { return server_.poll(psk,now,wall); }
        [[nodiscard]] auto expire(std::chrono::steady_clock::time_point now,std::uint64_t wall)
            -> std::expected<std::size_t,UdpSessionError> { return server_.expire(now,wall); }
        [[nodiscard]] auto retire(UdpSessionHandle const& session,std::chrono::steady_clock::time_point now) noexcept -> bool {
            return server_.retire(session,now);
        }
        auto close_relays() noexcept -> void { server_.close_relays(); }
        [[nodiscard]] auto active() const noexcept -> bool {return server_.active();}
        [[nodiscard]] auto sockets() const noexcept -> std::size_t { return server_.sockets(); }
    };
}
