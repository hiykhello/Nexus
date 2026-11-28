export module shadowsocks.udp_dispatch;
import std;
import net.principal_bytes;
import platform.socket_options;
import rules;
export import shadowsocks.udp_route;
export namespace shadowsocks {
    enum class UdpDispatchError { session, route, full, stale, timeout, no_candidate, limit, time_reversed, exhausted };
    struct UdpListenerAdmission {
        bool allow_new=true;
        UdpSessionError* rejected_session=nullptr;
        std::optional<UdpRequestIdentity> identity{};
    };
    struct UdpPending { std::uint64_t token; std::vector<std::uint8_t> address; };
    struct UdpDispatchRoute { std::size_t outbound; UdpPeer target; };
    struct UdpTunnelTicket { UdpSessionHandle session; UdpPeer target; UdpPeer source; };
    struct UdpTunnelPacket { UdpSessionHandle session; UdpPeer target; std::vector<std::uint8_t> payload; };
    // Single owner. Pending packets own their memory and are removed exactly
    // once by completion, cancellation or expiration. DNS is external.
    struct UdpTrafficObserver {
        void* owner=nullptr;
        void (*admitted)(void*,UdpSessionHandle,UdpPeer) noexcept=nullptr;
        void (*delivered)(void*,UdpSessionHandle,bool,std::size_t) noexcept=nullptr;
    };
    class UdpDispatcher {
        using Clock=std::chrono::steady_clock;
        struct Entry { UdpAccepted packet; Clock::time_point deadline; std::size_t bytes; rules::RouteProgram const* policy; bool selected; };
        UdpRoutedServer server_;
        UdpTrafficObserver traffic_;
        auto begin_impl(std::span<std::uint8_t const>,std::span<std::uint8_t const>,UdpPeer,
            Clock::time_point,std::uint64_t,Clock::time_point,rules::RouteProgram const*,bool,UdpListenerAdmission,bool)
            -> std::expected<UdpPending,UdpDispatchError>;
        std::map<std::uint64_t,Entry> pending_;
        std::size_t count_limit_,byte_limit_,bytes_=0;
        std::uint64_t next_=1;
        bool exhausted_=false;
        std::optional<Clock::time_point> last_;
        auto advance(Clock::time_point now) noexcept -> bool;
    public:
        UdpDispatcher(rules::Matcher policy,std::size_t sessions,std::size_t targets,std::size_t pending,std::size_t bytes,platform::SocketBinding const* binding=nullptr,
            UdpListenerReplay replay={})
            : server_(std::move(policy),sessions,targets,binding,std::move(replay)),count_limit_(pending),byte_limit_(bytes) {}
        UdpDispatcher(rules::RouteProgram policy,std::size_t sessions,std::size_t targets,std::size_t pending,std::size_t bytes,platform::SocketBinding const* binding=nullptr,
            UdpListenerReplay replay={})
            : server_(std::move(policy),sessions,targets,binding,std::move(replay)),count_limit_(pending),byte_limit_(bytes) {}
        // Set by the serialized listener before starting receive tasks and
        // cleared after all sends and tunneled operations have drained.
        auto observe_traffic(UdpTrafficObserver observer) noexcept -> void { traffic_=observer; }
        auto delivered(UdpSessionHandle session,bool upstream,std::size_t bytes) noexcept -> void {
            if (traffic_.delivered) traffic_.delivered(traffic_.owner,session,upstream,bytes);
        }
        // An optional listener policy must outlive the pending token, including
        // any asynchronous resolution and cancellation.
        [[nodiscard]] auto begin(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> wire,UdpPeer peer,
            Clock::time_point now,std::uint64_t wall,Clock::time_point deadline,
            rules::RouteProgram const* policy=nullptr,UdpListenerAdmission admission={},bool allow_tunnel=false) -> std::expected<UdpPending,UdpDispatchError>;
        // Authenticate and retain the packet without executing an indexed rule.
        // The caller must route it and consume or cancel the returned token.
        [[nodiscard]] auto begin_ordered(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> wire,UdpPeer peer,
            Clock::time_point now,std::uint64_t wall,Clock::time_point deadline,UdpListenerAdmission admission={})
            -> std::expected<UdpPending,UdpDispatchError>;
        // At most 64 resolved candidates. Blocked candidates are skipped; one
        // successful send ends the operation. A socket failure ends it too.
        [[nodiscard]] auto complete(std::uint64_t token,std::span<UdpPeer const> candidates,Clock::time_point now)
            -> std::expected<void,UdpDispatchError>;
        // Select a retained packet with its route matcher, then use the
        // same direct and tunnel submission contract as an ordered decision.
        [[nodiscard]] auto select_route(std::uint64_t token,std::span<UdpPeer const> candidates,Clock::time_point now)
            -> std::expected<UdpDispatchRoute,UdpDispatchError>;
        // The borrowed packet remains valid only while its pending token exists.
        [[nodiscard]] auto pending_packet(std::uint64_t token) const noexcept -> UdpAccepted const*;
        // Completes a direct decision without consulting the indexed policy.
        [[nodiscard]] auto complete_selected(std::uint64_t token,std::span<UdpPeer const> candidates,Clock::time_point now)
            -> std::expected<void,UdpDispatchError>;
        // An owned identity and target for acquiring a session-specific tunnel.
        // No packet view escapes; take_selected rechecks the token after any
        // asynchronous connection or queue wait.
        [[nodiscard]] auto inspect_selected(std::uint64_t token,UdpPeer candidate,Clock::time_point now)
            -> std::expected<UdpTunnelTicket,UdpDispatchError>;
        // Consume the token immediately before an external send. The caller
        // owns and budgets the returned payload, and must authorize replies
        // only after a successful send.
        [[nodiscard]] auto take_selected(std::uint64_t token,UdpPeer candidate,Clock::time_point now)
            -> std::expected<UdpTunnelPacket,UdpDispatchError>;
        [[nodiscard]] auto current(UdpSessionHandle const& session) const noexcept -> bool {return server_.current(session);}
        [[nodiscard]] auto reserve_bytes(UdpSessionHandle const& session,bool upstream,std::size_t size,Clock::time_point now)
            const -> std::optional<net::PrincipalBytes::Reservation> {
            return server_.reserve_bytes(session,upstream,size,now);
        }
        // Caller must first verify the tunnel's committed source authorization.
        [[nodiscard]] auto tunnel_response(std::span<std::uint8_t const> psk,UdpSessionHandle const& session,UdpPeer source,
            std::span<std::uint8_t const> payload,Clock::time_point now,std::uint64_t wall)
            -> std::expected<std::optional<UdpResponse>,UdpSessionError> {
            return server_.tunnel_response(psk,session,source,payload,now,wall);
        }
        [[nodiscard]] auto retire(UdpSessionHandle const&,Clock::time_point) noexcept -> bool;
        [[nodiscard]] auto cancel(std::uint64_t token) noexcept -> bool;
        [[nodiscard]] auto expire(Clock::time_point now,std::uint64_t wall) -> std::expected<std::size_t,UdpDispatchError>;
        [[nodiscard]] auto poll(std::span<std::uint8_t const> psk,Clock::time_point now,std::uint64_t wall)
            -> std::expected<std::optional<UdpResponse>,UdpServerFailure> {
            if (!advance(now)) return std::unexpected(UdpServerFailure{UdpSessionError::time_reversed});
            return server_.poll(psk,now,wall);
        }
        // Reconfiguration is safe only after external operations are drained.
        // Existing sessions and replay records survive the policy replacement.
        template<class Policy> requires (std::same_as<Policy,rules::Matcher> || std::same_as<Policy,rules::RouteProgram>)
        [[nodiscard]] auto replace_policy(Policy policy) noexcept -> bool {
            if (!pending_.empty() || server_.sockets()!=0) return false;
            server_.replace_policy(std::move(policy)); return true;
        }
        // After canceling all external operations, close transport resources.
        // Session replay state remains alive until this dispatcher is destroyed.
        auto close_relays() noexcept -> void { server_.close_relays(); }
        [[nodiscard]] auto pending() const noexcept -> std::size_t { return pending_.size(); }
        [[nodiscard]] auto active() const noexcept -> bool {return server_.active();}
        [[nodiscard]] auto sockets() const noexcept -> std::size_t { return server_.sockets(); }
    };
}
