export module nexus.shadowsocks.udp_dispatch;
import std;
import nexus.rules;
export import nexus.shadowsocks.udp_route;
export namespace nexus::shadowsocks {
    enum class UdpDispatchError { session, route, full, stale, timeout, no_candidate, limit, time_reversed, exhausted };
    struct UdpPending { std::uint64_t token; std::vector<std::uint8_t> address; };
    // Single owner. Pending packets own their memory and are removed exactly
    // once by completion, cancellation or expiration. DNS is external.
    class UdpDispatcher {
        using Clock=std::chrono::steady_clock;
        struct Entry { UdpAccepted packet; Clock::time_point deadline; std::size_t bytes; };
        UdpRoutedServer server_;
        std::map<std::uint64_t,Entry> pending_;
        std::size_t count_limit_,byte_limit_,bytes_=0;
        std::uint64_t next_=1;
        bool exhausted_=false;
        std::optional<Clock::time_point> last_;
        auto advance(Clock::time_point now) noexcept -> bool;
    public:
        UdpDispatcher(rules::Matcher policy,std::size_t sessions,std::size_t targets,std::size_t pending,std::size_t bytes)
            : server_(std::move(policy),sessions,targets),count_limit_(pending),byte_limit_(bytes) {}
        UdpDispatcher(rules::RouteMatcher policy,std::size_t sessions,std::size_t targets,std::size_t pending,std::size_t bytes)
            : server_(std::move(policy),sessions,targets),count_limit_(pending),byte_limit_(bytes) {}
        [[nodiscard]] auto begin(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> wire,UdpPeer peer,
            Clock::time_point now,std::uint64_t wall,Clock::time_point deadline) -> std::expected<UdpPending,UdpDispatchError>;
        // At most 64 resolved candidates. Blocked candidates are skipped; one
        // successful send ends the operation. A socket failure ends it too.
        [[nodiscard]] auto complete(std::uint64_t token,std::span<UdpPeer const> candidates,Clock::time_point now)
            -> std::expected<void,UdpDispatchError>;
        [[nodiscard]] auto cancel(std::uint64_t token) noexcept -> bool;
        [[nodiscard]] auto expire(Clock::time_point now,std::uint64_t wall) -> std::expected<std::size_t,UdpDispatchError>;
        [[nodiscard]] auto poll(std::span<std::uint8_t const> psk,Clock::time_point now,std::uint64_t wall)
            -> std::expected<std::optional<UdpResponse>,UdpServerFailure> {
            if (!advance(now)) return std::unexpected(UdpServerFailure{UdpSessionError::time_reversed});
            return server_.poll(psk,now,wall);
        }
        // Reconfiguration is safe only after external operations are drained.
        // Existing sessions and replay records survive the policy replacement.
        template<class Policy> requires (std::same_as<Policy,rules::Matcher> || std::same_as<Policy,rules::RouteMatcher>)
        [[nodiscard]] auto replace_policy(Policy policy) noexcept -> bool {
            if (!pending_.empty() || server_.sockets()!=0) return false;
            server_.replace_policy(std::move(policy)); return true;
        }
        // After canceling all external operations, close transport resources.
        // Session replay state remains alive until this dispatcher is destroyed.
        auto close_relays() noexcept -> void { server_.close_relays(); }
        [[nodiscard]] auto pending() const noexcept -> std::size_t { return pending_.size(); }
        [[nodiscard]] auto sockets() const noexcept -> std::size_t { return server_.sockets(); }
    };
}
