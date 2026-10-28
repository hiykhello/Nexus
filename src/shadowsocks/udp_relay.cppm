export module nexus.shadowsocks.udp_relay;
import std;
export import nexus.shadowsocks.udp_sessions;
export namespace nexus::shadowsocks {
    enum class UdpRelayError { invalid_target, session_limit, target_limit, system };
    struct UdpRelayFailure { UdpRelayError kind; std::error_code system; };
    struct UdpRelayReply { std::array<std::uint8_t,8> session; UdpPeer source; std::vector<std::uint8_t> payload; };
    // Single owner, Linux nonblocking sockets. Caller must authenticate packets,
    // resolve and authorize every destination, and close IDs returned by expire().
    class UdpRelay {
        struct Entry { int fd=-1; std::set<UdpPeer> targets; };
        std::map<std::array<std::uint8_t,8>,Entry> sockets_;
        std::optional<std::array<std::uint8_t,8>> cursor_;
        std::size_t max_sessions_,max_targets_;
    public:
        UdpRelay(std::size_t sessions,std::size_t targets) : max_sessions_(sessions),max_targets_(targets) {}
        ~UdpRelay();
        UdpRelay(UdpRelay const&)=delete;
        auto operator=(UdpRelay const&) -> UdpRelay& = delete;
        [[nodiscard]] auto send(std::array<std::uint8_t,8> session,UdpPeer target,std::span<std::uint8_t const> payload)
            -> std::expected<void,UdpRelayFailure>;
        // Visit at most 64 sockets, consuming at most one packet per socket;
        // drop unauthorized packets and return at most one authorized reply.
        // A socket receive error closes only that session socket and is reported.
        [[nodiscard]] auto poll() -> std::expected<std::optional<UdpRelayReply>,UdpRelayFailure>;
        auto close(std::array<std::uint8_t,8> session) noexcept -> void;
        auto clear() noexcept -> void;
        [[nodiscard]] auto size() const noexcept -> std::size_t { return sockets_.size(); }
    };
}
