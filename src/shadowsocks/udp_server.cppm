export module nexus.shadowsocks.udp_server;
import std;
export import nexus.shadowsocks.udp_relay;
export namespace nexus::shadowsocks {
    using UdpServerFailure=std::variant<UdpSessionError,UdpRelayFailure>;
    // Serialized owner for one PSK. The caller authenticates via receive(),
    // resolves and authorizes each destination before calling forward(), and
    // dispatches poll() output promptly to its returned peer. Replies too
    // large for the peer's IP family after encapsulation are dropped.
    class UdpServer {
        UdpServerSessions sessions_;
        UdpRelay relay_;
    public:
        UdpServer(std::size_t sessions,std::size_t targets) : sessions_(sessions),relay_(sessions,targets) {}
        UdpServer(UdpServer const&)=delete;
        auto operator=(UdpServer const&) -> UdpServer& = delete;
        [[nodiscard]] auto receive(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> wire,
            UdpPeer peer,std::chrono::steady_clock::time_point now,std::uint64_t wall)
            -> std::expected<UdpAccepted,UdpSessionError>;
        [[nodiscard]] auto forward(UdpAccepted const& packet,UdpPeer authorized_target) -> std::expected<void,UdpServerFailure>;
        [[nodiscard]] auto poll(std::span<std::uint8_t const> psk,std::chrono::steady_clock::time_point now,std::uint64_t wall)
            -> std::expected<std::optional<UdpResponse>,UdpServerFailure>;
        [[nodiscard]] auto expire(std::chrono::steady_clock::time_point now,std::uint64_t wall)
            -> std::expected<std::size_t,UdpSessionError>;
        // Close all relay sockets without discarding replay/session state.
        auto close_relays() noexcept -> void { relay_.clear(); }
        [[nodiscard]] auto sessions() const noexcept -> std::size_t { return sessions_.size(); }
        [[nodiscard]] auto sockets() const noexcept -> std::size_t { return relay_.size(); }
    };
}
