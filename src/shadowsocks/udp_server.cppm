export module shadowsocks.udp_server;
import std;
import platform.socket_options;
import net.principal_bytes;
export import shadowsocks.udp_relay;
export namespace shadowsocks {
    struct UdpListenerReplay {
        std::shared_ptr<UdpServerSessions> sessions;
        std::uint64_t listener_generation=0;
    };
    using UdpServerFailure=std::variant<UdpSessionError,UdpRelayFailure>;
    // Serialized owner for one PSK. The caller authenticates via receive(),
    // resolves and authorizes each destination before calling forward(), and
    // dispatches poll() output promptly to its returned peer. Replies too
    // large for the peer's IP family after encapsulation are dropped.
    class UdpServer {
        std::shared_ptr<UdpServerSessions> sessions_;
        std::uint64_t listener_generation_;
        UdpRelay relay_;
    public:
        UdpServer(std::size_t sessions,std::size_t targets,platform::SocketBinding const* binding=nullptr,
            UdpListenerReplay replay={})
            :sessions_(replay.sessions ? std::move(replay.sessions) : std::make_shared<UdpServerSessions>(sessions)),
             listener_generation_(replay.listener_generation),relay_(sessions,targets,binding) {}
        UdpServer(UdpServer const&)=delete;
        auto operator=(UdpServer const&) -> UdpServer& = delete;
        [[nodiscard]] auto receive(std::span<std::uint8_t const> psk,std::span<std::uint8_t const> wire,
            UdpPeer peer,std::chrono::steady_clock::time_point now,std::uint64_t wall,bool allow_new=true,
            std::optional<UdpRequestIdentity> identity={})
            -> std::expected<UdpAccepted,UdpSessionError>;
        [[nodiscard]] auto forward(UdpAccepted const& packet,UdpPeer authorized_target) -> std::expected<void,UdpServerFailure>;
        [[nodiscard]] auto reserve_bytes(UdpSessionHandle const& session,bool upstream,std::size_t size,
            std::chrono::steady_clock::time_point now) const -> std::optional<net::PrincipalBytes::Reservation> {
            return sessions_->reserve_bytes(session,listener_generation_,upstream,size,now);
        }
        [[nodiscard]] auto current(UdpAccepted const& packet) const noexcept -> bool {return sessions_->current(packet,listener_generation_);}
        [[nodiscard]] auto current(UdpSessionHandle const& session) const noexcept -> bool {return sessions_->current(session,listener_generation_);}
        // The tunnel owner must authorize the reply source after a successful
        // send. This method additionally rejects stale session generations.
        [[nodiscard]] auto tunnel_response(std::span<std::uint8_t const> psk,UdpSessionHandle const& session,UdpPeer source,
            std::span<std::uint8_t const> payload,std::chrono::steady_clock::time_point now,std::uint64_t wall)
            -> std::expected<std::optional<UdpResponse>,UdpSessionError>;
        [[nodiscard]] auto poll(std::span<std::uint8_t const> psk,std::chrono::steady_clock::time_point now,std::uint64_t wall)
            -> std::expected<std::optional<UdpResponse>,UdpServerFailure>;
        [[nodiscard]] auto expire(std::chrono::steady_clock::time_point now,std::uint64_t wall)
            -> std::expected<std::size_t,UdpSessionError>;
        [[nodiscard]] auto retire(UdpSessionHandle const& session,std::chrono::steady_clock::time_point now) noexcept -> bool {
            if (!current(session) || !sessions_->retire(session,now)) return false;
            relay_.close(session.id);
            return true;
        }
        // Close all relay sockets without discarding replay/session state.
        auto close_relays() noexcept -> void {
            relay_.clear();
            if (listener_generation_) sessions_->retire_listener(listener_generation_,std::chrono::steady_clock::now());
        }
        [[nodiscard]] auto active() const noexcept -> bool {return sessions_->active(listener_generation_);}
        [[nodiscard]] auto sessions() const noexcept -> std::size_t { return sessions_->size(); }
        [[nodiscard]] auto sockets() const noexcept -> std::size_t { return relay_.size(); }
    };
}
