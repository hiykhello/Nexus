export module xudp.server_direct;
import std;
import xudp;
import xudp.server_sessions;
import net.udp_route;
import net.udp_socket;
import net.udp_dial;
import platform.socket_options;
import rules;

export namespace xudp {
    enum class ServerDirectError { closed, stale, invalid, authorization };
    using ServerDirectFailure=std::variant<ServerDirectError,net::UdpRouteError,std::error_code>;
    struct ServerDirectReply { ServerToken token; Address source; std::size_t size=0; };
    // Nonblocking direct-only UDP sockets, one per Mux session. All calls use
    // one executor; the caller resolves domains, preserves frame payload while
    // retrying backpressure, and closes the owner when the stream ends.
    class ServerDirect {
        using Clock=std::chrono::steady_clock;
        struct Slot { ServerToken token; net::UdpDialSockets socket; Clock::time_point touched; explicit Slot(::platform::SocketBinding const* binding) : socket(binding) {} };
        ::rules::RouteMatcher const& policy_;
        ::platform::SocketBinding const* binding_;
        std::optional<net::UdpEndpoint> source_;
        std::optional<std::string_view> auth_user_;
        ServerSessions sessions_;
        std::vector<std::unique_ptr<Slot>> slots_;
        std::size_t cursor_=0;
        bool closed_=false;
        auto find(ServerToken token) noexcept { return std::ranges::find_if(slots_,[&](auto const& slot){return slot->token==token;}); }
        static auto to_address(net::UdpEndpoint const& peer) noexcept -> Address {
            Address out; out.family=peer.family==4 ? Family::ipv4 : Family::ipv6;
            out.length=peer.family==4 ? 4 : 16; out.port=peer.port;
            std::copy_n(peer.address.begin(),out.length,out.bytes.begin()); return out;
        }
        static auto route_target(Address const& target) noexcept -> std::optional<net::UdpTarget> {
            namespace n=net;
            auto kind=target.family==Family::ipv4 ? n::UdpTargetKind::ipv4 :
                target.family==Family::ipv6 ? n::UdpTargetKind::ipv6 : n::UdpTargetKind::domain;
            if ((kind==n::UdpTargetKind::ipv4 && target.length!=4) ||
                (kind==n::UdpTargetKind::ipv6 && target.length!=16) ||
                (kind==n::UdpTargetKind::domain && !target.length)) return {};
            return n::UdpTarget{kind,std::span{target.bytes}.first(target.length),target.port};
        }
    public:
        // auth_user is borrowed for the lifetime of this stream owner.
        ServerDirect(::rules::RouteMatcher const& policy,std::size_t limit,net::UdpEndpoint const* source=nullptr,
                     std::optional<std::string_view> auth_user={},::platform::SocketBinding const* binding=nullptr)
            : policy_(policy),binding_(binding),source_(source ? std::optional(*source) : std::nullopt),auth_user_(auth_user),sessions_(limit) { slots_.reserve(std::min(limit,std::size_t{65535})); }
        ServerDirect(ServerDirect const&)=delete;
        auto operator=(ServerDirect const&) -> ServerDirect& = delete;
        [[nodiscard]] auto receive(Frame const& frame,Clock::time_point now=Clock::now()) -> ServerEvent {
            // Allocate before mutating the table; push_back cannot allocate
            // after the constructor reserves the full session capacity.
            std::unique_ptr<Slot> created;
            if (!closed_ && frame.kind==Kind::open) created=std::make_unique<Slot>(binding_);
            auto event=sessions_.receive(frame);
            if (event.action==ServerAction::opened) { created->token=event.token; created->touched=now; slots_.push_back(std::move(created)); }
            else if (event.action==ServerAction::ended) {
                auto slot=find(event.token); if (slot!=slots_.end()) slots_.erase(slot);
                if (slots_.empty()) cursor_=0; else cursor_%=slots_.size();
            }
            else if (event.action==ServerAction::datagram) {
                auto slot=find(event.token); if (slot!=slots_.end()) (*slot)->touched=now;
            }
            return event;
        }
        [[nodiscard]] auto contains(ServerToken token) noexcept -> bool { return !closed_ && find(token)!=slots_.end(); }
        // Remove at most one idle session; the caller serializes this with I/O
        // and sends an end to the peer. Time moving backwards never expires it.
        [[nodiscard]] auto expire_one(Clock::time_point now,Clock::duration idle) -> std::optional<ServerToken> {
            if (closed_ || idle<=Clock::duration::zero()) return {};
            auto slot=std::ranges::find_if(slots_,[&](auto const& item){ return now>=item->touched && now-item->touched>=idle; });
            if (slot==slots_.end()) return {};
            auto token=(*slot)->token;
            auto event=receive(Frame{token.id,Kind::end},now);
            return event.action==ServerAction::ended && event.token==token ? std::optional{token} : std::nullopt;
        }
        [[nodiscard]] auto preflight(Address const& target) const -> std::expected<void,ServerDirectFailure> {
            if (closed_) return std::unexpected(ServerDirectFailure{ServerDirectError::closed});
            auto packet=route_target(target); if (!packet) return std::unexpected(ServerDirectFailure{ServerDirectError::invalid});
            auto result=net::udp_preflight(policy_,*packet,source_ ? &*source_ : nullptr,auth_user_);
            if (!result) return std::unexpected(ServerDirectFailure{result.error()});
            return {};
        }
        [[nodiscard]] auto send(ServerToken token,Address const& target,net::UdpEndpoint candidate,std::span<std::uint8_t const> payload)
            -> std::expected<void,ServerDirectFailure> {
            if (closed_) return std::unexpected(ServerDirectFailure{ServerDirectError::closed});
            auto slot=find(token); if (slot==slots_.end()) return std::unexpected(ServerDirectFailure{ServerDirectError::stale});
            auto packet=route_target(target);
            if (!packet) return std::unexpected(ServerDirectFailure{ServerDirectError::invalid});
            auto selected=net::udp_route(policy_,*packet,candidate,source_ ? &*source_ : nullptr,auth_user_);
            if (!selected) return std::unexpected(ServerDirectFailure{selected.error()});
            auto written=(*slot)->socket.send(*selected,payload);
            if (!written) return std::unexpected(ServerDirectFailure{written.error()});
            if (!sessions_.sent(token,to_address(*selected))) { close(); return std::unexpected(ServerDirectFailure{ServerDirectError::authorization}); }
            (*slot)->touched=Clock::now();
            return {};
        }
        // At most one datagram is consumed per call, including unauthorized or
        // oversized data. Bytes in buffer are valid only until the next poll.
        [[nodiscard]] auto poll(std::span<std::uint8_t> buffer,bool* dropped=nullptr)
            -> std::expected<std::optional<ServerDirectReply>,ServerDirectFailure> {
            if (dropped) *dropped=false;
            if (closed_) return std::unexpected(ServerDirectFailure{ServerDirectError::closed});
            if (slots_.empty()) return std::optional<ServerDirectReply>{};
            for (std::size_t i=0;i<slots_.size();++i) {
                auto index=(cursor_+i)%slots_.size(); auto& slot=*slots_[index];
                auto packet=slot.socket.peek(buffer); if (!packet) return std::unexpected(ServerDirectFailure{packet.error()});
                if (!*packet) continue;
                auto metadata=**packet; auto consumed=slot.socket.consume();
                if (!consumed) return std::unexpected(ServerDirectFailure{consumed.error()});
                if (!*consumed) continue;
                cursor_=(index+1)%slots_.size();
                auto source=to_address(metadata.source);
                if (!metadata.valid || **consumed!=metadata.size || !sessions_.accepts(slot.token,source)) {
                    if (dropped) *dropped=true; return std::optional<ServerDirectReply>{};
                }
                slot.touched=Clock::now();
                return std::optional{ServerDirectReply{slot.token,source,metadata.size}};
            }
            return std::optional<ServerDirectReply>{};
        }
        auto close() noexcept -> void { if (closed_) return; closed_=true; slots_.clear(); sessions_.close(); }
    };
}
