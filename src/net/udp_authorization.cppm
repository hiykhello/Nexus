export module net.udp_authorization;
export import net.udp_socket;
import std;

export namespace net {
    enum class UdpAuthorizationError { closed, busy, invalid_address, stale, exhausted };
    enum class UdpReplyAuthorization { accepted, pending, rejected };
    // One stream and executor own this bounded table. A target is committed
    // only after its complete send succeeds; a failed replacement keeps the old entry.
    class UdpAuthorization {
        struct Entry { UdpEndpoint peer{}; std::uint64_t last=0; };
        std::array<Entry,64> entries_{};
        std::size_t count_=0, pending_index_=0;
        UdpEndpoint pending_peer_{};
        std::uint64_t serial_=0, pending_token_=0;
        bool closed_=false;
    public:
        [[nodiscard]] auto begin(UdpEndpoint peer) noexcept -> std::expected<std::uint64_t,UdpAuthorizationError> {
            if (closed_) return std::unexpected(UdpAuthorizationError::closed);
            if (pending_token_) return std::unexpected(UdpAuthorizationError::busy);
            if ((peer.family!=4 && peer.family!=6) || !peer.port ||
                std::ranges::all_of(peer.address,[](auto b){return b==0;}) ||
                (peer.family==4 && std::ranges::any_of(std::span(peer.address).subspan(4),[](auto b){return b!=0;})))
                return std::unexpected(UdpAuthorizationError::invalid_address);
            if (serial_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(UdpAuthorizationError::exhausted);
            auto end=entries_.begin()+count_;
            auto found=std::find_if(entries_.begin(),end,[&](auto const& entry){return entry.peer==peer;});
            if (found==end && count_==entries_.size()) found=std::min_element(entries_.begin(),end,[](auto const& a,auto const& b){return a.last<b.last;});
            pending_index_=static_cast<std::size_t>(found-entries_.begin());
            pending_peer_=peer; pending_token_=++serial_;
            return pending_token_;
        }
        [[nodiscard]] auto finish(std::uint64_t token,bool success) noexcept -> std::expected<void,UdpAuthorizationError> {
            if (closed_) return std::unexpected(UdpAuthorizationError::closed);
            if (!token || token!=pending_token_) return std::unexpected(UdpAuthorizationError::stale);
            if (success) {
                entries_[pending_index_]={pending_peer_,token};
                if (pending_index_==count_) ++count_;
            }
            pending_token_=0; pending_peer_={};
            return {};
        }
        [[nodiscard]] auto classify(UdpEndpoint peer) const noexcept -> UdpReplyAuthorization {
            if (closed_) return UdpReplyAuthorization::rejected;
            if (std::find_if(entries_.begin(),entries_.begin()+count_,[&](auto const& entry){return entry.peer==peer;})!=entries_.begin()+count_)
                return UdpReplyAuthorization::accepted;
            if (pending_token_ && pending_peer_==peer) return UdpReplyAuthorization::pending;
            return UdpReplyAuthorization::rejected;
        }
        [[nodiscard]] auto accepts(UdpEndpoint peer) const noexcept -> bool { return classify(peer)==UdpReplyAuthorization::accepted; }
        auto close() noexcept -> void { closed_=true; count_=0; pending_token_=0; }
    };
}
