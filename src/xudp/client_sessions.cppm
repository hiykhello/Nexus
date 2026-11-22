export module xudp.client_sessions;
import std;
import xudp;

export namespace xudp {
    // One executor owns this table and serializes writes. Session IDs never
    // repeat on a stream, so a late reply cannot target a newer session.
    // The owner must defer incoming frames while a write is pending, and must
    // tear down the stream if a write fails or is only partially delivered.
    enum class SessionError { closed, busy, limit, exhausted, unknown, invalid_frame, stale };
    enum class Incoming { datagram, ended, unknown, ignored, invalid, unauthorized };
    struct PendingFrame { std::uint64_t token=0; Frame frame{}; };
    struct IncomingFrame { Incoming action=Incoming::invalid; std::uint16_t session=0; std::optional<Address> address; std::span<std::uint8_t const> payload{}; bool error=false; };
    class ClientSessions {
        struct Entry { std::uint16_t id=0; Address target{}; };
        struct Authorized { std::uint16_t id=0; Address target{}; std::uint64_t last=0; };
        std::vector<Entry> entries_;
        std::array<Authorized,64> authorized_{};
        std::size_t authorized_count_=0;
        std::size_t limit_;
#ifdef NEXUS_TEST_XUDP_ROTATION
        std::uint32_t next_id_=65534;
#else
        std::uint32_t next_id_=1;
#endif
        std::uint64_t serial_=0;
        PendingFrame pending_{};
        bool closed_=false;
        auto find(std::uint16_t id) noexcept { return std::ranges::find(entries_,id,&Entry::id); }
        auto authorize(std::uint16_t id,Address const& target,std::uint64_t serial) noexcept -> void {
            auto end=authorized_.begin()+authorized_count_;
            auto found=std::find_if(authorized_.begin(),end,[&](auto const& entry){return entry.id==id && entry.target==target;});
            if (found==end && authorized_count_==authorized_.size()) found=std::min_element(authorized_.begin(),end,[](auto const& a,auto const& b){return a.last<b.last;});
            auto index=static_cast<std::size_t>(found-authorized_.begin());
            *found={id,target,serial}; if (index==authorized_count_) ++authorized_count_;
        }
        auto forget(std::uint16_t id) noexcept -> void {
            auto end=std::remove_if(authorized_.begin(),authorized_.begin()+authorized_count_,[&](auto const& entry){return entry.id==id;});
            authorized_count_=static_cast<std::size_t>(end-authorized_.begin());
        }
        auto reserve_token() noexcept -> std::expected<std::uint64_t,SessionError> {
            if (closed_) return std::unexpected(SessionError::closed);
            if (pending_.token) return std::unexpected(SessionError::busy);
            if (serial_==std::numeric_limits<std::uint64_t>::max()) return std::unexpected(SessionError::exhausted);
            return ++serial_;
        }
    public:
        explicit ClientSessions(std::size_t limit) : limit_(std::min(limit,std::size_t{65535})) { entries_.reserve(limit_); }
        ClientSessions(ClientSessions const&)=delete;
        auto operator=(ClientSessions const&) -> ClientSessions& = delete;
        [[nodiscard]] auto size() const noexcept -> std::size_t { return entries_.size(); }
        [[nodiscard]] auto is_closed() const noexcept -> bool { return closed_; }
        // Payload remains borrowed until finish. Global IDs require separate
        // cross-connection lifecycle management and are deliberately omitted.
        [[nodiscard]] auto open(Address target,std::span<std::uint8_t const> payload) -> std::expected<PendingFrame,SessionError> {
            if (closed_) return std::unexpected(SessionError::closed);
            if (pending_.token) return std::unexpected(SessionError::busy);
            if (entries_.size()>=limit_) return std::unexpected(SessionError::limit);
            if (next_id_>65535) return std::unexpected(SessionError::exhausted);
            Frame frame{static_cast<std::uint16_t>(next_id_),Kind::open,true,false,target,{},payload};
            if (!encode(frame)) return std::unexpected(SessionError::invalid_frame);
            auto token=reserve_token(); if (!token) return std::unexpected(token.error());
            pending_={*token,frame}; return pending_;
        }
        [[nodiscard]] auto send(std::uint16_t id,std::optional<Address> target,std::span<std::uint8_t const> payload) -> std::expected<PendingFrame,SessionError> {
            if (closed_) return std::unexpected(SessionError::closed);
            if (pending_.token) return std::unexpected(SessionError::busy);
            if (find(id)==entries_.end()) return std::unexpected(SessionError::unknown);
            Frame frame{id,Kind::data,true,false,target,{},payload};
            if (!encode(frame)) return std::unexpected(SessionError::invalid_frame);
            auto token=reserve_token(); if (!token) return std::unexpected(token.error());
            pending_={*token,frame}; return pending_;
        }
        [[nodiscard]] auto end(std::uint16_t id) noexcept -> std::expected<PendingFrame,SessionError> {
            if (closed_) return std::unexpected(SessionError::closed);
            if (pending_.token) return std::unexpected(SessionError::busy);
            if (find(id)==entries_.end()) return std::unexpected(SessionError::unknown);
            auto token=reserve_token(); if (!token) return std::unexpected(token.error());
            pending_={*token,Frame{id,Kind::end}}; return pending_;
        }
        // A failed write invalidates the whole table: the peer may have seen
        // a prefix, so retrying or reusing the stream is unsafe.
        [[nodiscard]] auto finish(std::uint64_t token,bool success) noexcept -> std::expected<void,SessionError> {
            if (closed_) return std::unexpected(SessionError::closed);
            if (!token || token!=pending_.token) return std::unexpected(SessionError::stale);
            if (!success) { close(); return {}; }
            if (pending_.frame.kind==Kind::open) {
                entries_.push_back({pending_.frame.session,*pending_.frame.address}); ++next_id_;
                authorize(pending_.frame.session,*pending_.frame.address,token);
            } else if (pending_.frame.kind==Kind::data) {
                auto entry=find(pending_.frame.session);
                authorize(entry->id,pending_.frame.address ? *pending_.frame.address : entry->target,token);
            } else if (pending_.frame.kind==Kind::end) { forget(pending_.frame.session); entries_.erase(find(pending_.frame.session)); }
            pending_={}; return {};
        }
        // A reply is accepted only for a destination successfully written on
        // the same session. Up to 64 recent session/destination pairs are kept
        // across the stream; an omitted source denotes the initial target.
        // Name resolution and outbound policy remain the caller's responsibility.
        [[nodiscard]] auto receive(Frame const& frame) noexcept -> IncomingFrame {
            IncomingFrame result; result.session=frame.session; result.error=frame.error;
            if (closed_ || pending_.token) return result;
            if (frame.kind==Kind::keepalive || frame.kind==Kind::open) { result.action=Incoming::ignored; return result; }
            auto entry=find(frame.session);
            if (entry==entries_.end()) { result.action=Incoming::unknown; return result; }
            if (frame.kind==Kind::end) { forget(frame.session); entries_.erase(entry); result.action=Incoming::ended; return result; }
            if (frame.kind!=Kind::data) return result;
            if (!frame.has_data) { result.action=Incoming::ignored; return result; }
            result.address=frame.address ? frame.address : std::optional<Address>(entry->target);
            auto end=authorized_.begin()+authorized_count_;
            if (std::find_if(authorized_.begin(),end,[&](auto const& item){return item.id==frame.session && item.target==*result.address;})==end) {
                result.action=Incoming::unauthorized; return result;
            }
            result.action=Incoming::datagram; result.payload=frame.payload; return result;
        }
        auto close() noexcept -> void { closed_=true; entries_.clear(); authorized_count_=0; pending_={}; }
    };
}
