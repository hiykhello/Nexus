export module xudp.server_sessions;
import std;
import xudp;

export namespace xudp {
    struct ServerToken {
        std::uint16_t id=0;
        std::uint64_t generation=0;
        auto operator==(ServerToken const&) const -> bool = default;
    };
    enum class ServerAction { opened, datagram, ended, ignored, unknown, duplicate, limit, unsupported, invalid, closed };
    struct ServerEvent {
        ServerAction action=ServerAction::invalid;
        ServerToken token{};
        std::optional<Address> destination;
        std::span<std::uint8_t const> payload{};
        bool has_data=false, error=false;
    };
    // A single executor owns the table. The caller resolves and applies routing
    // to every datagram, then calls sent only after successful delivery. Tokens
    // prevent delayed I/O from authorizing a reused local session ID. Global ID
    // migration needs a separate process-wide owner and is not implemented here.
    class ServerSessions {
        struct Entry { ServerToken token; Address initial; };
        struct Authorized { ServerToken token; Address destination; std::uint64_t serial=0; };
        std::vector<Entry> entries_;
        std::array<Authorized,64> authorized_{};
        std::size_t count_=0,limit_;
        std::uint64_t generation_=0,serial_=0;
        bool closed_=false;
        auto find(std::uint16_t id) noexcept { return std::ranges::find_if(entries_,[&](auto const& entry){return entry.token.id==id;}); }
        auto forget(ServerToken token) noexcept -> void {
            auto last=std::remove_if(authorized_.begin(),authorized_.begin()+count_,[&](auto const& entry){return entry.token==token;});
            count_=static_cast<std::size_t>(last-authorized_.begin());
        }
        auto valid(ServerToken token) noexcept -> bool { auto entry=find(token.id); return entry!=entries_.end() && entry->token==token; }
    public:
        explicit ServerSessions(std::size_t limit) : limit_(std::min(limit,std::size_t{65535})) { entries_.reserve(limit_); }
        ServerSessions(ServerSessions const&)=delete;
        auto operator=(ServerSessions const&) -> ServerSessions& = delete;
        [[nodiscard]] auto size() const noexcept -> std::size_t { return entries_.size(); }
        [[nodiscard]] auto receive(Frame const& frame) -> ServerEvent {
            ServerEvent result; result.error=frame.error;
            if (closed_) { result.action=ServerAction::closed; return result; }
            if (frame.kind==Kind::keepalive) { result.action=ServerAction::ignored; return result; }
            auto entry=find(frame.session);
            if (frame.kind==Kind::open) {
                if (!frame.address) return result;
                // Accept non-zero 8-byte GlobalID as a normal local stream session:
                // mainstream XUDP clients always attach a GlobalID hash even without
                // cross-connection session migration.
                if (entry!=entries_.end()) { result.action=ServerAction::duplicate; return result; }
                if (entries_.size()>=limit_ || generation_==std::numeric_limits<std::uint64_t>::max()) { result.action=ServerAction::limit; return result; }
                ServerToken token{frame.session,++generation_}; entries_.push_back({token,*frame.address});
                result.action=ServerAction::opened; result.token=token; result.destination=frame.address;
            } else {
                if (entry==entries_.end()) { result.action=ServerAction::unknown; return result; }
                result.token=entry->token;
                if (frame.kind==Kind::end) { forget(entry->token); entries_.erase(entry); result.action=ServerAction::ended; return result; }
                if (frame.kind!=Kind::data) return result;
                if (!frame.has_data) { result.action=ServerAction::ignored; return result; }
                result.action=ServerAction::datagram; result.destination=frame.address ? frame.address : std::optional<Address>{entry->initial};
            }
            result.has_data=frame.has_data; result.payload=frame.payload; return result;
        }
        [[nodiscard]] auto sent(ServerToken token,Address const& destination) noexcept -> bool {
            if (closed_ || !valid(token) || serial_==std::numeric_limits<std::uint64_t>::max()) return false;
            auto last=authorized_.begin()+count_;
            auto entry=std::find_if(authorized_.begin(),last,[&](auto const& item){return item.token==token && item.destination==destination;});
            if (entry==last && count_==authorized_.size()) entry=std::min_element(authorized_.begin(),last,[](auto const& a,auto const& b){return a.serial<b.serial;});
            auto index=static_cast<std::size_t>(entry-authorized_.begin()); *entry={token,destination,++serial_}; if (index==count_) ++count_;
            return true;
        }
        [[nodiscard]] auto accepts(ServerToken token,Address const& source) noexcept -> bool {
            if (closed_ || !valid(token)) return false;
            auto last=authorized_.begin()+count_;
            return std::find_if(authorized_.begin(),last,[&](auto const& item){return item.token==token && item.destination==source;})!=last;
        }
        auto close() noexcept -> void { closed_=true; entries_.clear(); count_=0; }
    };
}
