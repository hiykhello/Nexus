export module tailscale.map_session;
import std;
import tailscale.control_messages;
import tailscale.control_http;
import tailscale.snapshot;
import tailscale.packet_filter;
import tailscale.magic_dns;

export namespace tailscale::map_session {
    namespace cm=control_messages;namespace ch=control_http;namespace sn=snapshot;namespace pf=packet_filter;namespace md=magic_dns;
    enum class Error { state,frame,parse,snapshot,policy,exhausted };
    struct Result {std::size_t consumed=0;std::optional<Error> error;};

    // Non-installable Map projection. `ready` only means an initial peer view
    // and explicit rule update were received. It does not establish identity,
    // TKA, routing, stateful filtering, or authorize any network operation.
    // Views are valid only until the next feed, EOF, stop, or destruction.
    // No operation or view can be used concurrently with an update.
    class State {
        sn::Snapshot snapshot_;
        pf::Filter filter_;
        cm::DerpNodes derp_;
        std::optional<md::DnsConfig> dns_;
        std::uint64_t revision_=0;
        friend class Session;
        auto begin(cm::DecodeOrigin const& origin) noexcept -> bool {
            if(!snapshot_.begin(origin))return false;
            filter_.clear();derp_.clear();dns_.reset();revision_=0;return true;
        }
        auto revoke() noexcept -> void {snapshot_.stop();filter_.clear();derp_.clear();dns_.reset();revision_=0;}
    public:
        State()=default;
        State(State const&)=delete;
        auto operator=(State const&) -> State& = delete;
        auto ready() const noexcept -> bool {return snapshot_.ready() && filter_.received();}
        auto peers() const noexcept -> std::span<sn::Peer const> {return ready() ? snapshot_.peers() : std::span<sn::Peer const>{};}
        auto self() const noexcept -> sn::Peer const* {return ready() ? snapshot_.self() : nullptr;}
        auto revision() const noexcept -> std::uint64_t {return ready() ? revision_ : 0;}
        auto derp_nodes() const noexcept -> std::span<cm::DerpNode const> {
            return ready() ? std::span<cm::DerpNode const>(derp_) : std::span<cm::DerpNode const>{};
        }
        auto dns_config() const noexcept -> md::DnsConfig const* {
            return ready() && dns_ ? &*dns_ : nullptr;
        }
        auto sync_magic_dns(md::Resolver& resolver) const -> void {
            if (!ready()) { resolver.clear(); return; }
            md::DnsConfig cfg = dns_.value_or(md::DnsConfig{});
            (void)resolver.update(std::move(cfg), peers(), self());
        }
        auto matches(pf::Address const& source, pf::Address const& target, std::uint8_t protocol,
                     std::uint16_t port) const noexcept -> bool {
            return ready() && filter_.matches(source, target, protocol, port);
        }
        auto policy_chunks() const noexcept -> std::span<pf::Chunk const> {return ready() ? filter_.chunks() : std::span<pf::Chunk const>{};}
    };

    // One owner per Map stream, serialized on one executor. The frame backing
    // storage, candidate, state and scratch must outlive the Session destructor,
    // even after stop/eof/error; they are exclusive while active. Feed input
    // must not overlap frame storage. Feed before consuming H2 stream data;
    // on error do not consume the failing chunk and cancel/reset and drain.
    // Reset/release may reclaim discarded bytes as connection-level credit.
    class Session {
        cm::DecodeOrigin origin_;
        ch::MapFrameDecoder decoder_;
        cm::MapCandidate& candidate_;
        State& state_;
        sn::Scratch& scratch_;
        std::uint64_t ordinal_=0;
        bool active_=false;
        static auto value(cm::JsonField field) noexcept -> std::optional<std::string_view> {
            return field.presence==cm::Presence::value ? std::optional(field.json) : std::nullopt;
        }
        auto fail(Error error,std::size_t consumed) noexcept -> Result {
            decoder_.close();candidate_.clear();scratch_.peers.clear();state_.revoke();active_=false;return {consumed,error};
        }
    public:
        Session(cm::DecodeOrigin origin,std::span<std::uint8_t> frame,cm::MapCandidate& candidate,State& state,sn::Scratch& scratch) noexcept
          :origin_(origin),decoder_(frame),candidate_(candidate),state_(state),scratch_(scratch) {
            active_=state_.begin(origin_);if(active_) {candidate_.clear();scratch_.peers.clear();}
        }
        Session(Session const&)=delete;
        auto operator=(Session const&) -> Session& = delete;
        ~Session() {stop();}
        auto stop() noexcept -> void {if(active_) {decoder_.close();candidate_.clear();scratch_.peers.clear();state_.revoke();active_=false;}}
        auto active() const noexcept -> bool {return active_;}
        auto ordinal() const noexcept -> std::uint64_t {return ordinal_;}
        auto feed(std::span<std::uint8_t const> bytes) noexcept -> Result {
            if(!active_)return {0,Error::state};std::size_t total=0;
            while(!bytes.empty()) {
                auto part=decoder_.feed(bytes);total+=part.consumed;bytes=bytes.subspan(part.consumed);
                if(part.error)return fail(Error::frame,total);
                if(part.ready) {
                    auto payload=decoder_.payload();cm::FilterFields fields;
                    if(!payload || !cm::parse_map_projection(*payload,origin_,candidate_,fields))return fail(Error::parse,total);
                    auto view=candidate_.view();if(!view || ordinal_==std::numeric_limits<std::uint64_t>::max())return fail(Error::exhausted,total);
                    auto applied=state_.snapshot_.apply(*view,++ordinal_,scratch_);scratch_.peers.clear();
                    if(!applied)return fail(Error::snapshot,total);
                    if(!state_.filter_.update(value(fields.legacy),value(fields.named)))return fail(Error::policy,total);
                    auto relays=cm::derp_nodes(view->derp_map);
                    if(!relays)return fail(Error::parse,total);
                    if(*relays)state_.derp_=std::move(**relays);
                    auto dns=md::parse_dns_config(view->dns_config,view->domain);
                    if(!dns)return fail(Error::parse,total);
                    if(*dns)state_.dns_=std::move(**dns);
                    if (!view->keep_alive) state_.revision_=ordinal_;
                    candidate_.clear();if(!decoder_.consume())return fail(Error::frame,total);
                } else if(!part.consumed)return fail(Error::frame,total);
            }
            return {total,{}};
        }
        // EOF, including a clean frame boundary, revokes the entire stream.
        auto eof() noexcept -> std::expected<void,Error> {
            if(!active_)return std::unexpected(Error::state);
            auto ok=decoder_.eof();candidate_.clear();scratch_.peers.clear();state_.revoke();active_=false;
            if(!ok)return std::unexpected(Error::frame);return {};
        }
    };
}
