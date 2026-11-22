export module xudp.server_io;
import std;
import platform.socket_options;
import xudp;
import xudp.server_sessions;
import xudp.server_direct;
import net.udp_socket;
import rules;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace xudp {
    enum class ServerIoError { closed, state, protocol, transport };
    // Stream provides read(span), write(span), cancel(); resolver provides
    // resolve(Address)->task<expected<vector<net::UdpEndpoint>,E>> and cancel(). One
    // executor, one reader, one poller; cancel and drain both before destruction.
    // The owner drives poll_one repeatedly and enforces idle/resolve deadlines.
    struct NoServerAccounting {
        auto opened(ServerToken,Address const&) noexcept -> bool {return true;}
        auto close_requested() const noexcept -> std::optional<ServerToken> {return {};}
        auto retired(ServerToken) noexcept -> void {}
        auto delivered(ServerToken,bool,std::size_t) noexcept -> void {}
        auto close() noexcept -> void {}
    };
    template<class Stream,class Resolver,class Direct=ServerDirect,class Accounting=NoServerAccounting>
    class ServerIo {
        Stream& stream_; Resolver& resolver_;
        Direct direct_; Decoder decoder_;
        [[no_unique_address]] Accounting accounting_;
        struct Unmetered {
            auto submit() noexcept -> void {}
            auto complete(std::size_t) noexcept -> void {}
        };
        auto reserve(bool upstream,std::size_t size) {
            if constexpr (requires {accounting_.reserve(upstream,size);}) return accounting_.reserve(upstream,size);
            else return std::optional<Unmetered>(std::in_place);
        }
        nex::capy::async_mutex mutex_;
        std::array<std::uint8_t,16384> input_{};
        std::array<std::uint8_t,65535> output_{};
        std::size_t begin_=0,end_=0;
        bool closed_=false,reading_=false,polling_=false,expiring_=false;
        auto fail(ServerIoError error) noexcept -> std::unexpected<ServerIoError> { cancel(); return std::unexpected(error); }
        auto write_end(std::uint16_t id,bool error) -> nex::capy::task<bool> {
            auto wire=encode(Frame{id,Kind::end,false,error});
            if (!wire) co_return false;
            co_return co_await stream_.write(*wire);
        }
        static auto literal(Address const& address) noexcept -> net::UdpEndpoint {
            net::UdpEndpoint peer{address.family==Family::ipv4 ? std::uint8_t{4} : std::uint8_t{6},{},address.port};
            std::copy_n(address.bytes.begin(),address.length,peer.address.begin()); return peer;
        }
    public:
        ServerIo(Stream& stream,Resolver& resolver,::rules::RouteMatcher const& policy,std::size_t sessions,std::size_t max_payload=65535,
                 net::UdpEndpoint const* source=nullptr,std::optional<std::string_view> auth_user={},
                 ::platform::SocketBinding const* binding=nullptr,Accounting accounting={})
            : stream_(stream),resolver_(resolver),direct_(policy,sessions,source,auth_user,binding),decoder_(max_payload),
              accounting_(std::move(accounting)) {}
        ServerIo(ServerIo const&)=delete;
        auto operator=(ServerIo const&) -> ServerIo& = delete;
        auto cancel() noexcept -> void {
            if (closed_) return; closed_=true; direct_.close(); accounting_.close(); decoder_.close(); resolver_.cancel(); stream_.cancel();
        }
        // Consumes exactly one frame; stream tail remains buffered. Resolving
        // can suspend, so the decoder retains the frame until delivery finishes.
        [[nodiscard]] auto read_one() -> nex::capy::task<std::expected<void,ServerIoError>> {
            if (closed_) co_return std::unexpected(ServerIoError::closed);
            if (reading_) co_return std::unexpected(ServerIoError::state);
            reading_=true;
            try {
                while (true) {
                    if (begin_==end_) {
                        auto n=co_await stream_.read(input_);
                        if (!n || !*n || *n>input_.size() || closed_) { reading_=false; co_return fail(ServerIoError::transport); }
                        begin_=0; end_=*n;
                    }
                    auto parsed=decoder_.feed(std::span(input_).subspan(begin_,end_-begin_)); begin_+=parsed.consumed;
                    if (parsed.status==Status::incomplete && parsed.consumed) continue;
                    if (parsed.status!=Status::ready) { reading_=false; co_return fail(ServerIoError::protocol); }
                    auto frame=decoder_.frame(); if (!frame) { reading_=false; co_return fail(ServerIoError::protocol); }
                    ServerEvent event;
                    {
                        auto [error,guard]=co_await mutex_.scoped_lock();
                        if (error || closed_) { reading_=false; co_return fail(ServerIoError::closed); }
                        event=direct_.receive(*frame);
                        if (event.action==ServerAction::opened && !accounting_.opened(event.token,*event.destination)) {
                            (void)direct_.receive(Frame{event.token.id,Kind::end});
                            event.action=ServerAction::limit;
                        }
                        if (event.action==ServerAction::ended) accounting_.retired(event.token);
                        if (event.action==ServerAction::duplicate || event.action==ServerAction::invalid || event.action==ServerAction::closed) {
                            reading_=false; co_return fail(ServerIoError::protocol);
                        }
                        bool reject=event.action==ServerAction::limit || event.action==ServerAction::unsupported;
                        bool unknown=event.action==ServerAction::unknown && frame->kind==Kind::data;
                        if ((reject || unknown) && !co_await write_end(frame->session,reject)) { reading_=false; co_return fail(ServerIoError::transport); }
                    }
                    if ((event.action==ServerAction::opened || event.action==ServerAction::datagram) && event.has_data) {
                        if (!event.destination) { reading_=false; co_return fail(ServerIoError::protocol); }
                        auto allowed=direct_.preflight(*event.destination);
                        std::vector<net::UdpEndpoint> candidates;
                        if (allowed) {
                            if (event.destination->family==Family::domain) {
                                auto resolved=co_await resolver_.resolve(*event.destination);
                                if (resolved) candidates=std::move(*resolved);
                            } else candidates.push_back(literal(*event.destination));
                        }
                        bool sent=false,expired=false,denied=false;
                        // Bound candidate work and retain the decoder's payload during
                        // transient UDP backpressure. Never hold the write mutex
                        // across the delay: replies and cancellation must progress.
                        unsigned retries=0;
                        for (auto candidate:std::span(candidates).first(std::min(candidates.size(),std::size_t{64}))) {
                            while (!closed_) {
                                bool retry=false;
                                {
                                auto [error,guard]=co_await mutex_.scoped_lock();
                                if (error || closed_) { reading_=false; co_return fail(ServerIoError::closed); }
                                if (!direct_.contains(event.token)) { expired=true; break; }
                                auto credit=reserve(true,event.payload.size());
                                if (!credit) {denied=true;break;}
                                auto result=direct_.send(event.token,*event.destination,candidate,event.payload);
                                if (result) {
                                    credit->complete(event.payload.size());
                                    accounting_.delivered(event.token,true,event.payload.size());
                                    sent=true;
                                    break;
                                }
                                auto code=std::get_if<std::error_code>(&result.error());
                                retry=code && (*code==std::errc::resource_unavailable_try_again || *code==std::errc::operation_would_block || *code==std::errc::interrupted);
                                }
                                if (!retry || retries++>=100) break;
                                auto [delay_error]=co_await nex::corosio::delay(std::chrono::milliseconds(5));
                                if (delay_error || closed_) { reading_=false; co_return fail(ServerIoError::closed); }
                            }
                            if (sent || expired || denied) break;
                        }
                        if (!sent && !denied) {
                            auto [error,guard]=co_await mutex_.scoped_lock();
                            if (error || closed_) { reading_=false; co_return fail(ServerIoError::closed); }
                            if (direct_.contains(event.token)) {
                                (void)direct_.receive(Frame{event.token.id,Kind::end});
                                accounting_.retired(event.token);
                                if (!co_await write_end(event.token.id,true)) { reading_=false; co_return fail(ServerIoError::transport); }
                            }
                        }
                    }
                    if (!decoder_.consume()) { reading_=false; co_return fail(ServerIoError::protocol); }
                    reading_=false; co_return std::expected<void,ServerIoError>{};
                }
            } catch (...) { reading_=false; cancel(); throw; }
        }
        // The owner schedules this periodically; one call removes at most one
        // idle session and serializes its end with all other stream writes.
        [[nodiscard]] auto expire_one(std::chrono::steady_clock::time_point now,std::chrono::steady_clock::duration idle)
            -> nex::capy::task<std::expected<bool,ServerIoError>> {
            if (closed_) co_return std::unexpected(ServerIoError::closed);
            if (expiring_) co_return std::unexpected(ServerIoError::state);
            expiring_=true;
            try {
                auto [error,guard]=co_await mutex_.scoped_lock();
                if (error || closed_) { expiring_=false; co_return fail(ServerIoError::closed); }
                auto token=direct_.expire_one(now,idle);
                if (token) {
                    accounting_.retired(*token);
                    if (!co_await write_end(token->id,false)) {expiring_=false;co_return fail(ServerIoError::transport);}
                }
                expiring_=false; co_return bool(token);
            } catch (...) { expiring_=false; cancel(); throw; }
        }
        // A true result means one datagram was consumed, including a rejected
        // source. The mutex covers poll and write so an end/reopen cannot pass
        // an old reply while a partial write is outstanding.
        [[nodiscard]] auto poll_one() -> nex::capy::task<std::expected<bool,ServerIoError>> {
            if (closed_) co_return std::unexpected(ServerIoError::closed);
            if (polling_) co_return std::unexpected(ServerIoError::state);
            polling_=true;
            try {
                auto [error,guard]=co_await mutex_.scoped_lock();
                if (error || closed_) { polling_=false; co_return fail(ServerIoError::closed); }
                if (auto token=accounting_.close_requested()) {
                    (void)direct_.receive(Frame{token->id,Kind::end});
                    accounting_.retired(*token);
                    if (!co_await write_end(token->id,false)) {polling_=false;co_return fail(ServerIoError::transport);}
                    polling_=false;
                    co_return true;
                }
                bool dropped=false; auto reply=direct_.poll(output_,&dropped);
                if (!reply) { polling_=false; co_return fail(ServerIoError::transport); }
                if (!*reply) { polling_=false; co_return dropped; }
                auto const& packet=**reply;
                auto credit=reserve(false,packet.size);
                if (!credit) {polling_=false;co_return true;}
                auto wire=encode(Frame{packet.token.id,Kind::data,true,false,packet.source,{},std::span(output_).first(packet.size)});
                if (!wire) {polling_=false;co_return fail(ServerIoError::transport);}
                credit->submit();
                if (!co_await stream_.write(*wire)) {polling_=false;co_return fail(ServerIoError::transport);}
                credit->complete(packet.size);
                accounting_.delivered(packet.token,false,packet.size);
                polling_=false; co_return true;
            } catch (...) { polling_=false; cancel(); throw; }
        }
    };
}
