export module xudp.client_io;
import std;
import xudp;
import xudp.client_sessions;
import nexus.thirdparty.capy;

export namespace xudp {
    enum class ClientIoError { closed, state, session, exhausted, protocol, transport };
    struct ClientEvent {
        Incoming action=Incoming::invalid;
        std::uint16_t session=0;
        std::optional<Address> source;
        std::vector<std::uint8_t> payload;
        bool error=false;
    };
    // Stream supplies write(span)->task<bool>, read(span)->task<expected<size_t,E>>
    // and cancel(). It and this owner must outlive all operations. One executor,
    // one reader and any number of serialized writers; cancel and drain before
    // destruction. Reply sources must match a successfully sent destination on
    // the same session; callers still enforce outbound routing policy.
    template<class Stream>
    class ClientIo {
        Stream& stream_;
        ClientSessions sessions_;
        Decoder decoder_;
        nex::capy::async_mutex mutex_;
        std::array<std::uint8_t,16384> input_{};
        std::size_t begin_=0,end_=0;
        bool closed_=false,reading_=false;
        auto fail(ClientIoError error) noexcept -> std::unexpected<ClientIoError> { cancel(); return std::unexpected(error); }
        auto write_pending(PendingFrame pending) -> nex::capy::task<bool> {
            auto bytes=encode(pending.frame);
            if (!bytes) { (void)sessions_.finish(pending.token,false); cancel(); co_return false; }
            bool written=co_await stream_.write(*bytes);
            auto committed=sessions_.finish(pending.token,written);
            if (!written || !committed || closed_) { cancel(); co_return false; }
            co_return true;
        }
    public:
        ClientIo(Stream& stream,std::size_t max_sessions,std::size_t max_payload=65535)
            : stream_(stream),sessions_(max_sessions),decoder_(max_payload) {}
        ClientIo(ClientIo const&)=delete;
        auto operator=(ClientIo const&) -> ClientIo& = delete;
        auto cancel() noexcept -> void {
            if (closed_) return;
            closed_=true; sessions_.close(); decoder_.close(); stream_.cancel();
        }
        [[nodiscard]] auto open(Address target,std::span<std::uint8_t const> payload)
            -> nex::capy::task<std::expected<std::uint16_t,ClientIoError>> {
            auto [error,guard]=co_await mutex_.scoped_lock();
            if (error || closed_) co_return std::unexpected(ClientIoError::closed);
            auto pending=sessions_.open(target,payload); if (!pending) co_return std::unexpected(pending.error()==SessionError::exhausted ? ClientIoError::exhausted : ClientIoError::session);
            auto id=pending->frame.session;
            try { if (!co_await write_pending(*pending)) co_return std::unexpected(ClientIoError::transport); }
            catch (...) { cancel(); throw; }
            co_return id;
        }
        [[nodiscard]] auto send(std::uint16_t id,std::optional<Address> target,std::span<std::uint8_t const> payload)
            -> nex::capy::task<std::expected<void,ClientIoError>> {
            auto [error,guard]=co_await mutex_.scoped_lock();
            if (error || closed_) co_return std::unexpected(ClientIoError::closed);
            auto pending=sessions_.send(id,target,payload); if (!pending) co_return std::unexpected(ClientIoError::session);
            try { if (!co_await write_pending(*pending)) co_return std::unexpected(ClientIoError::transport); }
            catch (...) { cancel(); throw; }
            co_return std::expected<void,ClientIoError>{};
        }
        [[nodiscard]] auto end(std::uint16_t id) -> nex::capy::task<std::expected<void,ClientIoError>> {
            auto [error,guard]=co_await mutex_.scoped_lock();
            if (error || closed_) co_return std::unexpected(ClientIoError::closed);
            auto pending=sessions_.end(id); if (!pending) co_return std::unexpected(ClientIoError::session);
            try { if (!co_await write_pending(*pending)) co_return std::unexpected(ClientIoError::transport); }
            catch (...) { cancel(); throw; }
            co_return std::expected<void,ClientIoError>{};
        }
        // One event per call; frame bytes after it remain buffered. Payload is
        // copied so the decoder can accept the next frame immediately.
        [[nodiscard]] auto read() -> nex::capy::task<std::expected<ClientEvent,ClientIoError>> {
            if (closed_) co_return std::unexpected(ClientIoError::closed);
            if (reading_) co_return std::unexpected(ClientIoError::state);
            reading_=true;
            try {
                for (;;) {
                    if (begin_==end_) {
                        auto result=co_await stream_.read(input_);
                        if (!result || !*result || *result>input_.size() || closed_) { reading_=false; co_return fail(ClientIoError::transport); }
                        begin_=0; end_=*result;
                    }
                    auto parsed=decoder_.feed(std::span(input_).subspan(begin_,end_-begin_)); begin_+=parsed.consumed;
                    if (parsed.status==Status::incomplete && parsed.consumed) continue;
                    if (parsed.status!=Status::ready) { reading_=false; co_return fail(ClientIoError::protocol); }
                    auto [error,guard]=co_await mutex_.scoped_lock();
                    if (error || closed_) { reading_=false; co_return fail(ClientIoError::closed); }
                    auto frame=decoder_.frame(); if (!frame) { reading_=false; co_return fail(ClientIoError::protocol); }
                    auto event=sessions_.receive(*frame);
                    if (event.action==Incoming::unknown && frame->kind==Kind::data && frame->has_data) {
                        auto close_frame=encode(Frame{frame->session,Kind::end});
                        if (!close_frame || !co_await stream_.write(*close_frame)) { reading_=false; co_return fail(ClientIoError::transport); }
                    }
                    ClientEvent out{event.action,event.session,event.address,{},event.error};
                    if (event.action==Incoming::datagram) out.payload.assign(event.payload.begin(),event.payload.end());
                    if (!decoder_.consume()) { reading_=false; co_return fail(ClientIoError::protocol); }
                    if (event.action==Incoming::invalid) { reading_=false; co_return fail(ClientIoError::protocol); }
                    if (event.action==Incoming::datagram || event.action==Incoming::ended) { reading_=false; co_return out; }
                }
            } catch (...) { reading_=false; cancel(); throw; }
        }
    };
}
