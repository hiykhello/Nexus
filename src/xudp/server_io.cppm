module;
#if defined(__linux__)
#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <boost/corosio/posix_stream_descriptor.hpp>
#include <boost/corosio/wait_type.hpp>
#endif
export module xudp.server_io;
import std;
import platform.socket_options;
import xudp;
import xudp.server_sessions;
import xudp.server_direct;
import net.udp_socket;
import rules;
import capy;
import corosio;

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
        capy::async_mutex mutex_;
        capy::async_event activity_wake_;
#if defined(__linux__)
        int ep_=-1,wake_rd_=-1,wake_wr_=-1;
        bool epoll_failed_=false;
        std::vector<int> watched_fds_;
        std::optional<corosio::posix_stream_descriptor> ep_desc_;
        auto init_epoll(corosio::io_context& ctx) noexcept -> void {
            if (ep_>=0 || closed_ || epoll_failed_) return;
            ep_=::epoll_create1(EPOLL_CLOEXEC);
            if (ep_<0) { epoll_failed_=true; return; }
            int pfds[2]{-1,-1};
            if (::pipe2(pfds,O_NONBLOCK|O_CLOEXEC)==0) {
                wake_rd_=pfds[0]; wake_wr_=pfds[1];
                epoll_event ev{.events=EPOLLIN,.data={.fd=wake_rd_}};
                if (::epoll_ctl(ep_,EPOLL_CTL_ADD,wake_rd_,&ev)!=0) { ::close(wake_rd_); ::close(wake_wr_); wake_rd_=wake_wr_=-1; }
            }
            ep_desc_.emplace(ctx);
            if (ep_desc_->assign(ep_)) {
                ep_desc_.reset(); ::close(ep_); ep_=-1;
                if (wake_rd_>=0) { ::close(wake_rd_); wake_rd_=-1; }
                if (wake_wr_>=0) { ::close(wake_wr_); wake_wr_=-1; }
                epoll_failed_=true;
            }
        }
        auto sync_epoll() -> void {
            if (ep_<0) return;
            std::vector<int> cur;
            direct_.for_each_fd([&](int fd){ cur.push_back(fd); });
            std::ranges::sort(cur);
            for (int old_fd : watched_fds_)
                if (!std::ranges::binary_search(cur,old_fd)) (void)::epoll_ctl(ep_,EPOLL_CTL_DEL,old_fd,nullptr);
            for (int fd : cur) {
                epoll_event ev{.events=EPOLLIN,.data={.fd=fd}};
                (void)::epoll_ctl(ep_,EPOLL_CTL_ADD,fd,&ev); // EEXIST for unchanged fds; registers reused fd numbers
            }
            watched_fds_=std::move(cur);
        }
#endif
        auto notify_activity() noexcept -> void {
            activity_wake_.set();
#if defined(__linux__)
            if (wake_wr_>=0) { char b=1; (void)::write(wake_wr_,&b,1); }
#endif
        }
        std::array<std::uint8_t,16384> input_{};
        std::array<std::uint8_t,65535> output_{};
        std::size_t begin_=0,end_=0;
        bool closed_=false,reading_=false,polling_=false,expiring_=false;
        struct OpGuard {
            ServerIo& self; bool& flag; bool ok = false;
            ~OpGuard() { flag = false; if (!ok) self.cancel(); }
        };
        auto fail(ServerIoError error) noexcept -> std::unexpected<ServerIoError> { cancel(); return std::unexpected(error); }
        auto write_end(std::uint16_t id,bool error) -> capy::task<bool> {
            auto wire=encode(Frame{id,Kind::end,false,error});
            if (!wire) co_return false;
            co_return co_await stream_.write(*wire);
        }
        static auto literal(Address const& address) noexcept -> net::UdpEndpoint {
            net::UdpEndpoint peer{address.family==Family::ipv4 ? std::uint8_t{4} : std::uint8_t{6},{},address.port};
            std::copy_n(address.bytes.begin(),address.length,peer.address.begin()); return peer;
        }
    public:
        ServerIo(Stream& stream,Resolver& resolver,::rules::RouteProgram const& policy,std::size_t sessions,std::size_t max_payload=65535,
                 net::UdpEndpoint const* source=nullptr,std::optional<std::string_view> auth_user={},
                 ::platform::SocketBinding const* binding=nullptr,Accounting accounting={})
            : stream_(stream),resolver_(resolver),direct_(policy,sessions,source,auth_user,binding),decoder_(max_payload),
              accounting_(std::move(accounting)) {}
        ServerIo(ServerIo const&)=delete;
        auto operator=(ServerIo const&) -> ServerIo& = delete;
        auto cancel() noexcept -> void {
            if (closed_) return; closed_=true;
            notify_activity();
#if defined(__linux__)
            if (ep_desc_) ep_desc_->close();
            watched_fds_.clear();
            if (wake_rd_>=0) { ::close(wake_rd_); wake_rd_=-1; }
            if (wake_wr_>=0) { ::close(wake_wr_); wake_wr_=-1; }
#endif
            direct_.close(); accounting_.close(); decoder_.close(); resolver_.cancel(); stream_.cancel();
        }
        ~ServerIo() {
#if defined(__linux__)
            if (ep_desc_) { ep_desc_->close(); ep_desc_.reset(); }
            if (wake_rd_>=0) ::close(wake_rd_);
            if (wake_wr_>=0) ::close(wake_wr_);
#endif
        }
        // Consumes exactly one frame; stream tail remains buffered. Resolving
        // can suspend, so the decoder retains the frame until delivery finishes.
        [[nodiscard]] auto read_one() -> capy::task<std::expected<void,ServerIoError>> {
            if (closed_) co_return std::unexpected(ServerIoError::closed);
            if (reading_) co_return std::unexpected(ServerIoError::state);
            reading_=true; OpGuard og{*this, reading_};
            while (true) {
                if (begin_==end_) {
                    auto n=co_await stream_.read(input_);
                    if (!n || !*n || *n>input_.size() || closed_) co_return fail(ServerIoError::transport);
                    begin_=0; end_=*n;
                }
                auto parsed=decoder_.feed(std::span(input_).subspan(begin_,end_-begin_)); begin_+=parsed.consumed;
                if (parsed.status==Status::incomplete && parsed.consumed) continue;
                if (parsed.status!=Status::ready) co_return fail(ServerIoError::protocol);
                auto frame=decoder_.frame(); if (!frame) co_return fail(ServerIoError::protocol);
                ServerEvent event;
                {
                    auto [error,guard]=co_await mutex_.scoped_lock();
                    if (error || closed_) co_return fail(ServerIoError::closed);
                    event=direct_.receive(*frame);
                    notify_activity();
                    if (event.action==ServerAction::opened && !accounting_.opened(event.token,*event.destination)) {
                        (void)direct_.receive(Frame{event.token.id,Kind::end});
                        event.action=ServerAction::limit;
                    }
                    if (event.action==ServerAction::ended) accounting_.retired(event.token);
                    if (event.action==ServerAction::duplicate || event.action==ServerAction::invalid || event.action==ServerAction::closed)
                        co_return fail(ServerIoError::protocol);
                    bool reject=event.action==ServerAction::limit || event.action==ServerAction::unsupported;
                    bool unknown=event.action==ServerAction::unknown && frame->kind==Kind::data;
                    if ((reject || unknown) && !co_await write_end(frame->session,reject)) co_return fail(ServerIoError::transport);
                }
                if ((event.action==ServerAction::opened || event.action==ServerAction::datagram) && event.has_data) {
                    if (!event.destination) co_return fail(ServerIoError::protocol);
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
                            if (error || closed_) co_return fail(ServerIoError::closed);
                            if (!direct_.contains(event.token)) { expired=true; break; }
                            auto credit=reserve(true,event.payload.size());
                            if (!credit) {denied=true;break;}
                            auto result=direct_.send(event.token,*event.destination,candidate,event.payload);
                            notify_activity();
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
                            auto [delay_error]=co_await corosio::delay(std::chrono::milliseconds(5));
                            if (delay_error || closed_) co_return fail(ServerIoError::closed);
                        }
                        if (sent || expired || denied) break;
                    }
                    if (!sent && !denied) {
                        auto [error,guard]=co_await mutex_.scoped_lock();
                        if (error || closed_) co_return fail(ServerIoError::closed);
                        if (direct_.contains(event.token)) {
                            (void)direct_.receive(Frame{event.token.id,Kind::end});
                            accounting_.retired(event.token);
                            if (!co_await write_end(event.token.id,true)) co_return fail(ServerIoError::transport);
                        }
                    }
                }
                if (!decoder_.consume()) co_return fail(ServerIoError::protocol);
                og.ok=true; co_return std::expected<void,ServerIoError>{};
            }
        }
        // The owner schedules this periodically; one call removes at most one
        // idle session and serializes its end with all other stream writes.
        [[nodiscard]] auto expire_one(std::chrono::steady_clock::time_point now,std::chrono::steady_clock::duration idle)
            -> capy::task<std::expected<bool,ServerIoError>> {
            if (closed_) co_return std::unexpected(ServerIoError::closed);
            if (expiring_) co_return std::unexpected(ServerIoError::state);
            expiring_=true; OpGuard og{*this, expiring_};
            auto [error,guard]=co_await mutex_.scoped_lock();
            if (error || closed_) co_return fail(ServerIoError::closed);
            auto token=direct_.expire_one(now,idle);
            if (token) {
                accounting_.retired(*token);
                if (!co_await write_end(token->id,false)) co_return fail(ServerIoError::transport);
            }
            og.ok=true; co_return bool(token);
        }
        // A true result means one datagram was consumed, including a rejected
        // source. The mutex covers poll and write so an end/reopen cannot pass
        // an old reply while a partial write is outstanding.
        [[nodiscard]] auto poll_one() -> capy::task<std::expected<bool,ServerIoError>> {
            if (closed_) co_return std::unexpected(ServerIoError::closed);
            if (polling_) co_return std::unexpected(ServerIoError::state);
            polling_=true; OpGuard og{*this, polling_};
            auto [error,guard]=co_await mutex_.scoped_lock();
            if (error || closed_) co_return fail(ServerIoError::closed);
            if (auto token=accounting_.close_requested()) {
                (void)direct_.receive(Frame{token->id,Kind::end});
                accounting_.retired(*token);
                if (!co_await write_end(token->id,false)) co_return fail(ServerIoError::transport);
                og.ok=true; co_return true;
            }
            bool dropped=false; auto reply=direct_.poll(output_,&dropped);
            if (!reply) co_return fail(ServerIoError::transport);
            if (!*reply) { og.ok=true; co_return dropped; }
            auto const& packet=**reply;
            auto credit=reserve(false,packet.size);
            if (!credit) { og.ok=true; co_return true; }
            auto wire=encode(Frame{packet.token.id,Kind::data,true,false,packet.source,{},std::span(output_).first(packet.size)});
            if (!wire) co_return fail(ServerIoError::transport);
            credit->submit();
            if (!co_await stream_.write(*wire)) co_return fail(ServerIoError::transport);
            credit->complete(packet.size);
            accounting_.delivered(packet.token,false,packet.size);
            og.ok=true; co_return true;
        }
        [[nodiscard]] auto has_sessions() const noexcept -> bool { return !direct_.empty(); }
        [[nodiscard]] auto wait_activity(std::chrono::steady_clock::time_point until) -> capy::task<bool> {
            if (closed_) co_return false;
#if defined(__linux__)
            if constexpr (requires { resolver_.context; }) {
                init_epoll(resolver_.context);
                if (ep_desc_) {
                    sync_epoll();
                    (void)co_await corosio::timeout(ep_desc_->wait(corosio::wait_type::read), until);
                    if (wake_rd_>=0) { std::array<char,64> b{}; while (::read(wake_rd_,b.data(),b.size())>0) {} }
                    co_return !closed_;
                }
            }
#endif
            activity_wake_.clear();
            (void)co_await corosio::timeout(activity_wake_.wait(), until);
            co_return !closed_;
        }
    };
}
