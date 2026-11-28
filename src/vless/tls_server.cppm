export module vless.tls_server;
import std;
export import functional;
import vless;
import httpupgrade;
import httpupgrade.stream;
import websocket.stream;
import tls.corosio_application;
import tls.application_io;
import tls.byte_stream;
import capy;
import corosio;
export namespace vless::detail {
    enum class TlsInboundError { state,rejected,io,timeout };
    using InboundRequest=std::variant<TcpRequest,UserId>;
    struct EmptyInboundConnection {};
    struct EmptyInboundWriter {};
    // Ordinary VLESS uses one direct ByteStream. The static Vision path keeps
    // its original reader/writer until handoff and never owns a ByteStream.
    template<class Socket,bool Vision=false,class PlainStream=websocket::VlessByteStream<Socket>>
    class TlsInbound {
        using Connection=tls::detail::ApplicationConnection<Socket>;
        using ConnectionRef=std::conditional_t<Vision,Connection*,EmptyInboundConnection>;
        using Stream=std::conditional_t<Vision,tls::detail::ApplicationStreamReader<Socket>,PlainStream>;
        using Writer=std::conditional_t<Vision,capy::async_mutex,EmptyInboundWriter>;
        using ReadTask=capy::task<std::expected<std::size_t,tls::detail::ByteStreamError>>;
        [[no_unique_address]] ConnectionRef connection_;
        Stream stream_;
        ServerHandshake handshake_;
        [[no_unique_address]] Writer writer_;
        std::array<std::uint8_t,4096> buffer_{};
        std::size_t begin_=0,end_=0;
        bool busy_=false,accepted_=false,failed_=false,upgraded_=false;
        struct OperationGuard {
            TlsInbound& owner; bool released=false;
            ~OperationGuard() { owner.busy_=false; if (!released) owner.cancel(); }
        };
        static auto retain(Connection& connection) noexcept -> ConnectionRef {
            if constexpr (Vision) return &connection; else return {};
        }
        auto fail(TlsInboundError error) noexcept -> std::unexpected<TlsInboundError> { cancel(); return std::unexpected(error); }
        auto receive(std::span<std::uint8_t> output,tls::detail::ApplicationDeadline deadline)
            -> capy::task<std::expected<std::size_t,TlsInboundError>> {
            if constexpr (!Vision) {
                auto result=co_await stream_.read(output,deadline);
                if (!result) co_return fail(TlsInboundError::io); co_return *result;
            } else for (;;) {
                auto result=co_await stream_.read_some(output,deadline);
                if (!result) co_return fail(TlsInboundError::io);
                if (result->kind==tls::detail::AsyncStreamReadKind::data) co_return result->size;
                if (result->kind==tls::detail::AsyncStreamReadKind::eof || (result->event && result->event->kind==tls::ApplicationEventKind::close_notify)) co_return 0;
                if (result->event && (result->event->kind==tls::ApplicationEventKind::fatal_alert || result->event->kind==tls::ApplicationEventKind::user_canceled)) co_return fail(TlsInboundError::io);
                if (result->kind==tls::detail::AsyncStreamReadKind::backpressure || (result->event && result->event->kind==tls::ApplicationEventKind::key_update_requested)) {
                    auto operation=writer_.scoped_lock();
                    auto [error,guard]=deadline ? co_await corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
                    if (error || failed_) co_return fail(TlsInboundError::io);
                    while (connection_->pending_output()) {
                        if (!co_await connection_->flush(deadline) || failed_) co_return fail(TlsInboundError::io);
                    }
                }
            }
        }
        static auto reject_send() -> capy::task<bool> { co_return false; }
        class ReadResult {
            TlsInbound* owner_=nullptr;
            std::span<std::uint8_t> output_;
            std::optional<ReadTask> operation_;
            std::size_t buffered_=0;
            bool started_=false,done_=false;
        public:
            ReadResult()=default;
            ReadResult(TlsInbound& owner,std::span<std::uint8_t> output,std::optional<ReadTask>&& operation,std::size_t buffered)
                : owner_(&owner),output_(output),operation_(std::move(operation)),buffered_(buffered) {}
            ReadResult(ReadResult const&)=delete;
            ReadResult(ReadResult&& other) noexcept
                : owner_(std::exchange(other.owner_,nullptr)),output_(other.output_),operation_(std::move(other.operation_)),buffered_(other.buffered_),
                  started_(other.started_),done_(other.done_) {}
            ~ReadResult() { if (owner_ && !done_) { owner_->busy_=false; if (started_) owner_->cancel(); } }
            auto await_ready() const noexcept -> bool { return !operation_ || operation_->await_ready(); }
            template<class Context>
            auto await_suspend(std::coroutine_handle<> continuation,Context const* context) {
                started_=true; return operation_->await_suspend(continuation,context);
            }
            auto await_resume() -> std::expected<std::size_t,TlsInboundError> {
                done_=true;
                if (!owner_) return std::unexpected(TlsInboundError::state);
                owner_->busy_=false;
                try {
                    if (owner_->failed_) return owner_->fail(TlsInboundError::io);
                    if (buffered_) {
                        std::copy_n(owner_->buffer_.begin()+owner_->begin_,buffered_,output_.begin()); owner_->begin_+=buffered_; return buffered_;
                    }
                    auto result=operation_->await_resume();
                    if (!result || *result>output_.size() || owner_->failed_) return owner_->fail(TlsInboundError::io);
                    return *result;
                } catch (...) { owner_->cancel(); throw; }
            }
        };
    public:
        TlsInbound(Connection& connection,ServerHandshake handshake) requires std::constructible_from<Stream,Connection&>
            : connection_(retain(connection)),stream_(connection),handshake_(std::move(handshake)),failed_(handshake_.is_vision()!=Vision) {}
        TlsInbound(PlainStream stream,ServerHandshake handshake) requires (!Vision && std::is_reference_v<PlainStream>)
            : connection_{},stream_(stream),handshake_(std::move(handshake)),failed_(handshake_.is_vision()) {}
        TlsInbound(TlsInbound const&)=delete;
        auto operator=(TlsInbound const&) -> TlsInbound& = delete;
        auto cancel() noexcept -> void { failed_=true; if constexpr (Vision) connection_->cancel(); else stream_.cancel(); }
        [[nodiscard]] auto vision_enabled() const noexcept -> bool { return Vision && handshake_.is_vision(); }
        [[nodiscard]] auto allow_mux() noexcept -> bool { return !failed_ && !busy_ && handshake_.allow_mux(); }
        auto upgrade(httpupgrade::Profile const& profile,std::chrono::steady_clock::time_point deadline)
            -> capy::task<std::expected<std::size_t,httpupgrade::Failure>> {
            if constexpr (Vision || !requires(Stream& stream) {stream.prepend_owned(std::vector<std::uint8_t>{});}) co_return std::unexpected(httpupgrade::Failure{httpupgrade::Error::state});
            else {
                if (busy_ || failed_ || upgraded_ || handshake_.status()!=ServerStatus::reading) co_return std::unexpected(httpupgrade::Failure{httpupgrade::Error::state});
                busy_=true; OperationGuard guard{*this};
                if (profile.websocket()) {
                    if constexpr (requires {stream_.activate_websocket(profile,deadline);}) {
                        auto ready=co_await stream_.activate_websocket(profile,deadline);
                        if (!ready) co_return std::unexpected(httpupgrade::Failure{httpupgrade::Error::rejected,ready.error()});
                        if (failed_) co_return std::unexpected(httpupgrade::Failure{httpupgrade::Error::state});
                        upgraded_=true;
                        guard.released=true;
                        co_return *ready;
                    } else co_return std::unexpected(httpupgrade::Failure{httpupgrade::Error::state});
                }
                auto ready=co_await httpupgrade::accept(stream_,profile,deadline);
                if (!ready) co_return std::unexpected(ready.error());
                if (failed_) co_return std::unexpected(httpupgrade::Failure{httpupgrade::Error::state});
                auto prefetched=ready->unread.size();
                if (!stream_.prepend_owned(std::move(ready->unread))) co_return std::unexpected(httpupgrade::Failure{httpupgrade::Error::state});
                upgraded_=true; guard.released=true; co_return prefetched;
            }
        }
        auto read_header(tls::detail::ApplicationDeadline deadline={}) -> capy::task<std::expected<InboundRequest,TlsInboundError>> {
            if (busy_ || failed_ || handshake_.status()!=ServerStatus::reading) co_return std::unexpected(TlsInboundError::state);
            busy_=true; OperationGuard guard{*this};
            for (;;) {
                auto received=co_await receive(buffer_,deadline);
                if (!received || !*received || failed_) co_return fail(TlsInboundError::io);
                auto step=handshake_.feed(std::span(buffer_).first(*received));
                if (step.status==ServerStatus::rejected) co_return fail(TlsInboundError::rejected);
                if (step.status==ServerStatus::dialing) {
                    begin_=step.consumed; end_=*received;
                    if (auto request=handshake_.request()) { InboundRequest result{*request}; guard.released=true; co_return result; }
                    if (auto user=handshake_.mux_user()) { InboundRequest result{*user}; guard.released=true; co_return result; }
                    co_return fail(TlsInboundError::state);
                }
            }
        }
        auto read_request(tls::detail::ApplicationDeadline deadline={}) -> capy::task<std::expected<TcpRequest,TlsInboundError>> {
            auto result=co_await read_header(deadline);
            if (!result) co_return std::unexpected(result.error());
            if (auto request=std::get_if<TcpRequest>(&*result)) co_return std::move(*request);
            co_return fail(TlsInboundError::rejected);
        }
        auto complete_dial(bool connected,tls::detail::ApplicationDeadline deadline={}) -> capy::task<std::expected<void,TlsInboundError>> {
            if (busy_ || failed_ || handshake_.status()!=ServerStatus::dialing) co_return std::unexpected(TlsInboundError::state);
            busy_=true; OperationGuard guard{*this}; auto response=handshake_.complete_dial(connected);
            if (!response) co_return fail(TlsInboundError::rejected);
            if constexpr (Vision) {
                auto operation=writer_.scoped_lock();
                auto [error,lock]=deadline ? co_await corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
                if (error || failed_) co_return fail(TlsInboundError::io);
                while (connection_->pending_output()) if (!co_await connection_->flush(deadline)) co_return fail(TlsInboundError::io);
                if (!co_await connection_->send_all(*response,deadline)) co_return fail(TlsInboundError::io);
            } else if (!co_await stream_.send(*response,deadline)) co_return fail(TlsInboundError::io);
            if (failed_) co_return fail(TlsInboundError::io);
            accepted_=true; guard.released=true; co_return std::expected<void,TlsInboundError>{};
        }
        struct VisionHandoff { tls::detail::ApplicationStreamReader<Socket>* reader; std::span<std::uint8_t const> initial; };
        [[nodiscard]] auto handoff_vision() noexcept -> std::optional<VisionHandoff> {
            if constexpr (!Vision) return {};
            else {
                if (busy_ || failed_ || !accepted_ || !stream_.idle()) return {};
                accepted_=false; return VisionHandoff{&stream_,std::span(buffer_).subspan(begin_,end_-begin_)};
            }
        }
        // These factories return the shared TLS task directly. The public
        // protocol state checks add no per-chunk forwarding coroutine.
        auto send(std::span<std::uint8_t const> bytes,tls::detail::ApplicationDeadline deadline={}) -> capy::task<bool> {
            if constexpr (Vision) return reject_send();
            else {
                if (failed_ || !accepted_) return reject_send();
                try { return stream_.send(bytes,deadline); } catch (...) { cancel(); throw; }
            }
        }
        auto close_output(tls::detail::ApplicationDeadline deadline={}) -> capy::task<bool> {
            if constexpr (Vision) return reject_send();
            else {
                if (failed_ || !accepted_) return reject_send();
                try { return stream_.close_output(deadline); } catch (...) { cancel(); throw; }
            }
        }
        // Before the VLESS response, inspect already decrypted payload or
        // perform a recoverable read without changing the handshake state.
        auto read_sniff(std::span<std::uint8_t> output,tls::detail::ApplicationDeadline deadline)
            -> capy::task<std::expected<std::size_t,TlsInboundError>> requires (!Vision) {
            if(busy_ || failed_ || accepted_ || handshake_.status()!=ServerStatus::dialing || output.empty())
                co_return std::unexpected(TlsInboundError::state);
            busy_=true;OperationGuard guard{*this};
            auto buffered=std::min(output.size(),end_-begin_);
            if(buffered) {
                std::copy_n(buffer_.begin()+begin_,buffered,output.begin());begin_+=buffered;
                guard.released=true;co_return buffered;
            }
            std::expected<std::size_t,tls::detail::ByteStreamError> result=std::unexpected(tls::detail::ByteStreamError::io);
            if constexpr (requires { stream_.read(output,deadline,tls::detail::ReadTimeoutPolicy::preserve_connection); })
                result=co_await stream_.read(output,deadline,tls::detail::ReadTimeoutPolicy::preserve_connection);
            else
                result=co_await stream_.read(output,deadline);
            if(!result) {
                if(result.error()==tls::detail::ByteStreamError::timeout){guard.released=true;co_return std::unexpected(TlsInboundError::timeout);}
                co_return fail(TlsInboundError::io);
            }
            if(*result>output.size() || failed_)co_return fail(TlsInboundError::io);
            guard.released=true;co_return *result;
        }
        auto read(std::span<std::uint8_t> output,tls::detail::ApplicationDeadline deadline={}) {
            if constexpr (Vision) return ReadResult{};
            else {
                if (busy_ || failed_ || !accepted_ || output.empty()) return ReadResult{};
                auto buffered=std::min(output.size(),end_-begin_); std::optional<ReadTask> operation;
                try { if (!buffered) operation.emplace(stream_.read(output,deadline)); }
                catch (...) { cancel(); throw; }
                busy_=true; return ReadResult{*this,output,std::move(operation),buffered};
            }
        }
    };
    // Each direction runs once; owner retains and drains both operations.
    template<class Incoming,class Target,class PlainStream=websocket::VlessByteStream<Incoming>>
    class TlsRelay {
        TlsInbound<Incoming,false,PlainStream>& inbound_;
        Target& target_;
        functional::move_only_function<void()> touch_;
        bool canceled_=false,uploading_=false,downloading_=false;
    public:
        TlsRelay(TlsInbound<Incoming,false,PlainStream>& inbound,Target& target,functional::move_only_function<void()> touch={})
            : inbound_(inbound),target_(target),touch_(std::move(touch)) {}
        TlsRelay(TlsRelay const&)=delete;
        auto operator=(TlsRelay const&) -> TlsRelay& = delete;
        auto cancel() noexcept -> void { if (!canceled_) { canceled_=true; inbound_.cancel(); target_.cancel(); } }
        auto upload() -> capy::task<bool> {
            if (uploading_ || canceled_) co_return false; uploading_=true;
            std::array<std::uint8_t,16640> small_buf{}; std::unique_ptr<std::uint8_t[]> large_buf;
            std::size_t total_bytes=0; bool large_failed=false;
            for (;;) {
                if (!large_buf && !large_failed && total_bytes>=65536) {
                    large_buf.reset(new (std::nothrow) std::uint8_t[65536]);
                    if (!large_buf) large_failed=true;
                }
                auto buffer=large_buf ? std::span<std::uint8_t>(large_buf.get(),65536) : std::span<std::uint8_t>(small_buf);
                auto received=co_await inbound_.read(buffer);
                if (!received || canceled_) { cancel(); co_return false; }
                if (!*received) { if (target_.shutdown(corosio::shutdown_send)) { cancel(); co_return false; } co_return true; }
                total_bytes+=*received;
                if (touch_) touch_();
                std::size_t sent=0;
                while (sent<*received) {
                    auto [error,count]=co_await target_.write_some(capy::const_buffer(buffer.data()+sent,*received-sent));
                    if (error || !count || count>*received-sent || canceled_) { cancel(); co_return false; } sent+=count;
                }
            }
        }
        auto download() -> capy::task<bool> {
            if (downloading_ || canceled_) co_return false; downloading_=true;
            std::array<std::uint8_t,16640> small_buf{}; std::unique_ptr<std::uint8_t[]> large_buf;
            std::size_t total_bytes=0; bool large_failed=false;
            for (;;) {
                if (!large_buf && !large_failed && total_bytes>=65536) {
                    large_buf.reset(new (std::nothrow) std::uint8_t[65536]);
                    if (!large_buf) large_failed=true;
                }
                auto buffer=large_buf ? std::span<std::uint8_t>(large_buf.get(),65536) : std::span<std::uint8_t>(small_buf);
                auto [error,size]=co_await target_.read_some(capy::mutable_buffer(buffer.data(),buffer.size()));
                if (capy::is_eof(error) && !canceled_) {
                    auto closed=co_await inbound_.close_output(); if (!closed || canceled_) { cancel(); co_return false; } co_return true;
                }
                if (error || !size || size>buffer.size() || canceled_) { cancel(); co_return false; }
                total_bytes+=size;
                if (touch_) touch_();
                if (!co_await inbound_.send(buffer.first(size))) { cancel(); co_return false; }
            }
        }
    };
}
