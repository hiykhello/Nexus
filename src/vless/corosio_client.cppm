export module vless.corosio_client;
import std;
export import functional;
import vless;
import httpupgrade;
import httpupgrade.stream;
import websocket.stream;
import tls.application_io;
import tls.corosio_application;
import tls.byte_stream;
import net.stream_relay;
import capy;
import corosio;

export namespace vless::detail {
    enum class ClientError { state,invalid_request,tls,response,backpressure };
    struct EmptyClientConnection {};
    template<class LocalSocket,class RemoteSocket,class PlainStream> class DuplexRelay;
    // Plain VLESS owns exactly one TLS byte reader/writer. Vision retains its
    // existing reader and hands control events to the Vision writer instead;
    // it never constructs a second, unused ByteStream mutex.
    template<class Socket,bool Vision=false,class PlainStream=websocket::VlessByteStream<Socket>>
    class TcpClient {
        template<class,class,class> friend class DuplexRelay;
        using Connection=tls::detail::ApplicationConnection<Socket>;
        using ConnectionRef=std::conditional_t<Vision,Connection*,EmptyClientConnection>;
        using Stream=std::conditional_t<Vision,tls::detail::ApplicationStreamReader<Socket>,PlainStream>;
        enum class State { initial,upgrading,transport_ready,sending_header,awaiting_response,ready,failed } state_=State::initial;
        std::array<std::uint8_t,2> response_{};
        bool reading_=false,writing_=false;
        std::size_t received_=0;
        [[no_unique_address]] ConnectionRef connection_;
        Stream stream_;
        struct OperationGuard {
            TcpClient& owner; bool& busy; bool released=false;
            ~OperationGuard() { busy=false; if (!released) owner.cancel(); }
        };
        static auto retain(Connection& connection) noexcept -> ConnectionRef {
            if constexpr (Vision) return &connection; else return {};
        }
        auto fail(ClientError error) noexcept -> std::unexpected<ClientError> { cancel(); return std::unexpected(error); }
        static auto reject_send() -> capy::task<bool> { co_return false; }
        static auto reject_read() -> capy::task<std::expected<std::size_t,tls::detail::ByteStreamError>> {
            co_return std::unexpected(tls::detail::ByteStreamError::state);
        }
        // Production relay factories return the actual TLS task. No VLESS
        // forwarding coroutine is added to each application read/write.
        auto send_bytes(std::span<std::uint8_t const> bytes,tls::detail::ApplicationDeadline deadline) requires (!Vision) {
            if ((state_!=State::awaiting_response && state_!=State::ready) || writing_) return reject_send();
            return stream_.send(bytes,deadline);
        }
        auto read_bytes(std::span<std::uint8_t> bytes,tls::detail::ApplicationDeadline deadline) requires (!Vision) {
            if (state_!=State::ready || reading_) return reject_read();
            return stream_.read(bytes,deadline);
        }
        auto close_bytes(tls::detail::ApplicationDeadline deadline) requires (!Vision) {
            if ((state_!=State::awaiting_response && state_!=State::ready) || writing_) return reject_send();
            return stream_.close_output(deadline);
        }
        auto start_impl(TcpRequest const& request,tls::detail::ApplicationDeadline deadline)
            -> capy::task<std::expected<void,ClientError>> {
            if ((state_!=State::initial && state_!=State::transport_ready) || writing_) co_return std::unexpected(ClientError::state);
            auto header=Vision ? encode_vision_tcp_request(request) :
                request.command==TargetCommand::udp ? encode_udp_request(request) : encode_tcp_request(request);
            if (!header) co_return std::unexpected(ClientError::invalid_request);
            state_=State::sending_header; writing_=true; OperationGuard guard{*this,writing_};
            if constexpr (Vision) {
                if (!co_await connection_->send_all(*header,deadline)) co_return fail(ClientError::tls);
            } else if (!co_await stream_.send(*header,deadline)) co_return fail(ClientError::tls);
            if (state_==State::failed) co_return fail(ClientError::tls);
            state_=State::awaiting_response; guard.released=true; co_return std::expected<void,ClientError>{};
        }
    public:
        explicit TcpClient(Connection& connection) requires std::constructible_from<Stream,Connection&>
            : connection_(retain(connection)),stream_(connection) {}
        explicit TcpClient(PlainStream stream) requires (!Vision && std::is_reference_v<PlainStream>)
            : connection_{},stream_(stream) {}
        TcpClient(TcpClient const&)=delete;
        auto operator=(TcpClient const&) -> TcpClient& = delete;
        auto cancel() noexcept -> void {
            state_=State::failed;
            if constexpr (Vision) connection_->cancel(); else stream_.cancel();
        }
        // Legacy explicit read handoff remains available to diagnostics. The
        // plain production relay keeps using stream_, without handing it off.
        [[nodiscard]] auto reader() noexcept -> tls::detail::ApplicationStreamReader<Socket>* {
            if (state_!=State::ready || reading_) return nullptr;
            if constexpr (Vision) return &stream_;
            else if constexpr (requires { stream_.release_reader(); }) return stream_.release_reader();
            else return nullptr;
        }
        auto upgrade(httpupgrade::Profile const& profile,std::chrono::steady_clock::time_point deadline)
            -> capy::task<std::expected<std::size_t,httpupgrade::Failure>> {
            if constexpr (Vision || !requires(Stream& stream) {stream.prepend_owned(std::vector<std::uint8_t>{});}) co_return std::unexpected(httpupgrade::Failure{httpupgrade::Error::state});
            else {
                if (state_!=State::initial || reading_ || writing_) co_return std::unexpected(httpupgrade::Failure{httpupgrade::Error::state});
                state_=State::upgrading; writing_=true; OperationGuard guard{*this,writing_};
                if (profile.websocket()) {
                    if constexpr (requires {stream_.activate_websocket(profile,deadline);}) {
                        auto ready=co_await stream_.activate_websocket(profile,deadline);
                        if (!ready) co_return std::unexpected(httpupgrade::Failure{httpupgrade::Error::rejected,ready.error()});
                        if (state_==State::failed) co_return std::unexpected(httpupgrade::Failure{httpupgrade::Error::state});
                        state_=State::transport_ready;
                        guard.released=true;
                        co_return *ready;
                    } else co_return std::unexpected(httpupgrade::Failure{httpupgrade::Error::state});
                }
                auto ready=co_await httpupgrade::connect(stream_,profile,deadline);
                if (!ready) co_return std::unexpected(ready.error());
                if (state_==State::failed) co_return std::unexpected(httpupgrade::Failure{httpupgrade::Error::state});
                auto prefetched=ready->unread.size();
                if (!stream_.prepend_owned(std::move(ready->unread))) co_return std::unexpected(httpupgrade::Failure{httpupgrade::Error::state});
                state_=State::transport_ready; guard.released=true; co_return prefetched;
            }
        }
        // The response may be deferred until application data arrives.
        auto start(TcpRequest const& request,tls::detail::ApplicationDeadline deadline={}) -> capy::task<std::expected<void,ClientError>> {
            if constexpr (Vision) co_return std::unexpected(ClientError::state);
            else co_return co_await start_impl(request,deadline);
        }
        auto start_datagrams(UserId const& user,bool packetaddr,tls::detail::ApplicationDeadline deadline)
            -> capy::task<std::expected<void,ClientError>> requires (!Vision) {
            if (!packetaddr) co_return co_await start_mux(user,false,deadline);
            TcpRequest request{.user=user,.kind=AddressKind::domain,
                .address={packetaddr_domain.begin(),packetaddr_domain.end()},.command=TargetCommand::udp};
            co_return co_await start_impl(request,deadline);
        }
        auto start_vision(TcpRequest const& request,tls::detail::ApplicationDeadline deadline={}) -> capy::task<std::expected<void,ClientError>> {
            if constexpr (!Vision) co_return std::unexpected(ClientError::state);
            else co_return co_await start_impl(request,deadline);
        }
        auto start_mux(UserId const& user,bool vision=false,tls::detail::ApplicationDeadline deadline={})
            -> capy::task<std::expected<void,ClientError>> {
            if (vision!=Vision || (state_!=State::initial && state_!=State::transport_ready) || writing_) co_return std::unexpected(ClientError::state);
            auto header=encode_mux_request(user,Vision);
            state_=State::sending_header; writing_=true; OperationGuard guard{*this,writing_};
            if constexpr (Vision) {
                if (!co_await connection_->send_all(header,deadline)) co_return fail(ClientError::tls);
            } else if (!co_await stream_.send(header,deadline)) co_return fail(ClientError::tls);
            if (state_==State::failed) co_return fail(ClientError::tls);
            state_=State::awaiting_response; guard.released=true; co_return std::expected<void,ClientError>{};
        }
        auto send(std::span<std::uint8_t const> bytes,tls::detail::ApplicationDeadline deadline={})
            -> capy::task<std::expected<void,ClientError>> {
            if ((state_!=State::awaiting_response && state_!=State::ready) || writing_) co_return std::unexpected(ClientError::state);
            writing_=true; OperationGuard guard{*this,writing_};
            if constexpr (Vision) {
                if (!co_await connection_->send_all(bytes,deadline)) co_return fail(ClientError::tls);
            } else if (!co_await stream_.send(bytes,deadline)) co_return fail(ClientError::tls);
            if (state_==State::failed) co_return fail(ClientError::tls);
            guard.released=true; co_return std::expected<void,ClientError>{};
        }
        auto receive_response(tls::detail::ApplicationDeadline deadline={}) -> capy::task<std::expected<void,ClientError>> {
            if (state_!=State::awaiting_response || reading_) co_return std::unexpected(ClientError::state);
            reading_=true; OperationGuard guard{*this,reading_};
            while (received_<response_.size()) {
                if constexpr (Vision) {
                    auto result=co_await stream_.read_some(std::span(response_).subspan(received_),deadline);
                    if (!result || state_==State::failed) co_return fail(ClientError::tls);
                    if (result->kind==tls::detail::AsyncStreamReadKind::backpressure ||
                        (result->event && result->event->kind==tls::ApplicationEventKind::key_update_requested)) {
                        guard.released=true; co_return std::unexpected(ClientError::backpressure);
                    }
                    if (result->kind==tls::detail::AsyncStreamReadKind::eof ||
                        (result->event && (result->event->kind==tls::ApplicationEventKind::close_notify || result->event->kind==tls::ApplicationEventKind::fatal_alert ||
                                          result->event->kind==tls::ApplicationEventKind::user_canceled))) co_return fail(ClientError::response);
                    if (result->kind==tls::detail::AsyncStreamReadKind::data) received_+=result->size;
                } else {
                    auto result=co_await stream_.read(std::span(response_).subspan(received_),deadline);
                    if (!result || state_==State::failed) co_return fail(ClientError::tls);
                    if (!*result) co_return fail(ClientError::response);
                    received_+=*result;
                }
            }
            if (parse_response(response_).status!=HeaderStatus::accepted) co_return fail(ClientError::response);
            state_=State::ready; guard.released=true; co_return std::expected<void,ClientError>{};
        }
    };

    // The only persistent writer lives in TcpClient's ByteStream. Factories
    // below map results in await_resume; they own no coroutine frame, stream
    // buffer, virtual interface or separately allocated transport state.
    template<class LocalSocket,class RemoteSocket,class PlainStream=websocket::VlessByteStream<RemoteSocket>>
    class DuplexRelay {
        using Client=TcpClient<RemoteSocket,false,PlainStream>;
        using ReadTask=capy::task<std::expected<std::size_t,tls::detail::ByteStreamError>>;
        LocalSocket& local_;
        Client& client_;
        functional::move_only_function<void()> touch_;
        bool canceled_=false,upload_started_=false,download_started_=false,response_ready_=false,cancel_local_=true;
        template<class Operation,bool Read>
        class Result {
            DuplexRelay& relay_;
            std::optional<Operation> operation_;
            bool touch_,started_=false,done_=false;
        public:
            Result(DuplexRelay& relay,std::optional<Operation>&& operation,bool touch)
                : relay_(relay),operation_(std::move(operation)),touch_(touch) {}
            Result(Result const&)=delete;
            Result(Result&&)=default;
            ~Result() { if (started_ && !done_) relay_.cancel(); }
            auto await_ready() const noexcept -> bool { return !operation_ || operation_->await_ready(); }
            template<class Context>
            auto await_suspend(std::coroutine_handle<> continuation,Context const* context) {
                started_=true; return operation_->await_suspend(continuation,context);
            }
            auto await_resume() -> std::conditional_t<Read,std::expected<std::size_t,ClientError>,bool> {
                done_=true;
                try {
                    if constexpr (Read) {
                        if (!operation_) return std::unexpected(ClientError::state);
                        auto result=operation_->await_resume();
                        if (!result || relay_.canceled_) {
                            auto error=relay_.response_ready_ ? ClientError::tls : ClientError::response;
                            relay_.cancel(); return std::unexpected(error);
                        }
                        if (*result && touch_ && relay_.touch_) relay_.touch_(); return *result;
                    } else {
                        if (!operation_ || !operation_->await_resume() || relay_.canceled_) { relay_.cancel(); return false; }
                        if (touch_ && relay_.touch_) relay_.touch_(); return true;
                    }
                } catch (...) { relay_.cancel(); throw; }
            }
        };
        // Extra parsing is confined to the first VLESS response. Every later
        // application read returns the ByteStream read task directly.
        auto first_read(std::span<std::uint8_t> bytes,tls::detail::ApplicationDeadline deadline) -> ReadTask {
            auto response=co_await client_.receive_response(deadline);
            if (!response) co_return std::unexpected(tls::detail::ByteStreamError::protocol);
            response_ready_=true; co_return co_await client_.read_bytes(bytes,deadline);
        }
        auto write_result(std::span<std::uint8_t const> bytes,tls::detail::ApplicationDeadline deadline,bool touch) {
            std::optional<capy::task<bool>> operation;
            try { if (!canceled_) operation.emplace(client_.send_bytes(bytes,deadline)); }
            catch (...) { cancel(); throw; }
            return Result<capy::task<bool>,false>{*this,std::move(operation),touch && !bytes.empty()};
        }
    public:
        DuplexRelay(LocalSocket& local,tls::detail::ApplicationConnection<RemoteSocket>&,Client& client,
                    functional::move_only_function<void()> touch={},bool cancel_local=true)
            : local_(local),client_(client),touch_(std::move(touch)),
              response_ready_(client_.state_==Client::State::ready),cancel_local_(cancel_local) {}
        DuplexRelay(LocalSocket& local,Client& client,functional::move_only_function<void()> touch={},bool cancel_local=true)
            : local_(local),client_(client),touch_(std::move(touch)),
              response_ready_(client_.state_==Client::State::ready),cancel_local_(cancel_local) {}
        DuplexRelay(DuplexRelay const&)=delete;
        auto operator=(DuplexRelay const&) -> DuplexRelay& = delete;
        auto cancel() noexcept -> void {
            if (canceled_) return;
            canceled_=true; if (cancel_local_) local_.cancel(); client_.cancel();
        }
        auto write(std::span<std::uint8_t const> data,tls::detail::ApplicationDeadline deadline={}) { return write_result(data,deadline,true); }
        auto read(std::span<std::uint8_t> bytes,tls::detail::ApplicationDeadline deadline={}) {
            std::optional<ReadTask> operation;
            try {
                if (!canceled_ && !bytes.empty()) {
                    if (response_ready_) operation.emplace(client_.read_bytes(bytes,deadline));
                    else operation.emplace(first_read(bytes,deadline));
                }
            } catch (...) { cancel(); throw; }
            return Result<ReadTask,true>{*this,std::move(operation),true};
        }
        auto close_output(tls::detail::ApplicationDeadline deadline={}) {
            std::optional<capy::task<bool>> operation;
            try { if (!canceled_) operation.emplace(client_.close_bytes(deadline)); }
            catch (...) { cancel(); throw; }
            return Result<capy::task<bool>,false>{*this,std::move(operation),false};
        }
    private:
        struct RelayAdapter {
            DuplexRelay& relay; tls::detail::ApplicationDeadline deadline;
            net::stream_relay::Delivery delivery;
            static constexpr bool locked_upload=false;
            auto local() const -> LocalSocket& { return relay.local_; }
            auto start_upload() -> bool { if (relay.upload_started_ || relay.canceled_) return false; relay.upload_started_=true; return true; }
            auto start_download() -> bool { if (relay.download_started_ || relay.canceled_) return false; relay.download_started_=true; return true; }
            template<class Error> auto upload_eof(Error const& error,std::size_t) const -> bool { return capy::is_eof(error); }
            template<class Error> auto invalid_upload(Error const& error,std::size_t n,std::size_t size) const -> bool { return error || !n || n>size || relay.canceled_; }
            template<class Error> auto invalid_download(Error const& error,std::size_t n,std::size_t size) const -> bool { return error || !n || n>size || relay.canceled_; }
            auto after_local_read() const -> void { if (relay.touch_) relay.touch_(); }
            auto after_local_write() const -> void { if (relay.touch_) relay.touch_(); }
            auto cancel() const noexcept -> void { relay.cancel(); }
            auto close_upload() const { return relay.close_output(deadline); }
            auto send_upload(std::span<std::uint8_t const> bytes) const { return relay.write_result(bytes,deadline,false); }
            auto receive(std::span<std::uint8_t> bytes) const { return relay.read(bytes,deadline); }
            auto shutdown_local() const -> bool { if (relay.local_.shutdown(corosio::shutdown_send)) { relay.cancel(); return false; } return true; }
        };
    public:
        auto upload(tls::detail::ApplicationDeadline deadline={},net::stream_relay::Delivery delivery={}) -> capy::task<bool> { return net::stream_relay::upload(RelayAdapter{*this,deadline,delivery}); }
        auto download(tls::detail::ApplicationDeadline deadline={},net::stream_relay::Delivery delivery={}) -> capy::task<bool> { return net::stream_relay::download(RelayAdapter{*this,deadline,delivery}); }
    };
}
