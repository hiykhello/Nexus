export module nexus.vless.corosio_client;
import std;
import nexus.vless;
import nexus.tls.application_io;
import nexus.tls.corosio_application;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;


export namespace nexus::vless::detail {
    enum class ClientError { state, invalid_request, tls, response, backpressure };
    // The connection must already have completed peer authentication. One reader and one
    // writer may overlap on the same executor; cancel and drain both before destruction.
    template<class Socket>
    class TcpClient {
        enum class State { initial, sending_header, awaiting_response, ready, failed } state_=State::initial;
        tls::detail::ApplicationConnection<Socket>& connection_;
        tls::detail::ApplicationStreamReader<Socket> reader_;
        std::array<std::uint8_t,2> response_{};
        std::size_t received_=0;
        bool reading_=false, writing_=false;
        auto fail(ClientError error) -> std::unexpected<ClientError> { state_=State::failed; connection_.cancel(); return std::unexpected(error); }
    public:
        explicit TcpClient(tls::detail::ApplicationConnection<Socket>& connection) : connection_(connection),reader_(connection) {}
        TcpClient(TcpClient const&)=delete;
        auto operator=(TcpClient const&) -> TcpClient& = delete;
        [[nodiscard]] auto reader() noexcept -> tls::detail::ApplicationStreamReader<Socket>* { return state_==State::ready ? &reader_ : nullptr; }
        // Sends only the header. The peer may defer its response until application data arrives.
        auto start(TcpRequest const& request,tls::detail::ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<void,ClientError>> {
            if (state_!=State::initial || writing_) co_return std::unexpected(ClientError::state);
            auto header=encode_tcp_request(request); if (!header) co_return std::unexpected(ClientError::invalid_request);
            state_=State::sending_header; writing_=true;
            auto result=co_await connection_.send_all(*header,deadline); writing_=false;
            if (!result || state_==State::failed) co_return fail(ClientError::tls);
            state_=State::awaiting_response; co_return std::expected<void,ClientError>{};
        }
        // Data can be sent before the VLESS response, including while it is being read.
        // The input span must remain alive until the coroutine completes.
        auto send(std::span<std::uint8_t const> bytes,tls::detail::ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<void,ClientError>> {
            if ((state_!=State::awaiting_response && state_!=State::ready) || writing_) co_return std::unexpected(ClientError::state);
            writing_=true; auto result=co_await connection_.send_all(bytes,deadline); writing_=false;
            if (!result || state_==State::failed) co_return fail(ClientError::tls);
            co_return std::expected<void,ClientError>{};
        }
        // Backpressure is recoverable: wait for the writer, flush TLS output, then retry.
        auto receive_response(tls::detail::ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<void,ClientError>> {
            if (state_!=State::awaiting_response || reading_) co_return std::unexpected(ClientError::state);
            reading_=true;
            while (received_<response_.size()) {
                auto result=co_await reader_.read_some(std::span{response_}.subspan(received_),deadline);
                if (!result || state_==State::failed) { reading_=false; co_return fail(ClientError::tls); }
                if (result->kind==tls::detail::AsyncStreamReadKind::backpressure ||
                    (result->event && result->event->kind==tls::ApplicationEventKind::key_update_requested)) {
                    reading_=false; co_return std::unexpected(ClientError::backpressure);
                }
                if (result->kind==tls::detail::AsyncStreamReadKind::eof ||
                    (result->event && (result->event->kind==tls::ApplicationEventKind::close_notify || result->event->kind==tls::ApplicationEventKind::fatal_alert || result->event->kind==tls::ApplicationEventKind::user_canceled))) {
                    reading_=false; co_return fail(ClientError::response);
                }
                if (result->kind==tls::detail::AsyncStreamReadKind::data) received_+=result->size;
            }
            reading_=false;
            if (parse_response(response_).status!=HeaderStatus::accepted) co_return fail(ClientError::response);
            state_=State::ready; co_return std::expected<void,ClientError>{};
        }
    };
}


export namespace nexus::vless::detail {
    // The owner starts both directions on one executor and retains this object,
    // both sockets and the TLS connection until both coroutines have returned.
    // cancel() interrupts both directions; the owner must still drain them.
    template<class LocalSocket, class RemoteSocket>
    class DuplexRelay {
        LocalSocket& local_;
        tls::detail::ApplicationConnection<RemoteSocket>& connection_;
        TcpClient<RemoteSocket>& client_;
        std::move_only_function<void()> touch_;
        nex::capy::async_mutex writer_;
        bool canceled_=false, upload_started_=false, download_started_=false, response_ready_=false;
        auto fail() noexcept -> void { cancel(); }
        auto flush(tls::detail::ApplicationDeadline deadline) -> nex::capy::task<bool> {
            auto [error, guard]=co_await writer_.scoped_lock();
            if (error || canceled_) co_return false;
            if (!connection_.pending_output()) co_return true;
            auto result=co_await connection_.flush(deadline);
            co_return result.has_value();
        }
    public:
        DuplexRelay(LocalSocket& local, tls::detail::ApplicationConnection<RemoteSocket>& connection,
                    TcpClient<RemoteSocket>& client, std::move_only_function<void()> touch = {})
            : local_(local),connection_(connection),client_(client),touch_(std::move(touch)) {}
        DuplexRelay(DuplexRelay const&)=delete;
        auto operator=(DuplexRelay const&) -> DuplexRelay& = delete;
        auto cancel() noexcept -> void {
            if (canceled_) return;
            canceled_=true; local_.cancel(); connection_.cancel();
        }
        auto write(std::span<std::uint8_t const> data, tls::detail::ApplicationDeadline deadline = {}) -> nex::capy::task<bool> {
            auto [error, guard]=co_await writer_.scoped_lock();
            if (error || canceled_) co_return false;
            auto result=co_await client_.send(data,deadline);
            if (!result) { fail(); co_return false; }
            if (touch_ && !data.empty()) touch_();
            co_return true;
        }
        // A zero length is an authenticated EOF; errors cancel both directions.
        auto read(std::span<std::uint8_t> buffer, tls::detail::ApplicationDeadline deadline = {})
            -> nex::capy::task<std::expected<std::size_t,ClientError>> {
            if (!response_ready_) {
                for (;;) {
                    auto response=co_await client_.receive_response(deadline);
                    if (response) { response_ready_=true; break; }
                    if (response.error()!=ClientError::backpressure || !co_await flush(deadline)) {
                        fail(); co_return std::unexpected(ClientError::response);
                    }
                }
            }
            auto reader=client_.reader();
            if (!reader) { fail(); co_return std::unexpected(ClientError::state); }
            for (;;) {
                auto result=co_await reader->read_some(buffer,deadline);
                if (!result || canceled_) { fail(); co_return std::unexpected(ClientError::tls); }
                if (result->kind==tls::detail::AsyncStreamReadKind::backpressure ||
                    (result->event && result->event->kind==tls::ApplicationEventKind::key_update_requested)) {
                    if (!co_await flush(deadline)) { fail(); co_return std::unexpected(ClientError::tls); }
                    continue;
                }
                if (result->kind==tls::detail::AsyncStreamReadKind::eof ||
                    (result->event && result->event->kind==tls::ApplicationEventKind::close_notify)) co_return 0;
                if (result->event && (result->event->kind==tls::ApplicationEventKind::fatal_alert ||
                                      result->event->kind==tls::ApplicationEventKind::user_canceled)) {
                    fail(); co_return std::unexpected(ClientError::tls);
                }
                if (result->kind==tls::detail::AsyncStreamReadKind::data) {
                    if (touch_) touch_();
                    co_return result->size;
                }
            }
        }
        auto close_output(tls::detail::ApplicationDeadline deadline = {}) -> nex::capy::task<bool> {
            auto [error,guard]=co_await writer_.scoped_lock();
            if (error || canceled_) co_return false;
            auto result=co_await connection_.close_notify(deadline);
            if (!result) { fail(); co_return false; }
            co_return true;
        }
        auto upload(tls::detail::ApplicationDeadline deadline = {}) -> nex::capy::task<bool> {
            if (upload_started_ || canceled_) co_return false;
            upload_started_=true;
            std::array<std::uint8_t,16384> buffer{};
            for (;;) {
                auto [error,n]=co_await local_.read_some(nex::capy::mutable_buffer(buffer.data(),buffer.size()));
                if (nex::capy::is_eof(error)) {
                    auto [lock_error, guard]=co_await writer_.scoped_lock();
                    if (lock_error || canceled_) co_return false;
                    auto closed=co_await connection_.close_notify(deadline);
                    if (!closed) { fail(); co_return false; }
                    co_return true;
                }
                if (error || !n || canceled_) { fail(); co_return false; }
                if (touch_) touch_();
                auto [lock_error, guard]=co_await writer_.scoped_lock();
                if (lock_error || canceled_) co_return false;
                auto sent=co_await client_.send(std::span{buffer}.first(n),deadline);
                if (!sent) { fail(); co_return false; }
            }
        }
        auto download(tls::detail::ApplicationDeadline deadline = {}) -> nex::capy::task<bool> {
            if (download_started_ || canceled_) co_return false;
            download_started_=true;
            std::array<std::uint8_t,16384> buffer{};
            for (;;) {
                auto result=co_await read(buffer,deadline);
                if (!result) co_return false;
                if (!*result) {
                    (void)local_.shutdown(nex::corosio::shutdown_send);
                    co_return true;
                }
                auto bytes=std::span{buffer}.first(*result);
                while (!bytes.empty()) {
                    auto [error,n]=co_await local_.write_some(nex::capy::const_buffer(bytes.data(),bytes.size()));
                    if (error || !n || canceled_) { fail(); co_return false; }
                    if (touch_) touch_();
                    bytes=bytes.subspan(n);
                }
            }
        }
    };
}
