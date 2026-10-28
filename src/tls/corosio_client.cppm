export module nexus.tls.corosio_client;
import std;
import nexus.tls.client_handshake_io;
import nexus.tls.application_io;
import nexus.tls.corosio_application;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;


export namespace nexus::tls::detail {
    enum class AsyncHandshakeError { transport, protocol, authentication, timeout };
    struct AsyncHandshakeResult {
        ApplicationRecords records;
        crypto::Bytes unread;
    };
    // The owner keeps socket and handshake alive until completion and drains cancellation.
    // The handshake deadline must use the steady-clock millisecond epoch.
    template<class Socket>
    auto corosio_handshake(Socket& socket, ClientHandshakeIo& handshake)
        -> nex::capy::task<std::expected<AsyncHandshakeResult,AsyncHandshakeError>> {
        auto now=[] { return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()); };
        auto max_ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::duration::max()).count();
        if (handshake.deadline()>static_cast<std::uint64_t>(max_ms)) { (void)handshake.cancel(); co_return std::unexpected(AsyncHandshakeError::protocol); }
        auto deadline=std::chrono::steady_clock::time_point(std::chrono::milliseconds(handshake.deadline()));
        std::array<std::uint8_t,4096> buffer{};
        std::size_t begin=0, end=0;
        while (!handshake.complete()) {
            if (!handshake.tick(now())) co_return std::unexpected(AsyncHandshakeError::timeout);
            if (!handshake.pending_output().empty()) {
                // An owned copy keeps an in-flight buffer alive until completion.
                auto pending=handshake.pending_output(); crypto::Bytes bytes(pending.begin(),pending.end());
                auto [error,n]=co_await nex::corosio::timeout(socket.write_some(nex::capy::const_buffer(bytes.data(),bytes.size())),deadline);
                if (error || n==0 || n>bytes.size()) {
                    if (nex::capy::is_timeout(error)) { (void)handshake.cancel(); co_return std::unexpected(AsyncHandshakeError::timeout); }
                    if (!handshake.tick(now())) co_return std::unexpected(AsyncHandshakeError::timeout);
                    (void)handshake.cancel(); co_return std::unexpected(AsyncHandshakeError::transport);
                }
                auto written=handshake.written(n,now());
                if (!written) co_return std::unexpected(written.error()==ClientHandshakeIoError::timeout ? AsyncHandshakeError::timeout : AsyncHandshakeError::protocol);
                continue;
            }
            if (begin==end) {
                auto [error,n]=co_await nex::corosio::timeout(socket.read_some(nex::capy::mutable_buffer(buffer.data(),buffer.size())),deadline);
                if (error || n==0 || n>buffer.size()) {
                    if (nex::capy::is_timeout(error)) { (void)handshake.cancel(); co_return std::unexpected(AsyncHandshakeError::timeout); }
                    if (!handshake.tick(now())) co_return std::unexpected(AsyncHandshakeError::timeout);
                    (void)handshake.finish_input(now()); co_return std::unexpected(AsyncHandshakeError::transport);
                }
                begin=0; end=n;
            }
            auto result=handshake.feed(std::span{buffer}.subspan(begin,end-begin),now());
            if (!result) co_return std::unexpected(result.error()==ClientHandshakeIoError::timeout ? AsyncHandshakeError::timeout : result.error()==ClientHandshakeIoError::authentication_failed ? AsyncHandshakeError::authentication : AsyncHandshakeError::protocol);
            if (!result->consumed) co_return std::unexpected(AsyncHandshakeError::protocol);
            begin+=result->consumed;
        }
        auto app=handshake.take_application_records(); if (!app) co_return std::unexpected(AsyncHandshakeError::protocol);
        co_return AsyncHandshakeResult{std::move(*app),crypto::Bytes(buffer.begin()+static_cast<std::ptrdiff_t>(begin),buffer.begin()+static_cast<std::ptrdiff_t>(end))};
    }
}

export namespace nexus::tls::detail {
    // Single-executor owner. Socket and this object must outlive start() and any application
    // operation; cancel and drain those operations before destroying either object.
    template<class Socket>
    class ClientConnection {
        enum class State { initial, handshaking, ready, stopped } state_=State::initial;
        Socket& socket_;
        std::optional<ClientHandshakeIo> handshake_;
        std::optional<ApplicationConnection<Socket>> application_;
        std::optional<EncryptedExtensions> negotiated_;
        bool canceled_=false;
    public:
        ClientConnection(Socket& socket, ClientHandshakeIo&& handshake)
            : socket_(socket), handshake_(std::move(handshake)) {}
        ClientConnection(ClientConnection const&)=delete;
        auto operator=(ClientConnection const&) -> ClientConnection& = delete;
        [[nodiscard]] auto idle() const noexcept -> bool {
            return state_!=State::handshaking && (!application_ || application_->idle());
        }
        [[nodiscard]] auto application() noexcept -> ApplicationConnection<Socket>* {
            return state_==State::ready ? &*application_ : nullptr;
        }
        [[nodiscard]] auto negotiated() const noexcept -> EncryptedExtensions const* {
            return state_==State::ready ? &*negotiated_ : nullptr;
        }
        auto cancel() noexcept -> void {
            if (canceled_) return;
            canceled_=true;
            if (application_) application_->cancel();
            else if (state_==State::handshaking) socket_.cancel();
            else if (handshake_) (void)handshake_->cancel();
            if (state_!=State::handshaking) state_=State::stopped;
        }
        auto start() -> nex::capy::task<std::expected<void,AsyncHandshakeError>> {
            if (state_!=State::initial || canceled_) co_return std::unexpected(AsyncHandshakeError::protocol);
            state_=State::handshaking;
            auto result=co_await corosio_handshake(socket_,*handshake_);
            if (canceled_ || !result) {
                if (canceled_) (void)handshake_->cancel();
                state_=State::stopped; handshake_.reset();
                co_return std::unexpected(canceled_ ? AsyncHandshakeError::transport : result.error());
            }
            auto const* selected=handshake_->negotiated();
            if (!selected) { state_=State::stopped; handshake_.reset(); co_return std::unexpected(AsyncHandshakeError::protocol); }
            negotiated_=*selected;
            application_.emplace(socket_,std::move(result->records),std::move(result->unread));
            handshake_.reset(); state_=State::ready;
            co_return std::expected<void,AsyncHandshakeError>{};
        }
    };
}


export namespace nexus::tls::detail {
    // Owns the socket from numeric-endpoint connect through authenticated TLS. All calls
    // run on one executor; cancel and drain start/application operations before destruction.
    class OwnedClient {
        enum class State { initial, connecting, handshaking, ready, stopped } state_=State::initial;
        std::uint64_t deadline_ms_;
        nex::corosio::tcp_socket socket_;
        ClientConnection<nex::corosio::tcp_socket> client_;
        bool canceled_=false;
    public:
        OwnedClient(nex::corosio::io_context& context, ClientHandshakeIo&& handshake)
            : deadline_ms_(handshake.deadline()), socket_(context), client_(socket_,std::move(handshake)) {}
        OwnedClient(OwnedClient const&)=delete;
        auto operator=(OwnedClient const&) -> OwnedClient& = delete;
        [[nodiscard]] auto idle() const noexcept -> bool { return state_!=State::connecting && state_!=State::handshaking && client_.idle(); }
        [[nodiscard]] auto client() noexcept -> ClientConnection<nex::corosio::tcp_socket>* { return state_==State::ready ? &client_ : nullptr; }
        auto cancel() noexcept -> void {
            if (canceled_) return;
            canceled_=true;
            if (state_==State::connecting) socket_.cancel();
            client_.cancel();
            if (state_!=State::connecting && state_!=State::handshaking) state_=State::stopped;
        }
        auto start(nex::corosio::endpoint endpoint) -> nex::capy::task<std::expected<void,AsyncHandshakeError>> {
            if (state_!=State::initial || canceled_) co_return std::unexpected(AsyncHandshakeError::protocol);
            auto max_ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::duration::max()).count();
            if (deadline_ms_>static_cast<std::uint64_t>(max_ms)) { cancel(); co_return std::unexpected(AsyncHandshakeError::protocol); }
            auto deadline=std::chrono::steady_clock::time_point(std::chrono::milliseconds(deadline_ms_));
            if (std::chrono::steady_clock::now()>=deadline) { cancel(); co_return std::unexpected(AsyncHandshakeError::timeout); }
            state_=State::connecting;
            auto [error]=co_await nex::corosio::timeout(socket_.connect(endpoint),deadline);
            if (error || canceled_ || std::chrono::steady_clock::now()>=deadline) {
                auto timed_out=!canceled_ && (nex::capy::is_timeout(error) || std::chrono::steady_clock::now()>=deadline);
                client_.cancel(); socket_.close(); state_=State::stopped;
                co_return std::unexpected(timed_out ? AsyncHandshakeError::timeout : AsyncHandshakeError::transport);
            }
            state_=State::handshaking;
            auto result=co_await client_.start();
            if (canceled_ || !result) {
                auto failure=canceled_ ? AsyncHandshakeError::transport : result.error();
                client_.cancel(); socket_.close(); state_=State::stopped;
                co_return std::unexpected(failure);
            }
            state_=State::ready;
            co_return std::expected<void,AsyncHandshakeError>{};
        }
    };
}
