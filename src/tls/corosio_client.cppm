export module tls.corosio_client;
import std;
import tls.client_handshake_io;
import platform.socket_options;
import tls.application_io;
import tls.corosio_application;
import capy;
import corosio;


export namespace tls::detail {
    enum class AsyncHandshakeError { transport, protocol, authentication, timeout, crypto, socket_policy };
    struct AsyncHandshakeResult {
        ApplicationRecords records;
        crypto::Bytes unread;
    };
    template<class Socket>
    auto corosio_handshake_loop(Socket& socket, ClientHandshakeIo& handshake,
        std::span<std::uint8_t> buffer, std::size_t& begin, std::size_t& end)
        -> capy::task<capy::results<std::optional<AsyncHandshakeError>>> {
        using LoopResult = capy::results<std::optional<AsyncHandshakeError>>;
        auto now=[] { return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()); };
        while (!handshake.complete()) {
            auto tick=handshake.tick(now());
            if (!tick) co_return LoopResult{std::error_code{}, std::optional<AsyncHandshakeError>(tick.error()==ClientHandshakeIoError::timeout ? AsyncHandshakeError::timeout : AsyncHandshakeError::protocol)};
            if (!handshake.pending_output().empty()) {
                auto pending=handshake.pending_output();
                auto [error,n]=co_await socket.write_some(capy::const_buffer(pending.data(),pending.size()));
                if (error || n==0 || n>pending.size()) {
                    if (capy::is_timeout(error)) { (void)handshake.cancel(); co_return LoopResult{error, std::optional<AsyncHandshakeError>(AsyncHandshakeError::timeout)}; }
                    auto tick2=handshake.tick(now());
                    if (!tick2) co_return LoopResult{error, std::optional<AsyncHandshakeError>(tick2.error()==ClientHandshakeIoError::timeout ? AsyncHandshakeError::timeout : AsyncHandshakeError::protocol)};
                    (void)handshake.cancel(); co_return LoopResult{error, std::optional<AsyncHandshakeError>(AsyncHandshakeError::transport)};
                }
                auto written=handshake.written(n,now());
                if (!written) co_return LoopResult{std::error_code{}, std::optional<AsyncHandshakeError>(written.error()==ClientHandshakeIoError::timeout ? AsyncHandshakeError::timeout : AsyncHandshakeError::protocol)};
                continue;
            }
            if (begin==end) {
                auto [error,n]=co_await socket.read_some(capy::mutable_buffer(buffer.data(),buffer.size()));
                if (error || n==0 || n>buffer.size()) {
                    if (capy::is_timeout(error)) { (void)handshake.cancel(); co_return LoopResult{error, std::optional<AsyncHandshakeError>(AsyncHandshakeError::timeout)}; }
                    auto tick2=handshake.tick(now());
                    if (!tick2) co_return LoopResult{error, std::optional<AsyncHandshakeError>(tick2.error()==ClientHandshakeIoError::timeout ? AsyncHandshakeError::timeout : AsyncHandshakeError::protocol)};
                    (void)handshake.finish_input(now()); co_return LoopResult{error, std::optional<AsyncHandshakeError>(AsyncHandshakeError::transport)};
                }
                begin=0; end=n;
            }
            auto result=handshake.feed(buffer.subspan(begin,end-begin),now());
            if (!result) co_return LoopResult{std::error_code{}, std::optional<AsyncHandshakeError>(result.error()==ClientHandshakeIoError::crypto_error ? AsyncHandshakeError::crypto : result.error()==ClientHandshakeIoError::timeout ? AsyncHandshakeError::timeout : result.error()==ClientHandshakeIoError::authentication_failed ? AsyncHandshakeError::authentication : AsyncHandshakeError::protocol)};
            if (!result->consumed) { (void)handshake.cancel(); co_return LoopResult{std::error_code{}, std::optional<AsyncHandshakeError>(AsyncHandshakeError::protocol)}; }
            begin+=result->consumed;
        }
        co_return LoopResult{std::error_code{}, std::nullopt};
    }

    // The owner keeps socket and handshake alive until completion and drains cancellation.
    // The handshake deadline must use the steady-clock millisecond epoch.
    template<class Socket>
    auto corosio_handshake(Socket& socket, ClientHandshakeIo& handshake)
        -> capy::task<std::expected<AsyncHandshakeResult,AsyncHandshakeError>> {
        try {
        auto max_ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::duration::max()).count();
        if (handshake.deadline()>static_cast<std::uint64_t>(max_ms)) { (void)handshake.cancel(); co_return std::unexpected(AsyncHandshakeError::protocol); }
        auto deadline=std::chrono::steady_clock::time_point(std::chrono::milliseconds(handshake.deadline()));
        std::array<std::uint8_t,4096> buffer;
        std::size_t begin=0, end=0;
        auto [timeout_ec, hs_err]=co_await corosio::timeout(corosio_handshake_loop(socket,handshake,buffer,begin,end),deadline);
        if (capy::is_timeout(timeout_ec)) { (void)handshake.cancel(); co_return std::unexpected(AsyncHandshakeError::timeout); }
        if (hs_err) co_return std::unexpected(*hs_err);
        auto app=handshake.take_application_records(); if (!app) co_return std::unexpected(AsyncHandshakeError::protocol);
        co_return AsyncHandshakeResult{std::move(*app),crypto::Bytes(buffer.begin()+static_cast<std::ptrdiff_t>(begin),buffer.begin()+static_cast<std::ptrdiff_t>(end))};
        } catch (...) { (void)handshake.cancel(); throw; }
    }
}

export namespace tls::detail {
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
        auto start() -> capy::task<std::expected<void,AsyncHandshakeError>> {
            if (state_!=State::initial || canceled_) co_return std::unexpected(AsyncHandshakeError::protocol);
            state_=State::handshaking;
            try {
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
            } catch (...) {
                if (handshake_) (void)handshake_->cancel();
                handshake_.reset(); application_.reset(); negotiated_.reset(); state_=State::stopped; throw;
            }
        }
    };
}


export namespace tls::detail {
    // Owns the socket from numeric-endpoint connect through authenticated TLS. All calls
    // run on one executor; cancel and drain start/application operations before destruction.
    class OwnedClient {
        enum class State { initial, connecting, handshaking, ready, stopped } state_=State::initial;
        std::uint64_t deadline_ms_;
        corosio::tcp_socket socket_;
        ClientConnection<corosio::tcp_socket> client_;
        bool canceled_=false;
    public:
        OwnedClient(corosio::io_context& context, ClientHandshakeIo&& handshake);
        ~OwnedClient();
        OwnedClient(OwnedClient const&)=delete;
        auto operator=(OwnedClient const&) -> OwnedClient& = delete;
        [[nodiscard]] auto idle() const noexcept -> bool { return state_!=State::connecting && state_!=State::handshaking && client_.idle(); }
        [[nodiscard]] auto client() noexcept -> ClientConnection<corosio::tcp_socket>* { return state_==State::ready ? &client_ : nullptr; }
        [[nodiscard]] auto socket() noexcept -> corosio::tcp_socket* { return state_==State::ready ? &socket_ : nullptr; }
        // Connection policy may configure the physical socket before start().
        [[nodiscard]] auto unconnected_socket() noexcept -> corosio::tcp_socket* { return state_==State::initial && !canceled_ ? &socket_ : nullptr; }
        auto cancel() noexcept -> void;
        auto start(corosio::endpoint endpoint,platform::TcpSocketOptions const* interfaces=nullptr)
            -> capy::task<std::expected<void,AsyncHandshakeError>>;
    };
}
