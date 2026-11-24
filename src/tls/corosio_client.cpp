module tls.corosio_client;
import std;
import net.tcp_connect;
import platform.socket_options;
import tls.client_handshake_io;
import tls.corosio_application;
import capy;
import corosio;

namespace tls::detail {
    OwnedClient::OwnedClient(corosio::io_context& context,ClientHandshakeIo&& handshake)
        : deadline_ms_(handshake.deadline()),socket_(context),client_(socket_,std::move(handshake)) {}
    OwnedClient::~OwnedClient()=default;
    auto OwnedClient::cancel() noexcept -> void {
        if (canceled_) return;
        canceled_=true;
        if (state_==State::connecting) socket_.cancel();
        client_.cancel();
        if (state_!=State::connecting && state_!=State::handshaking) state_=State::stopped;
    }
    auto OwnedClient::start(corosio::endpoint endpoint,platform::TcpSocketOptions const* interfaces) -> capy::task<std::expected<void,AsyncHandshakeError>> {
        if (state_!=State::initial || canceled_) co_return std::unexpected(AsyncHandshakeError::protocol);
        auto max_ms=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::duration::max()).count();
        if (deadline_ms_>static_cast<std::uint64_t>(max_ms)) { cancel(); co_return std::unexpected(AsyncHandshakeError::protocol); }
        auto deadline=std::chrono::steady_clock::time_point(std::chrono::milliseconds(deadline_ms_));
        if (std::chrono::steady_clock::now()>=deadline) { cancel(); co_return std::unexpected(AsyncHandshakeError::timeout); }
        state_=State::connecting;
        try {
            std::error_code error;
            bool preparation_failed=false;
            if (interfaces) {
                auto candidates=net::connect_tcp_candidates(socket_,std::array{endpoint},
                    [](auto const&,auto const&) {return true;},*interfaces,preparation_failed,deadline);
                auto [result,selected]=co_await corosio::timeout(std::move(candidates),deadline);
                (void)selected;
                error=result;
            } else {
                auto [result]=co_await corosio::timeout(socket_.connect(endpoint),deadline);
                error=result;
            }
            if (error || canceled_ || std::chrono::steady_clock::now()>=deadline) {
                auto timed_out=!canceled_ && (capy::is_timeout(error) || std::chrono::steady_clock::now()>=deadline);
                client_.cancel(); socket_.close(); state_=State::stopped;
                if (timed_out) co_return std::unexpected(AsyncHandshakeError::timeout);
                co_return std::unexpected(preparation_failed ? AsyncHandshakeError::socket_policy : AsyncHandshakeError::transport);
            }
            if (!interfaces) platform::tune_tcp_low_latency(socket_.native_handle());
            state_=State::handshaking;
            auto result=co_await client_.start();
            if (canceled_ || !result) {
                auto failure=canceled_ ? AsyncHandshakeError::transport : result.error();
                client_.cancel(); socket_.close(); state_=State::stopped;
                co_return std::unexpected(failure);
            }
            state_=State::ready;
            co_return std::expected<void,AsyncHandshakeError>{};
        } catch (...) { client_.cancel(); socket_.close(); state_=State::stopped; throw; }
    }
}
