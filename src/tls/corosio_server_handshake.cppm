export module nexus.tls.corosio_server_handshake;
import std;
import nexus.tls.server_handshake_io;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
export namespace nexus::tls::detail {
    enum class ServerAsyncError { transport, protocol, timeout };
    struct ServerAsyncResult { ApplicationRecords records; crypto::Bytes unread; };
    // Socket and handshake must outlive this operation; cancel the socket and drain completion before destruction.
    // The deadline uses the steady-clock millisecond epoch. Returned unread bytes belong to the application reader.
    template<class Socket>
    auto server_handshake(Socket& socket, ServerHandshakeIo& handshake) -> nex::capy::task<std::expected<ServerAsyncResult,ServerAsyncError>> {
        auto now=[] { return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()); };
        auto maximum=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::duration::max()).count();
        if (handshake.deadline()>static_cast<std::uint64_t>(maximum)) { (void)handshake.cancel(); co_return std::unexpected(ServerAsyncError::protocol); }
        auto deadline=std::chrono::steady_clock::time_point(std::chrono::milliseconds(handshake.deadline()));
        std::array<std::uint8_t,4096> buffer{}; std::size_t begin=0,end=0;
        while (!handshake.complete()) {
            auto tick=handshake.tick(now());
            if (!tick) co_return std::unexpected(tick.error()==ServerHandshakeIoError::timeout ? ServerAsyncError::timeout : ServerAsyncError::protocol);
            if (!handshake.pending_output().empty()) {
                auto pending=handshake.pending_output(); crypto::Bytes owned(pending.begin(),pending.end());
                auto [error,n]=co_await nex::corosio::timeout(socket.write_some(nex::capy::const_buffer(owned.data(),owned.size())),deadline);
                if (error || !n || n>owned.size()) {
                    if (nex::capy::is_timeout(error)) { (void)handshake.cancel(); co_return std::unexpected(ServerAsyncError::timeout); }
                    auto tick=handshake.tick(now());
                    if (!tick) co_return std::unexpected(tick.error()==ServerHandshakeIoError::timeout ? ServerAsyncError::timeout : ServerAsyncError::protocol);
                    (void)handshake.cancel(); co_return std::unexpected(ServerAsyncError::transport);
                }
                auto written=handshake.written(n,now());
                if (!written) co_return std::unexpected(written.error()==ServerHandshakeIoError::timeout ? ServerAsyncError::timeout : ServerAsyncError::protocol);
                continue;
            }
            if (begin==end) {
                auto [error,n]=co_await nex::corosio::timeout(socket.read_some(nex::capy::mutable_buffer(buffer.data(),buffer.size())),deadline);
                if (error || !n || n>buffer.size()) {
                    if (nex::capy::is_timeout(error)) { (void)handshake.cancel(); co_return std::unexpected(ServerAsyncError::timeout); }
                    auto tick=handshake.tick(now());
                    if (!tick) co_return std::unexpected(tick.error()==ServerHandshakeIoError::timeout ? ServerAsyncError::timeout : ServerAsyncError::protocol);
                    (void)handshake.finish_input(now()); co_return std::unexpected(ServerAsyncError::transport);
                }
                begin=0; end=n;
            }
            auto result=handshake.feed(std::span{buffer}.subspan(begin,end-begin),now());
            if (!result) co_return std::unexpected(result.error()==ServerHandshakeIoError::timeout ? ServerAsyncError::timeout : ServerAsyncError::protocol);
            if (!result->consumed) { (void)handshake.cancel(); co_return std::unexpected(ServerAsyncError::protocol); }
            begin+=result->consumed;
        }
        auto app=handshake.take_application_records(); if (!app) co_return std::unexpected(ServerAsyncError::protocol);
        co_return ServerAsyncResult{std::move(*app),crypto::Bytes(buffer.begin()+static_cast<std::ptrdiff_t>(begin),buffer.begin()+static_cast<std::ptrdiff_t>(end))};
    }
}
