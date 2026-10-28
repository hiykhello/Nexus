export module nexus.tls.corosio_server_handshake;
export import nexus.memory.budget;
import std;
import nexus.tls.server_handshake_io;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
export namespace nexus::tls::detail {
    enum class ServerAsyncError { transport, protocol, timeout, budget_exceeded };
    struct ServerAsyncResult {
        ApplicationRecords records;
        std::optional<memory::Budget::Reservation> unread_reservation;
        crypto::Bytes unread;
        // Release after the unread allocation has been destroyed or transferred
        // to an independently charged owner. Keep this result alive until then.
        auto release_unread_reservation() noexcept -> bool {
            if (unread.capacity()!=0) return false;
            unread_reservation.reset(); return true;
        }
    };
    // Socket and handshake must outlive this operation; cancel the socket and drain completion before destruction.
    // The deadline uses the steady-clock millisecond epoch. Returned unread bytes belong to the application reader.
    template<class Socket>
    auto server_handshake(Socket& socket, ServerHandshakeIo& handshake, std::shared_ptr<memory::Budget> budget = {}) -> nex::capy::task<std::expected<ServerAsyncResult,ServerAsyncError>> {
        try {
        auto handshake_budget=handshake.budget();
        if (handshake_budget && budget && handshake_budget!=budget) { (void)handshake.cancel(); co_return std::unexpected(ServerAsyncError::protocol); }
        if (!budget) budget=std::move(handshake_budget);
        auto io_error=[](ServerHandshakeIoError error) {
            return error==ServerHandshakeIoError::timeout ? ServerAsyncError::timeout :
                   error==ServerHandshakeIoError::budget_exceeded ? ServerAsyncError::budget_exceeded : ServerAsyncError::protocol;
        };
        auto now=[] { return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count()); };
        auto maximum=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::duration::max()).count();
        if (handshake.deadline()>static_cast<std::uint64_t>(maximum)) { (void)handshake.cancel(); co_return std::unexpected(ServerAsyncError::protocol); }
        auto deadline=std::chrono::steady_clock::time_point(std::chrono::milliseconds(handshake.deadline()));
        std::optional<memory::Budget::Reservation> read_reservation;
        if (budget) {
            read_reservation=memory::Budget::reserve(budget,4096);
            if (!read_reservation) { (void)handshake.cancel(); co_return std::unexpected(ServerAsyncError::budget_exceeded); }
        }
        std::array<std::uint8_t,4096> buffer{}; std::size_t begin=0,end=0;
        while (!handshake.complete()) {
            auto tick=handshake.tick(now());
            if (!tick) co_return std::unexpected(io_error(tick.error()));
            if (!handshake.pending_output().empty()) {
                auto pending=handshake.pending_output();
                std::optional<memory::Budget::Reservation> write_reservation;
                if (budget) {
                    write_reservation=memory::Budget::reserve(budget,pending.size());
                    if (!write_reservation) { (void)handshake.cancel(); co_return std::unexpected(ServerAsyncError::budget_exceeded); }
                }
                crypto::Bytes owned(pending.begin(),pending.end());
                auto [error,n]=co_await nex::corosio::timeout(socket.write_some(nex::capy::const_buffer(owned.data(),owned.size())),deadline);
                if (error || !n || n>owned.size()) {
                    if (nex::capy::is_timeout(error)) { (void)handshake.cancel(); co_return std::unexpected(ServerAsyncError::timeout); }
                    auto tick=handshake.tick(now());
                    if (!tick) co_return std::unexpected(io_error(tick.error()));
                    (void)handshake.cancel(); co_return std::unexpected(ServerAsyncError::transport);
                }
                auto written=handshake.written(n,now());
                if (!written) co_return std::unexpected(io_error(written.error()));
                continue;
            }
            if (begin==end) {
                auto [error,n]=co_await nex::corosio::timeout(socket.read_some(nex::capy::mutable_buffer(buffer.data(),buffer.size())),deadline);
                if (error || !n || n>buffer.size()) {
                    if (nex::capy::is_timeout(error)) { (void)handshake.cancel(); co_return std::unexpected(ServerAsyncError::timeout); }
                    auto tick=handshake.tick(now());
                    if (!tick) co_return std::unexpected(io_error(tick.error()));
                    (void)handshake.finish_input(now()); co_return std::unexpected(ServerAsyncError::transport);
                }
                begin=0; end=n;
            }
            auto result=handshake.feed(std::span{buffer}.subspan(begin,end-begin),now());
            if (!result) co_return std::unexpected(io_error(result.error()));
            if (!result->consumed) { (void)handshake.cancel(); co_return std::unexpected(ServerAsyncError::protocol); }
            begin+=result->consumed;
        }
        auto app=handshake.take_application_records(); if (!app) co_return std::unexpected(ServerAsyncError::protocol);
        std::optional<memory::Budget::Reservation> unread_reservation;
        if (budget && begin!=end) {
            unread_reservation=memory::Budget::reserve(budget,end-begin);
            if (!unread_reservation) co_return std::unexpected(ServerAsyncError::budget_exceeded);
        }
        co_return ServerAsyncResult{std::move(*app),std::move(unread_reservation),crypto::Bytes(buffer.begin()+static_cast<std::ptrdiff_t>(begin),buffer.begin()+static_cast<std::ptrdiff_t>(end))};
        } catch (...) { (void)handshake.cancel(); throw; }
    }
}
