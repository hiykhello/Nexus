export module vision.corosio_writer;
import std;
import vision;
import vision.random;
import tls.corosio_application;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace vision::detail {
    // Owns the sole output path. The connection, socket and shared filter live
    // until every operation is drained. A concurrent TLS reader must serialize
    // its KeyUpdate flush through flush_control(); all calls use one executor.
    template<class Socket>
    class Writer {
        Socket& socket_;
        tls::detail::ApplicationConnection<Socket>& tls_;
        TrafficFilter& filter_;
        Sender sender_;
        nex::capy::async_mutex mutex_;
        bool canceled_=false, closed_=false;
        auto fail() noexcept -> void { canceled_=true; tls_.cancel(); socket_.cancel(); }
        auto flush_pending(tls::detail::ApplicationDeadline deadline) -> nex::capy::task<bool> {
            while (tls_.pending_output()) if (!co_await tls_.flush(deadline)) co_return false;
            co_return true;
        }
    public:
        Writer(Socket& socket,tls::detail::ApplicationConnection<Socket>& tls,TrafficFilter& filter,UserId user)
            : socket_(socket),tls_(tls),filter_(filter),sender_(user) {}
        Writer(Writer const&)=delete;
        auto operator=(Writer const&) -> Writer& = delete;
        auto cancel() noexcept -> void { if (!canceled_) fail(); }
        [[nodiscard]] auto status() const noexcept -> SendStatus { return sender_.status(); }
        auto flush_control(tls::detail::ApplicationDeadline deadline={}) -> nex::capy::task<bool> {
            auto [error,guard]=co_await mutex_.scoped_lock();
            if (error || canceled_) co_return false;
            // A concurrent write or close may have flushed the response and detached TLS
            // while this reader waited for the lock. No TLS output can be added
            // after detachment; a later requested update fails in the TLS reader.
            if (closed_ || sender_.status()==SendStatus::direct) co_return !tls_.pending_output();
            if (!co_await flush_pending(deadline)) { fail(); co_return false; }
            co_return true;
        }
        // The input remains alive until completion. On failure some bytes may
        // have been written; callers must cancel, not retry the same input.
        auto write(std::span<std::uint8_t const> data,tls::detail::ApplicationDeadline deadline={}) -> nex::capy::task<bool> {
            auto [error,guard]=co_await mutex_.scoped_lock();
            if (error || canceled_ || closed_ || data.empty()) co_return false;
            try {
                while (!data.empty()) {
                    auto count=std::min<std::size_t>(8192,data.size());
                    auto part=data.first(count);
                    if (sender_.status()==SendStatus::direct) {
                        auto op=socket_.write_some(nex::capy::const_buffer(part.data(),part.size()));
                        auto [ec,n]=deadline ? co_await nex::corosio::timeout(std::move(op),*deadline) : co_await std::move(op);
                        if (ec || !n || n>part.size() || canceled_) { fail(); co_return false; }
                        data=data.subspan(n); continue;
                    }
                    filter_.observe(part);
                    auto block=count>=8171 ? prepare_large_secure(sender_,filter_,part) : prepare_secure(sender_,filter_,part);
                    if (!block) { fail(); co_return false; }
                    auto sent=co_await tls_.send_all(block->wire,deadline);
                    (void)sender_.commit(sent.has_value() && !canceled_);
                    if (!sent || canceled_) { fail(); co_return false; }
                    if (sender_.status()==SendStatus::direct) {
                        if (!co_await flush_pending(deadline) || !tls_.detach_output()) { fail(); co_return false; }
                    }
                    data=data.subspan(count);
                }
                co_return true;
            } catch (...) { fail(); throw; }
        }
        auto close_output(tls::detail::ApplicationDeadline deadline={}) -> nex::capy::task<bool> {
            auto [error,guard]=co_await mutex_.scoped_lock();
            if (error || canceled_ || closed_) co_return false;
            closed_=true;
            if (!co_await flush_pending(deadline)) { fail(); co_return false; }
            if (sender_.status()==SendStatus::direct) {
                if constexpr (requires { socket_.close_output_some(); }) {
                    auto operation=socket_.close_output_some();
                    auto [error,n]=deadline ? co_await nex::corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
                    if (error || n || canceled_) { fail(); co_return false; }
                } else if (socket_.shutdown(nex::corosio::shutdown_send)) { fail(); co_return false; }
            } else if (!co_await tls_.close_notify(deadline)) { fail(); co_return false; }
            co_return true;
        }
    };
}
