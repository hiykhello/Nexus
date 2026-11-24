// Reply transmission helpers for stream datagram routing.
module;
#if defined(__linux__)
#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <boost/corosio/posix_stream_descriptor.hpp>
#include <boost/corosio/wait_type.hpp>
#endif
export module net.stream_datagram_reply;
import std;
import capy;
import corosio;
import net.datagram_frame;
import net.udp_direct;
import platform.stream_peer;

export namespace net::stream_datagrams {
    using Clock = std::chrono::steady_clock;
    namespace capy = ::capy;
    namespace io = ::corosio;

    struct UnmeteredDatagram {
        auto submit() noexcept -> void {}
        auto complete(std::size_t) noexcept -> void {}
    };

    template<class Session>
    auto reserve_datagram_bytes(Session& session, bool upstream, std::size_t size) {
        if constexpr (requires { session.reserve_principal_datagram(upstream, size); })
            return session.reserve_principal_datagram(upstream, size);
        else
            return std::optional<UnmeteredDatagram>(std::in_place);
    }

    template<class State>
    auto count_download(State& state, std::size_t payload_size) -> void {
        // Some transports return success for a deliberate drop and report
        // delivery at their own write-completion boundary.
        if constexpr (!requires { state.incoming.accounts_download; })
            state.session.count_traffic(false, payload_size);
    }

    template<class State>
    auto send_reply(State& state, ProxyAddress const& address, std::span<std::uint8_t const> payload,
        Clock::time_point deadline = Clock::now() + std::chrono::seconds(300)) -> capy::task<bool> {
        using namespace std::chrono_literals;
        // A transport with asynchronous datagram completion reserves and
        // settles its own replies, including deliberate transport drops.
        if constexpr (requires { state.incoming.accounts_download; }) {
            if (!co_await state.incoming.send_packet(address, payload)) co_return false;
            state.session.touched = Clock::now();
            co_return true;
        }
        auto credit = reserve_datagram_bytes(state.session, false, payload.size());
        if (!credit) {
            auto [error] = co_await io::delay(1ms);
            co_return !error && !state.session.closed;
        }
        if constexpr (requires { state.incoming.send_packet(address, payload); }) {
            credit->submit();
            if (!co_await state.incoming.send_packet(address, payload)) co_return false;
        } else {
            auto wire = encode_datagram(state.framing, address, payload);
            if (!wire) co_return false;
            credit->submit();
            if (!co_await state.incoming.send(*wire, deadline)) co_return false;
        }
        credit->complete(payload.size());
        count_download(state, payload.size());
        state.session.touched = Clock::now();
        co_return true;
    }

    class DirectSocketWait {
#if defined(__linux__)
        int ep_ = -1, wake_rd_ = -1, wake_wr_ = -1;
        std::array<int, 2> watched_{-1, -1};
        std::optional<io::posix_stream_descriptor> desc_;
        bool stopped_ = false;
    public:
        explicit DirectSocketWait(io::io_context& ctx) {
            ep_ = ::epoll_create1(EPOLL_CLOEXEC);
            int pfds[2]{-1, -1};
            if (ep_ >= 0 && ::pipe2(pfds, O_NONBLOCK | O_CLOEXEC) == 0) {
                wake_rd_ = pfds[0]; wake_wr_ = pfds[1];
                epoll_event ev{.events = EPOLLIN, .data = {.fd = wake_rd_}};
                if (::epoll_ctl(ep_, EPOLL_CTL_ADD, wake_rd_, &ev) != 0) {
                    ::close(wake_rd_); ::close(wake_wr_); wake_rd_ = wake_wr_ = -1;
                }
            }
            if (ep_ >= 0) {
                desc_.emplace(ctx);
                if (desc_->assign(ep_)) { desc_.reset(); ::close(ep_); ep_ = -1; }
            }
        }
        ~DirectSocketWait() { stop(); desc_.reset(); ep_ = -1; }
        DirectSocketWait(DirectSocketWait const&) = delete;
        auto operator=(DirectSocketWait const&) -> DirectSocketWait& = delete;
        auto watch(std::array<int, 2> fds) noexcept -> void {
            if (stopped_ || ep_ < 0) return;
            for (std::size_t i = 0; i < 2; ++i) {
                if (fds[i] >= 0 && fds[i] != watched_[i]) {
                    if (watched_[i] >= 0) (void)::epoll_ctl(ep_, EPOLL_CTL_DEL, watched_[i], nullptr);
                    epoll_event ev{.events = EPOLLIN, .data = {.fd = fds[i]}};
                    if (::epoll_ctl(ep_, EPOLL_CTL_ADD, fds[i], &ev) == 0) watched_[i] = fds[i];
                }
            }
        }
        auto notify() const noexcept -> void {
            if (wake_wr_ >= 0) { char b = 1; (void)::write(wake_wr_, &b, 1); }
        }
        auto wait(bool brief) -> capy::task<bool> {
            using namespace std::chrono_literals;
            if (stopped_) co_return false;
            if (!desc_) { auto [ec] = co_await io::delay(brief ? 1ms : 5ms); co_return !ec && !stopped_; }
            if (brief) { co_await io::delay(1ms); co_return !stopped_; }
            auto [ec] = co_await desc_->wait(io::wait_type::read);
            if (wake_rd_ >= 0) { std::array<char, 64> buf{}; while (::read(wake_rd_, buf.data(), buf.size()) > 0) {} }
            co_return !ec && !stopped_;
        }
        auto stop() noexcept -> void {
            if (stopped_) return;
            stopped_ = true;
            notify();
            if (desc_) desc_->close();
            if (wake_rd_ >= 0) { ::close(wake_rd_); wake_rd_ = -1; }
            if (wake_wr_ >= 0) { ::close(wake_wr_); wake_wr_ = -1; }
        }
#else
        capy::async_event wake_;
        bool stopped_ = false;
    public:
        explicit DirectSocketWait(io::io_context&) noexcept {}
        DirectSocketWait(DirectSocketWait const&) = delete;
        auto operator=(DirectSocketWait const&) -> DirectSocketWait& = delete;
        auto watch(std::array<int, 2>) noexcept -> void {}
        auto notify() noexcept -> void { wake_.set(); }
        auto wait(bool brief) -> capy::task<bool> {
            using namespace std::chrono_literals;
            if (stopped_) co_return false;
            wake_.clear();
            auto [ec] = co_await io::timeout(wake_.wait(), Clock::now() + (brief ? 1ms : 5ms));
            co_return !stopped_ && ec != std::errc::operation_canceled;
        }
        auto stop() noexcept -> void { stopped_ = true; wake_.set(); }
#endif
    };
}
