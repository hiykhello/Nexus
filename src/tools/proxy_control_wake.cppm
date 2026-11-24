// Event-driven control plane & self-pipe wakeup bridge for ProxyRun / ProxyHost.
module;
#if !defined(_WIN32)
#include <cerrno>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/posix_stream_descriptor.hpp>
#include <boost/corosio/wait_type.hpp>
#endif

export module cli.proxy_control_wake;
import std;
import capy;
import cli.proxy_run_state;
import corosio;

export namespace cli::run_detail {
    class ControlEventBridge {
#if !defined(_WIN32)
        struct Watcher {
            std::optional<corosio::posix_stream_descriptor> desc;
            bool in_flight = false;
        };
        struct SharedState {
            corosio::io_context* io = nullptr;
            std::atomic_bool detached{false};
            std::array<Watcher, 3> watchers{};
        };
        std::shared_ptr<SharedState> state_;
        corosio::io_context* io_ = nullptr;
        int wake_rd_ = -1, wake_wr_ = -1;
        int uds_fd_ = -1, http_fd_ = -1;

        static auto wait_once(std::shared_ptr<SharedState> st, std::size_t idx) -> capy::task<> {
            auto& w = st->watchers[idx];
            if (w.desc) (void)co_await w.desc->wait(corosio::wait_type::read);
            if (!st->detached.load(std::memory_order_acquire) && st->io) st->io->stop();
        }

        auto arm_one(std::size_t idx, int src_fd) -> void {
            if (src_fd < 0 || !io_ || !state_ || state_->detached.load(std::memory_order_acquire)) return;
            auto& w = state_->watchers[idx];
            if (!w.desc) {
                int dup_fd = ::fcntl(src_fd, F_DUPFD_CLOEXEC, 0);
                if (dup_fd < 0) return;
                int fl = ::fcntl(dup_fd, F_GETFL, 0);
                if (fl >= 0) (void)::fcntl(dup_fd, F_SETFL, fl | O_NONBLOCK);
                w.desc.emplace(*io_);
                if (w.desc->assign(dup_fd)) { ::close(dup_fd); w.desc.reset(); return; }
            }
            if (w.in_flight) return;
            w.in_flight = true;
            auto st = state_;
            auto finish = [st, idx]() noexcept {
                st->watchers[idx].in_flight = false;
                if (st->detached.load(std::memory_order_acquire)) st->watchers[idx].desc.reset();
            };
            try {
                capy::run_async(io_->get_executor(),
                    [finish]() noexcept { finish(); },
                    [finish](std::exception_ptr) noexcept { finish(); })(wait_once(st, idx));
            } catch (...) { w.in_flight = false; }
        }
#endif
    public:
        ControlEventBridge() noexcept = default;
        ControlEventBridge(ControlEventBridge const&) = delete;
        auto operator=(ControlEventBridge const&) -> ControlEventBridge& = delete;
        ~ControlEventBridge() { detach(); }

        auto attach(corosio::io_context* io, int uds_listen_fd, int http_listen_fd) noexcept -> void {
#if !defined(_WIN32)
            if (state_ || wake_rd_ >= 0 || wake_wr_ >= 0) detach();
            io_ = io;
            uds_fd_ = uds_listen_fd;
            http_fd_ = http_listen_fd;
            try {
                state_ = std::make_shared<SharedState>();
                state_->io = io;
            } catch (...) {
                state_.reset();
            }
            if (wake_rd_ < 0) {
                int fds[2]{-1, -1};
#if defined(__linux__)
                if (::pipe2(fds, O_NONBLOCK | O_CLOEXEC) == 0) {
#else
                if (::pipe(fds) == 0) {
                    for (int fd : fds) {
                        int fl = ::fcntl(fd, F_GETFL, 0);
                        if (fl >= 0) (void)::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
                        (void)::fcntl(fd, F_SETFD, FD_CLOEXEC);
                    }
#endif
                    std::lock_guard lock(wake_pipe_mutex());
                    wake_rd_ = fds[0];
                    wake_wr_ = fds[1];
                    wake_write_fd.store(wake_wr_, std::memory_order_seq_cst);
                }
            }
#else
            (void)io; (void)uds_listen_fd; (void)http_listen_fd;
#endif
        }

        [[nodiscard]] auto has_events() const noexcept -> bool {
#if !defined(_WIN32)
            return wake_rd_ >= 0 || uds_fd_ >= 0 || http_fd_ >= 0;
#else
            return false;
#endif
        }

        auto arm() -> void {
#if !defined(_WIN32)
            if (!io_ || !state_ || state_->detached.load(std::memory_order_acquire)) return;
            arm_one(0, wake_rd_);
            arm_one(1, uds_fd_);
            arm_one(2, http_fd_);
#endif
        }

        auto drain_wake_pipe() noexcept -> void {
#if !defined(_WIN32)
            if (wake_rd_ < 0) return;
            std::array<char, 64> junk{};
            while (::read(wake_rd_, junk.data(), junk.size()) > 0) {}
#endif
        }

        auto wait_idle(std::chrono::milliseconds wait) noexcept -> void {
#if !defined(_WIN32)
            std::array<pollfd, 3> pfds{};
            nfds_t n = 0;
            for (int fd : {wake_rd_, uds_fd_, http_fd_}) if (fd >= 0) pfds[n++] = {fd, POLLIN, 0};
            if (n > 0) {
                int ms = static_cast<int>(std::clamp<long long>(wait.count(), 0, 500));
                (void)::poll(pfds.data(), n, ms);
                drain_wake_pipe();
                return;
            }
#endif
            std::this_thread::sleep_for(std::min(wait, std::chrono::milliseconds(20)));
        }

        auto detach() noexcept -> void {
#if !defined(_WIN32)
            auto st = std::move(state_);
            if (st) st->detached.store(true, std::memory_order_release);
            {
                std::lock_guard lock(wake_pipe_mutex());
                if (wake_wr_ >= 0) {
                    int expected = wake_wr_;
                    (void)wake_write_fd.compare_exchange_strong(expected, -1, std::memory_order_seq_cst);
                    while (wake_write_inflight.load(std::memory_order_seq_cst) != 0)
                        std::this_thread::yield();
                    char b = 1;
                    (void)::write(wake_wr_, &b, 1);
                    ::close(wake_wr_);
                    wake_wr_ = -1;
                }
            }
            if (st) {
                for (auto& w : st->watchers) if (w.desc) w.desc->close();
                if (io_) {
                    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
                    while (std::ranges::any_of(st->watchers, [](auto const& w) { return w.in_flight; }) &&
                           std::chrono::steady_clock::now() < deadline) {
                        io_->restart();
                        if (!io_->poll()) (void)io_->run_for(std::chrono::milliseconds(5));
                    }
                }
                for (auto& w : st->watchers) {
                    if (!w.in_flight) w.desc.reset();
                }
                st->io = nullptr;
            }
            io_ = nullptr;
            if (wake_rd_ >= 0) { ::close(wake_rd_); wake_rd_ = -1; }
            uds_fd_ = -1;
            http_fd_ = -1;
#endif
        }
    };

    [[nodiscard]] inline auto compute_host_poll_wait(bool shared_driven, bool has_events, bool single_worker_multi_ctx,
        std::size_t listener_count, std::optional<std::chrono::milliseconds> uds_delay,
        std::optional<std::chrono::milliseconds> http_delay, bool has_retired, bool has_timers) noexcept
        -> std::chrono::milliseconds {
        using namespace std::chrono_literals;
        auto wait = (shared_driven || has_events) ? 500ms : 100ms;
        if (has_timers) wait = std::min(wait, 100ms);
        if (has_retired) wait = std::min(wait, 20ms);
        if (uds_delay) wait = std::min(wait, *uds_delay);
        if (http_delay) wait = std::min(wait, *http_delay);
        if (single_worker_multi_ctx && listener_count > 1)
            wait = std::max(1ms, wait / static_cast<long long>(listener_count));
        return wait;
    }
}
