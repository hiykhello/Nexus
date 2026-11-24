// Event-driven descriptor & epoll wake helper for the TUN pump loop.
module;
#if !defined(_WIN32)
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/epoll.h>
#endif
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/corosio/posix_stream_descriptor.hpp>
#include <boost/corosio/wait_type.hpp>
#endif

export module cli.tun_event_wait;
import std;
import capy;
import corosio;
import udp;

export namespace cli::tun_enabled {
    struct UdpWatchKey {
        bool is_v6 = false;
        bool is_alias = false;
        udp::FlowId flow = 0;
    };

    class TunEventWait {
#if !defined(_WIN32)
        struct Watcher {
            std::optional<corosio::posix_stream_descriptor> desc;
            bool in_flight = false;
        };
        struct SharedState {
            corosio::io_context* io = nullptr;
            std::atomic_bool stopped{false};
            std::atomic_bool uring_stopped{false};
            std::atomic_bool wake_pipe_ready{false};
            std::array<Watcher, 4> watchers{};
        };
        std::shared_ptr<SharedState> state_;
        corosio::io_context* io_ = nullptr;
        int wake_rd_ = -1, wake_wr_ = -1;
        int tun_dup_ = -1;
        int uring_dup_ = -1;
        mutable std::mutex wake_mu_;
        mutable std::atomic_bool wake_written_{false};
#if defined(__linux__)
        int udp_ep_ = -1;
        std::unordered_map<int, UdpWatchKey> udp_map_;
#endif

        static auto wait_once(std::shared_ptr<SharedState> st, std::size_t idx) -> capy::task<> {
            auto& w = st->watchers[idx];
            if (w.desc) (void)co_await w.desc->wait(corosio::wait_type::read);
            if (!st->stopped.load(std::memory_order_acquire) &&
                !(idx == 3 && st->uring_stopped.load(std::memory_order_acquire))) {
                if (idx == 0) st->wake_pipe_ready.store(true, std::memory_order_release);
                if (st->io) st->io->stop();
            }
        }

        auto init_watcher(std::size_t idx, int raw_fd) -> bool {
            if (!state_ || raw_fd < 0 || !io_) return false;
            auto& w = state_->watchers[idx];
            w.desc.emplace(*io_);
            if (w.desc->assign(raw_fd)) { w.desc.reset(); return false; }
            return true;
        }

        auto arm_one(std::size_t idx) -> void {
            if (!state_ || state_->stopped.load(std::memory_order_acquire) || !io_) return;
            if (idx == 3 && state_->uring_stopped.load(std::memory_order_acquire)) return;
            auto& w = state_->watchers[idx];
            if (!w.desc || w.in_flight) return;
            w.in_flight = true;
            auto st = state_;
            auto finish = [st, idx]() noexcept {
                st->watchers[idx].in_flight = false;
                if (st->stopped.load(std::memory_order_acquire) ||
                    (idx == 3 && st->uring_stopped.load(std::memory_order_acquire)))
                    st->watchers[idx].desc.reset();
            };
            try {
                capy::run_async(io_->get_executor(),
                    [finish]() noexcept { finish(); },
                    [finish](std::exception_ptr) noexcept { finish(); })(wait_once(st, idx));
            } catch (...) { w.in_flight = false; }
        }
#endif
    public:
        TunEventWait() noexcept = default;
        TunEventWait(TunEventWait const&) = delete;
        auto operator=(TunEventWait const&) -> TunEventWait& = delete;
        ~TunEventWait() { stop(); }

        auto start(corosio::io_context& io, int tun_fd, int uring_fd = -1) -> void {
#if !defined(_WIN32)
            if (state_ || io_) stop();
            io_ = &io;
            state_ = std::make_shared<SharedState>();
            state_->io = &io;
            int pfds[2]{-1, -1};
#if defined(__linux__)
            if (::pipe2(pfds, O_NONBLOCK | O_CLOEXEC) == 0) {
#else
            if (::pipe(pfds) == 0) {
                for (int fd : pfds) {
                    (void)::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
                    (void)::fcntl(fd, F_SETFD, FD_CLOEXEC);
                }
#endif
                if (init_watcher(0, pfds[0])) {
                    wake_rd_ = pfds[0];
                    std::lock_guard lock(wake_mu_);
                    wake_wr_ = pfds[1];
                } else {
                    ::close(pfds[0]);
                    ::close(pfds[1]);
                }
            }
            if (tun_fd >= 0) {
                int dup_fd = ::fcntl(tun_fd, F_DUPFD_CLOEXEC, 0);
                if (dup_fd >= 0) {
                    if (init_watcher(1, dup_fd)) tun_dup_ = dup_fd;
                    else ::close(dup_fd);
                }
            }
#if defined(__linux__)
            udp_ep_ = ::epoll_create1(EPOLL_CLOEXEC);
            if (udp_ep_ >= 0 && !init_watcher(2, udp_ep_)) {
                ::close(udp_ep_);
                udp_ep_ = -1;
            }
            if (uring_fd >= 0) {
                int dup_fd = ::fcntl(uring_fd, F_DUPFD_CLOEXEC, 0);
                if (dup_fd >= 0) {
                    if (init_watcher(3, dup_fd)) uring_dup_ = dup_fd;
                    else ::close(dup_fd);
                }
            }
#else
            (void)uring_fd;
#endif
#else
            (void)io; (void)tun_fd; (void)uring_fd;
#endif
        }

        auto stop_uring() noexcept -> void {
#if !defined(_WIN32)
            if (!state_ || uring_dup_ < 0) return;
            state_->uring_stopped.store(true, std::memory_order_release);
            auto& w = state_->watchers[3];
            if (w.desc) {
                w.desc->close();
                if (!w.in_flight) w.desc.reset();
            }
            uring_dup_ = -1;
#endif
        }

        auto notify_async() const noexcept -> void {
#if !defined(_WIN32)
            std::lock_guard lock(wake_mu_);
            if (wake_wr_ >= 0) {
                wake_written_.store(true, std::memory_order_release);
                char b = 1;
                (void)::write(wake_wr_, &b, 1);
            }
#endif
        }

        // Fast zero-syscall wakeup when invoked directly on the TUN pump thread.
        auto wake_local() noexcept -> void {
#if !defined(_WIN32)
            if (state_ && !state_->stopped.load(std::memory_order_acquire) && io_) io_->stop();
#endif
        }

        auto drain_wake() noexcept -> void {
#if !defined(_WIN32)
            bool const dirty = (state_ && state_->wake_pipe_ready.exchange(false, std::memory_order_acq_rel)) |
                wake_written_.exchange(false, std::memory_order_acq_rel);
            if (wake_rd_ < 0 || !dirty) return;
            std::array<char, 64> junk;
            while (::read(wake_rd_, junk.data(), junk.size()) > 0) {}
#endif
        }

        auto arm() -> void {
#if !defined(_WIN32)
            if (!state_) return;
            for (std::size_t i = 0; i < state_->watchers.size(); ++i) arm_one(i);
#endif
        }

        [[nodiscard]] auto has_udp_epoll() const noexcept -> bool {
#if defined(__linux__)
            return udp_ep_ >= 0;
#else
            return false;
#endif
        }

        auto watch_udp(std::array<int, 2> fds, UdpWatchKey key) -> void {
#if defined(__linux__)
            if (udp_ep_ < 0) return;
            for (int fd : fds) {
                if (fd < 0 || udp_map_.contains(fd)) continue;
                epoll_event ev{.events = EPOLLIN, .data = {.fd = fd}};
                if (::epoll_ctl(udp_ep_, EPOLL_CTL_ADD, fd, &ev) == 0)
                    udp_map_.emplace(fd, key);
            }
#else
            (void)fds; (void)key;
#endif
        }

        auto unwatch_udp(std::array<int, 2> fds) noexcept -> void {
#if defined(__linux__)
            if (udp_ep_ < 0) return;
            for (int fd : fds) {
                if (fd < 0) continue;
                if (udp_map_.erase(fd)) (void)::epoll_ctl(udp_ep_, EPOLL_CTL_DEL, fd, nullptr);
            }
#else
            (void)fds;
#endif
        }

        template<class Fn>
        auto drain_ready_udp(Fn&& fn) -> bool {
#if defined(__linux__)
            if (udp_ep_ < 0 || udp_map_.empty()) return false;
            std::array<epoll_event, 64> evs;
            int n = ::epoll_wait(udp_ep_, evs.data(), static_cast<int>(evs.size()), 0);
            if (n <= 0) return false;
            for (int i = 0; i < n; ++i) {
                if (auto it = udp_map_.find(evs[i].data.fd); it != udp_map_.end())
                    fn(it->second);
            }
            return true;
#else
            (void)fn;
            return false;
#endif
        }

        auto stop() noexcept -> void {
#if !defined(_WIN32)
            auto st = std::move(state_);
            if (st) st->stopped.store(true, std::memory_order_release);
            {
                std::lock_guard lock(wake_mu_);
                if (wake_wr_ >= 0) {
                    wake_written_.store(true, std::memory_order_release);
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
            } else {
                if (wake_rd_ >= 0) ::close(wake_rd_);
                if (tun_dup_ >= 0) ::close(tun_dup_);
                if (uring_dup_ >= 0) ::close(uring_dup_);
#if defined(__linux__)
                if (udp_ep_ >= 0) ::close(udp_ep_);
#endif
            }
            wake_rd_ = -1;
            wake_written_.store(false, std::memory_order_relaxed);
            tun_dup_ = -1;
            uring_dup_ = -1;
#if defined(__linux__)
            udp_map_.clear();
            udp_ep_ = -1;
#endif
            io_ = nullptr;
#endif
        }
    };
}
