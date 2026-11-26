module;
#include <fcntl.h>
#include <unistd.h>
export module tailscale.netlink_worker;
import std;
import packet.tun_linux;
import packet.tun_network;
import packet.tun_network_types;

export namespace tailscale::wireguard_tun_detail {
    using Clock = std::chrono::steady_clock;

    class NetlinkWorker {
        using Lease = packet::TunNetworkLease<>;
        enum class Op { none, apply, revoke };
        std::string interface_;
        std::optional<packet::LinuxTun> device_;
        std::optional<Lease> lease_;
        mutable std::mutex mutex_;
        std::condition_variable cv_;
        std::thread worker_;
        int notify_rd_ = -1, notify_wr_ = -1, tun_fd_ = -1;
        std::uint64_t desired_gen_ = 0, completed_gen_ = 0;
        Op desired_op_ = Op::none;
        packet::TunNetworkOptions desired_network_{};
        std::optional<packet::TunNetworkOptions> applied_network_;
        bool need_revoke_ = false, busy_ = false, failed_ = false, shutdown_ = false;

        auto wake() noexcept -> void { if (notify_wr_ >= 0) { char b = 1; (void)::write(notify_wr_, &b, 1); } }
        auto close_pipes() noexcept -> void {
            if (notify_rd_ >= 0) { ::close(notify_rd_); notify_rd_ = -1; }
            if (notify_wr_ >= 0) { ::close(notify_wr_); notify_wr_ = -1; }
        }
        auto stop_lease() noexcept -> bool {
            bool ok = true;
            if (lease_) {
                auto report = lease_->stop(Clock::now() + std::chrono::seconds(2));
                if (report.total || !lease_->drained()) ok = false;
                lease_.reset();
            }
            device_.reset();
            return ok;
        }
        auto apply_lease(packet::TunNetworkOptions const& network) -> bool {
            auto apply = Clock::now() + std::chrono::milliseconds(750), rollback = apply + std::chrono::seconds(1);
            if (lease_) {
                if (network == lease_->network_options() || lease_->replace(network, apply, rollback).has_value()) return true;
                (void)stop_lease(); return false;
            }
            auto tun = packet::LinuxTun::create(interface_);
            if (!tun) return false;
            device_.emplace(std::move(*tun));
            auto token = device_->claim_network();
            if (!token || !Lease::emplace_into(lease_, std::move(*token), network) || !lease_->start(apply, rollback)) {
                (void)stop_lease(); return false;
            }
            return true;
        }
        auto run() noexcept -> void {
            std::unique_lock lock(mutex_);
            for (;;) {
                cv_.wait(lock, [&] { return shutdown_ || need_revoke_ || desired_gen_ != completed_gen_; });
                if (need_revoke_ || shutdown_) {
                    auto gen = desired_gen_; bool ending = shutdown_; need_revoke_ = false; busy_ = true; tun_fd_ = -1; applied_network_.reset();
                    lock.unlock(); bool ok = stop_lease(); lock.lock();
                    if (!ok) failed_ = true;
                    if (desired_op_ == Op::revoke && desired_gen_ == gen) { completed_gen_ = gen; busy_ = false; wake(); }
                    if (ending && !need_revoke_) { busy_ = false; break; }
                    continue;
                }
                if (failed_) { completed_gen_ = desired_gen_; busy_ = false; wake(); continue; }
                if (desired_gen_ == completed_gen_) continue;
                auto gen = desired_gen_; auto op = desired_op_; auto network = desired_network_; busy_ = true;
                lock.unlock();
                bool ok = op == Op::apply ? apply_lease(network) : stop_lease();
                int fd = ok && lease_ ? lease_->native_handle() : -1;
                lock.lock();
                if (!ok) {
                    failed_ = true; tun_fd_ = -1; applied_network_.reset(); completed_gen_ = desired_gen_; busy_ = false; wake();
                } else if (desired_gen_ == gen && !need_revoke_ && !shutdown_) {
                    tun_fd_ = fd;
                    if (op == Op::apply) applied_network_ = network; else applied_network_.reset();
                    completed_gen_ = gen; busy_ = false; wake();
                }
            }
        }
        auto ensure_started() noexcept -> bool {
            if (worker_.joinable()) return true;
            int pfds[2]{-1, -1};
            if (::pipe2(pfds, O_NONBLOCK | O_CLOEXEC) == 0) { notify_rd_ = pfds[0]; notify_wr_ = pfds[1]; }
            try { worker_ = std::thread([this] { run(); }); return true; }
            catch (...) { close_pipes(); std::lock_guard lock(mutex_); failed_ = true; return false; }
        }
    public:
        explicit NetlinkWorker(std::string_view iface) : interface_(iface) {}
        ~NetlinkWorker() { shutdown_and_join(); }
        auto request_apply(packet::TunNetworkOptions const& network) noexcept -> bool {
            if (!ensure_started()) return false;
            { std::lock_guard lock(mutex_); if (failed_) return false; desired_op_ = Op::apply; desired_network_ = network; ++desired_gen_; busy_ = true; }
            cv_.notify_one(); return true;
        }
        auto request_revoke() noexcept -> void {
            if (!worker_.joinable()) return;
            { std::lock_guard lock(mutex_); need_revoke_ = true; desired_op_ = Op::revoke; ++desired_gen_; busy_ = true; }
            cv_.notify_one();
        }
        auto shutdown_and_join() noexcept -> void {
            if (worker_.joinable()) {
                { std::lock_guard lock(mutex_); shutdown_ = true; need_revoke_ = true; desired_op_ = Op::revoke; ++desired_gen_; }
                cv_.notify_one(); worker_.join();
            }
            close_pipes();
        }
        struct Sync { bool failed = false, ready = false; int tun_fd = -1; std::optional<packet::TunNetworkOptions> network; };
        auto sync() noexcept -> Sync {
            if (notify_rd_ >= 0) { char buf[64]; while (::read(notify_rd_, buf, sizeof(buf)) > 0) {} }
            std::lock_guard lock(mutex_);
            Sync out{.failed = failed_};
            if (!failed_ && !busy_ && completed_gen_ == desired_gen_ && desired_op_ == Op::apply && tun_fd_ >= 0) {
                out.ready = true; out.tun_fd = tun_fd_; out.network = applied_network_;
            }
            return out;
        }
        auto failed() const noexcept -> bool { std::lock_guard lock(mutex_); return failed_; }
        auto pending() const noexcept -> bool { std::lock_guard lock(mutex_); return busy_ || desired_gen_ != completed_gen_; }
        auto notify_fd() const noexcept -> int { return notify_rd_; }
    };
}
