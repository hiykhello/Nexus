module;
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

export module platform.tun_bridge;
import std;

export namespace platform {
    enum class TunBridgeError { closed, invalid_packet, queue_full };
    enum class PopOutboundStatus { ok, empty, buffer_too_small };
    struct PopOutboundResult {
        PopOutboundStatus status = PopOutboundStatus::empty;
        std::size_t size = 0;
    };
    using TunBridgeFailure = std::variant<TunBridgeError, std::error_code>;
    using TunBridgeOutputCallback = void (*)(std::uint8_t const* packet, std::size_t len, void* ctx);
    using TunBridgeWakeCallback = void (*)(void* ctx) noexcept;

    // Bounded userspace packet bridge for mobile PacketTunnel / embedded runtimes
    // (e.g., iOS NEPacketTunnelProvider NEPacketTunnelFlow).
    class ExternalTunBridge {
    public:
        static constexpr std::size_t max_queued_packets = 512;
    private:
        mutable std::mutex mutex_;
        std::condition_variable inflight_cv_;
        std::size_t inflight_ = 0;
        std::size_t wake_inflight_ = 0;
        std::deque<std::vector<std::uint8_t>> rx_;
        std::deque<std::vector<std::uint8_t>> tx_;
        std::atomic_bool closed_{false};
        std::uint16_t mtu_ = 1500;
        TunBridgeOutputCallback output_cb_ = nullptr;
        void* output_ctx_ = nullptr;
        TunBridgeWakeCallback wake_cb_ = nullptr;
        void* wake_ctx_ = nullptr;
    public:
        explicit ExternalTunBridge(std::uint16_t mtu = 1500, TunBridgeOutputCallback cb = nullptr,
            void* ctx = nullptr) noexcept
            : mtu_(std::clamp<std::uint16_t>(mtu, 68, 65535)), output_cb_(cb), output_ctx_(cb ? ctx : nullptr) {}

        ~ExternalTunBridge() { close(); }

        auto set_output_callback(TunBridgeOutputCallback cb, void* ctx = nullptr) noexcept -> void {
            std::unique_lock lock(mutex_);
            output_cb_ = cb;
            output_ctx_ = cb ? ctx : nullptr;
            inflight_cv_.wait(lock, [&] { return inflight_ == 0; });
        }

        auto set_wake_callback(TunBridgeWakeCallback cb, void* ctx = nullptr) noexcept -> void {
            std::unique_lock lock(mutex_);
            wake_cb_ = cb;
            wake_ctx_ = cb ? ctx : nullptr;
            inflight_cv_.wait(lock, [&] { return wake_inflight_ == 0; });
        }

        [[nodiscard]] auto read_packet(std::span<std::uint8_t> out)
            -> std::expected<std::optional<std::size_t>, TunBridgeFailure> {
            std::lock_guard lock(mutex_);
            if (rx_.empty()) {
                if (closed_.load(std::memory_order_acquire))
                    return std::unexpected(TunBridgeFailure{TunBridgeError::closed});
                return std::optional<std::size_t>{};
            }
            auto pkt = std::move(rx_.front());
            rx_.pop_front();
            if (pkt.size() > out.size())
                return std::unexpected(TunBridgeFailure{std::make_error_code(std::errc::message_size)});
            std::ranges::copy(pkt, out.begin());
            return std::optional<std::size_t>{pkt.size()};
        }

        [[nodiscard]] auto write_packet(std::span<std::uint8_t const> pkt)
            -> std::expected<void, TunBridgeFailure> {
            if (closed_.load(std::memory_order_acquire))
                return std::unexpected(TunBridgeFailure{TunBridgeError::closed});
            if (pkt.empty() || pkt.size() > mtu_ || pkt.size() > 65535)
                return std::unexpected(TunBridgeFailure{TunBridgeError::invalid_packet});
            TunBridgeOutputCallback cb = nullptr;
            void* ctx = nullptr;
            {
                std::lock_guard lock(mutex_);
                if (closed_.load(std::memory_order_acquire))
                    return std::unexpected(TunBridgeFailure{TunBridgeError::closed});
                cb = output_cb_;
                ctx = output_ctx_;
                if (!cb) {
                    if (tx_.size() >= max_queued_packets)
                        return std::unexpected(TunBridgeFailure{std::make_error_code(std::errc::no_buffer_space)});
                    tx_.emplace_back(pkt.begin(), pkt.end());
                    return {};
                }
                ++inflight_;
            }
            struct InflightGuard {
                ExternalTunBridge& self;
                ~InflightGuard() noexcept {
                    std::lock_guard lock(self.mutex_);
                    if (--self.inflight_ == 0) self.inflight_cv_.notify_all();
                }
            } guard{*this};
            cb(pkt.data(), pkt.size(), ctx);
            return {};
        }

        [[nodiscard]] auto inject_packet(std::span<std::uint8_t const> pkt)
            -> std::expected<void, TunBridgeFailure> {
            if (closed_.load(std::memory_order_acquire))
                return std::unexpected(TunBridgeFailure{TunBridgeError::closed});
            if (pkt.empty() || pkt.size() > mtu_ || pkt.size() > 65535)
                return std::unexpected(TunBridgeFailure{TunBridgeError::invalid_packet});
            TunBridgeWakeCallback wcb = nullptr;
            void* wctx = nullptr;
            {
                std::lock_guard lock(mutex_);
                if (closed_.load(std::memory_order_acquire))
                    return std::unexpected(TunBridgeFailure{TunBridgeError::closed});
                if (rx_.size() >= max_queued_packets)
                    return std::unexpected(TunBridgeFailure{TunBridgeError::queue_full});
                rx_.emplace_back(pkt.begin(), pkt.end());
                wcb = wake_cb_;
                wctx = wake_ctx_;
                if (wcb) ++wake_inflight_;
            }
            if (wcb) {
                wcb(wctx);
                std::lock_guard lock(mutex_);
                if (--wake_inflight_ <= 1) inflight_cv_.notify_all();
            }
            return {};
        }

        [[nodiscard]] auto pop_outbound_checked(std::span<std::uint8_t> out) -> PopOutboundResult {
            std::lock_guard lock(mutex_);
            if (tx_.empty()) return {PopOutboundStatus::empty, 0};
            auto const& front = tx_.front();
            if (front.size() > out.size()) return {PopOutboundStatus::buffer_too_small, front.size()};
            auto size = front.size();
            std::ranges::copy(front, out.begin());
            tx_.pop_front();
            return {PopOutboundStatus::ok, size};
        }

        [[nodiscard]] auto pop_outbound(std::span<std::uint8_t> out) -> std::optional<std::size_t> {
            auto res = pop_outbound_checked(out);
            return res.status == PopOutboundStatus::ok ? std::optional<std::size_t>{res.size} : std::nullopt;
        }

        auto close() noexcept -> void {
            TunBridgeWakeCallback wcb = nullptr;
            void* wctx = nullptr;
            {
                std::unique_lock lock(mutex_);
                closed_.store(true, std::memory_order_release);
                output_cb_ = nullptr;
                output_ctx_ = nullptr;
                wcb = std::exchange(wake_cb_, nullptr);
                wctx = std::exchange(wake_ctx_, nullptr);
                rx_.clear();
                tx_.clear();
                if (wcb) ++wake_inflight_;
                inflight_cv_.wait(lock, [&] { return inflight_ == 0 && wake_inflight_ == (wcb ? 1u : 0u); });
            }
            if (wcb) {
                wcb(wctx);
                std::lock_guard lock(mutex_);
                if (--wake_inflight_ <= 1) inflight_cv_.notify_all();
            }
        }

        [[nodiscard]] auto closed() const noexcept -> bool { return closed_.load(std::memory_order_acquire); }
        [[nodiscard]] auto mtu() const noexcept -> std::uint16_t { return mtu_; }
        [[nodiscard]] static auto device_name() noexcept -> std::string_view { return "nexus-bridge"; }
    };

    struct ExternalTunFdOverride {
        int fd = -1;
        bool adopt = false;
        bool skip_ioctl = false;
    };

    namespace tun_bridge_detail {
        inline auto close_native_fd(int fd) noexcept -> void {
            if (fd < 0) return;
#ifdef _WIN32
            ::_close(fd);
#else
            ::close(fd);
#endif
        }

        struct GlobalState {
            std::mutex mutex;
            std::optional<ExternalTunFdOverride> fd_override;
            std::shared_ptr<ExternalTunBridge> bridge;

            ~GlobalState() noexcept {
                if (fd_override && fd_override->adopt && fd_override->fd >= 0) {
                    close_native_fd(fd_override->fd);
                }
            }
        };
        inline auto state() noexcept -> GlobalState& {
            static GlobalState instance;
            return instance;
        }
    }

    inline auto set_external_tun_fd(int fd, bool adopt, bool skip_ioctl) noexcept -> void {
        auto& s = tun_bridge_detail::state();
        std::lock_guard lock(s.mutex);
        if (s.fd_override && s.fd_override->adopt && s.fd_override->fd >= 0 && s.fd_override->fd != fd)
            tun_bridge_detail::close_native_fd(s.fd_override->fd);
        if (fd < 0) s.fd_override.reset();
        else s.fd_override = ExternalTunFdOverride{fd, adopt, skip_ioctl};
    }

    [[nodiscard]] inline auto peek_external_tun_fd() noexcept -> std::optional<ExternalTunFdOverride> {
        auto& s = tun_bridge_detail::state();
        std::lock_guard lock(s.mutex);
        return s.fd_override;
    }

    [[nodiscard]] inline auto consume_external_tun_fd() noexcept -> std::optional<ExternalTunFdOverride> {
        auto& s = tun_bridge_detail::state();
        std::lock_guard lock(s.mutex);
        auto out = s.fd_override;
        s.fd_override.reset();
        return out;
    }

    inline auto enable_global_tun_bridge(bool enabled, std::uint16_t mtu = 1500,
        TunBridgeOutputCallback cb = nullptr, void* ctx = nullptr) -> std::shared_ptr<ExternalTunBridge> {
        auto& s = tun_bridge_detail::state();
        std::shared_ptr<ExternalTunBridge> old_bridge;
        std::shared_ptr<ExternalTunBridge> next_bridge;
        {
            std::lock_guard lock(s.mutex);
            old_bridge = std::move(s.bridge);
            if (enabled) next_bridge = s.bridge = std::make_shared<ExternalTunBridge>(mtu, cb, ctx);
            else s.bridge.reset();
        }
        if (old_bridge) old_bridge->close();
        return next_bridge;
    }

    [[nodiscard]] inline auto global_tun_bridge() -> std::shared_ptr<ExternalTunBridge> {
        auto& s = tun_bridge_detail::state();
        std::lock_guard lock(s.mutex);
        return s.bridge;
    }
}
