module platform.socket_options;
import std;

namespace platform {
    namespace {
        struct ProtectSlot {
            std::mutex mutex;
            std::condition_variable cv;
            std::size_t inflight = 0;
            std::atomic<bool> active{false};
            ProtectFdCallback cb = nullptr;
            void* ctx = nullptr;
        };

        auto protect_slot() noexcept -> ProtectSlot& {
            static ProtectSlot slot;
            return slot;
        }
    }

    auto set_protect_fd_callback(ProtectFdCallback cb, void* ctx) noexcept -> void {
        auto& slot = protect_slot();
        std::unique_lock lock(slot.mutex);
        slot.cb = cb;
        slot.ctx = cb ? ctx : nullptr;
        slot.active.store(cb != nullptr, std::memory_order_release);
        slot.cv.wait(lock, [&] { return slot.inflight == 0; });
    }

    auto has_protect_fd_callback() noexcept -> bool {
        return protect_slot().active.load(std::memory_order_acquire);
    }

    auto invoke_protect_fd(int fd) noexcept -> std::error_code {
        if (!has_protect_fd_callback()) return {};
        auto& slot = protect_slot();
        ProtectFdCallback cb = nullptr;
        void* ctx = nullptr;
        {
            std::lock_guard lock(slot.mutex);
            cb = slot.cb;
            ctx = slot.ctx;
            if (!cb) return {};
            ++slot.inflight;
        }
        struct InflightGuard {
            ProtectSlot& s;
            ~InflightGuard() noexcept {
                std::lock_guard lock(s.mutex);
                if (--s.inflight == 0) s.cv.notify_all();
            }
        } guard{slot};
        int rc = cb(fd, ctx);
        if (rc == 0) return {};
        return rc > 0 ? std::error_code{rc, std::generic_category()}
                      : std::make_error_code(std::errc::operation_not_permitted);
    }
}
