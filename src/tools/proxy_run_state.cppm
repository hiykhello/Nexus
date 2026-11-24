// Shared runtime atomic signal state, secret key buffer & control formatting helpers.
module;
#include <cerrno>
#include <csignal>
#if !defined(_WIN32)
#include <unistd.h>
#endif
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

export module cli.proxy_run_state;
import std;
import encoding.base64_key;
import utility;

export namespace cli::run_detail {
    struct SecretKey {
        std::array<std::uint8_t, 32> bytes{};
        ~SecretKey() { utility::secure_zero(bytes.data(), bytes.size()); }
    };

    using ::encoding::decode_key;

    inline std::atomic<int> wake_write_fd{-1};
    inline std::atomic<std::uint32_t> wake_write_inflight{0};
    inline auto wake_pipe_mutex() noexcept -> std::mutex& {
        static std::mutex mu;
        return mu;
    }
    inline auto notify_proxy_wakeup() noexcept -> void {
#if !defined(_WIN32)
        int const saved_errno = errno;
        wake_write_inflight.fetch_add(1, std::memory_order_seq_cst);
        int fd = wake_write_fd.load(std::memory_order_seq_cst);
        if (fd >= 0) { char b = 1; (void)::write(fd, &b, 1); }
        wake_write_inflight.fetch_sub(1, std::memory_order_seq_cst);
        errno = saved_errno;
#endif
    }

    inline std::atomic<bool> stopped{false};
    extern "C" inline auto handle_signal(int) -> void { stopped.store(true, std::memory_order_relaxed); notify_proxy_wakeup(); }

    inline std::atomic<bool> reload_requested{false};
    extern "C" inline auto handle_reload(int) -> void { reload_requested.store(true, std::memory_order_relaxed); notify_proxy_wakeup(); }

    inline std::atomic<bool> traffic_requested{false};
    extern "C" inline auto handle_traffic(int) -> void { traffic_requested.store(true, std::memory_order_relaxed); notify_proxy_wakeup(); }

    class SignalGuard {
        using Handler = void (*)(int);
        struct Saved { int sig = 0; Handler prev = SIG_DFL; bool set = false; };
        std::array<Saved, 4> saved_{};
        std::size_t count_ = 0;

        auto hook(int sig, Handler fn) noexcept -> bool {
            Handler prev = std::signal(sig, fn);
            if (prev == SIG_ERR) return false;
            saved_[count_++] = {sig, prev, true};
            return true;
        }
    public:
        SignalGuard() noexcept = default;
        SignalGuard(SignalGuard const&) = delete;
        auto operator=(SignalGuard const&) -> SignalGuard& = delete;
        ~SignalGuard() { reset(); }

        auto reset() noexcept -> void {
            while (count_ > 0) {
                auto const& s = saved_[--count_];
                if (s.set) (void)std::signal(s.sig, s.prev);
            }
        }

        [[nodiscard]] auto install(bool with_reload, bool with_traffic) noexcept
            -> std::expected<void, std::string_view> {
#ifdef SIGHUP
            if (with_reload && !hook(SIGHUP, handle_reload)) {
                reset();
                return std::unexpected("cannot install traffic rule reload signal handler");
            }
#else
            (void)with_reload;
#endif
#ifdef SIGUSR1
            if (with_traffic && !hook(SIGUSR1, handle_traffic)) {
                reset();
                return std::unexpected("cannot install traffic snapshot signal handler");
            }
#else
            (void)with_traffic;
#endif
            if (!hook(SIGINT, handle_signal) || !hook(SIGTERM, handle_signal)) {
                reset();
                return std::unexpected("cannot install proxy stop signal handlers");
            }
            return {};
        }
    };

    class WinStopEventGuard {
#ifdef _WIN32
        HANDLE handle_ = nullptr;
    public:
        WinStopEventGuard() noexcept {
            auto name = L"Local\\nexus-stop-" + std::to_wstring(::GetCurrentProcessId());
            handle_ = ::CreateEventW(nullptr, TRUE, FALSE, name.c_str());
        }
        WinStopEventGuard(WinStopEventGuard const&) = delete;
        auto operator=(WinStopEventGuard const&) -> WinStopEventGuard& = delete;
        ~WinStopEventGuard() { if (handle_) ::CloseHandle(handle_); }
        [[nodiscard]] auto signaled() const noexcept -> bool {
            if (handle_ && ::WaitForSingleObject(handle_, 0) == WAIT_OBJECT_0) {
                stopped.store(true, std::memory_order_relaxed);
                return true;
            }
            return false;
        }
#else
    public:
        [[nodiscard]] constexpr auto signaled() const noexcept -> bool { return false; }
#endif
    };

    inline auto control_name(std::string_view name) -> std::string {
        if (std::ranges::all_of(name, [](unsigned char byte) {
            return byte > 32 && byte < 127 && byte != '"' && byte != '\\';
        })) return std::string(name);
        return std::format("{:?}", name);
    }
}
