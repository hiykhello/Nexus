module;
#if defined(__linux__)
#include <poll.h>
#include <sys/inotify.h>
#endif
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

export module cli.cert_reloader;
import std;
import logging;
import logging.cli;
import tls.profiles;
import tls.server_credential;

export namespace cli {
    inline auto as_atomic_credential(std::shared_ptr<void> const& erased) noexcept
        -> std::shared_ptr<tls::AtomicServerCredential> {
        return std::static_pointer_cast<tls::AtomicServerCredential>(erased);
    }

    inline auto make_atomic_credential_erased() -> std::shared_ptr<void> {
        return std::static_pointer_cast<void>(std::make_shared<tls::AtomicServerCredential>());
    }

    struct CertFileStamp {
        bool exists = false;
        std::uint64_t size = 0;
        std::int64_t mtime_ns = 0;
        std::uint64_t dev = 0;
        std::uint64_t ino = 0;
        auto operator==(CertFileStamp const&) const -> bool = default;
    };

    inline auto stat_cert_file(std::string const& path) noexcept -> CertFileStamp {
        CertFileStamp out{};
#if !defined(_WIN32)
        struct ::stat st{};
        if (::stat(path.c_str(), &st) != 0) return out;
        out.exists = true;
        out.size = static_cast<std::uint64_t>(st.st_size);
        out.dev = static_cast<std::uint64_t>(st.st_dev);
        out.ino = static_cast<std::uint64_t>(st.st_ino);
#if defined(__APPLE__)
        out.mtime_ns = static_cast<std::int64_t>(st.st_mtimespec.tv_sec) * 1000000000LL + st.st_mtimespec.tv_nsec;
#else
        out.mtime_ns = static_cast<std::int64_t>(st.st_mtim.tv_sec) * 1000000000LL + st.st_mtim.tv_nsec;
#endif
#else
        std::error_code ec;
        auto sz = std::filesystem::file_size(path, ec);
        if (ec) return out;
        auto mt = std::filesystem::last_write_time(path, ec);
        if (ec) return out;
        out.exists = true;
        out.size = static_cast<std::uint64_t>(sz);
        out.mtime_ns = static_cast<std::int64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(mt.time_since_epoch()).count());
#endif
        return out;
    }

    class StaticCertReloader {
        using Clock = std::chrono::steady_clock;
        struct PairStamp {
            CertFileStamp cert, key;
            auto operator==(PairStamp const&) const -> bool = default;
        };

        std::string cert_path_, key_path_;
        std::shared_ptr<tls::AtomicServerCredential> credential_;
        logging::Runtime const* logs_ = nullptr;
        std::chrono::milliseconds poll_interval_{5000};
        std::chrono::milliseconds debounce_{500};

        mutable std::mutex state_mu_;
        PairStamp applied_{};
        std::optional<PairStamp> pending_{};
        Clock::time_point pending_since_{};
        std::optional<PairStamp> failed_stamp_{};
        std::uint64_t reload_failures_ = 0;

        std::atomic_bool stopping_{false};
        std::mutex cv_mu_;
        std::condition_variable_any cv_;
        std::jthread watcher_;

        StaticCertReloader(std::string cert_path, std::string key_path,
            std::shared_ptr<tls::AtomicServerCredential> cred, PairStamp initial,
            logging::Runtime const* logs, std::chrono::milliseconds poll_interval, std::chrono::milliseconds debounce)
            : cert_path_(std::move(cert_path)), key_path_(std::move(key_path)),
              credential_(std::move(cred)), logs_(logs),
              poll_interval_(poll_interval), debounce_(debounce), applied_(initial) {}

        auto current_stamp() const noexcept -> PairStamp {
            return {stat_cert_file(cert_path_), stat_cert_file(key_path_)};
        }

        auto try_apply_locked(PairStamp const& cur) -> bool {
            auto loaded = tls::load_server_credential(cert_path_, key_path_);
            if (!loaded) {
                ++reload_failures_;
                if (!failed_stamp_ || *failed_stamp_ != cur) {
                    failed_stamp_ = cur;
                    if (logs_) logs_->emit(logging::Level::warn, logging::Domain::core, 108, {},
                        "TLS cert hot-reload rejected ({}): keeping previous credential (generation={})",
                        loaded.error(), credential_->generation());
                }
                return false;
            }
            auto gen = credential_->update(std::move(*loaded));
            applied_ = cur;
            pending_.reset();
            failed_stamp_.reset();
            if (logs_) logs_->emit(logging::Level::info, logging::Domain::core, 102, {},
                "TLS cert hot-reloaded from {} (generation={})", cert_path_, gen);
            return true;
        }

        auto watch_loop(std::stop_token st) -> void {
#if defined(__linux__)
            int ifd = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
            auto add_dir_watch = [&](std::string const& file) {
                if (ifd < 0) return;
                auto dir = std::filesystem::path(file).parent_path().string();
                if (dir.empty()) dir = ".";
                (void)::inotify_add_watch(ifd, dir.c_str(),
                    IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_ATTRIB | IN_MODIFY);
            };
            add_dir_watch(cert_path_);
            if (std::filesystem::path(key_path_).parent_path() != std::filesystem::path(cert_path_).parent_path())
                add_dir_watch(key_path_);
            struct CloseIfd { int fd; ~CloseIfd() { if (fd >= 0) ::close(fd); } } guard{ifd};
#endif
            while (!st.stop_requested() && !stopping_.load(std::memory_order_acquire)) {
                auto wait_ms = next_wait_ms();
#if defined(__linux__)
                if (ifd >= 0) {
                    auto slice = std::min<long long>(wait_ms, 200);
                    pollfd pfd{ifd, POLLIN, 0};
                    if (::poll(&pfd, 1, static_cast<int>(std::max<long long>(slice, 10))) > 0 && (pfd.revents & POLLIN)) {
                        alignas(inotify_event) std::array<char, 1024> drain{};
                        while (::read(ifd, drain.data(), drain.size()) > 0) {}
                    }
                    (void)check_now(false);
                    continue;
                }
#endif
                std::unique_lock lk(cv_mu_);
                cv_.wait_for(lk, st, std::chrono::milliseconds(std::max<long long>(wait_ms, 10)),
                    [this] { return stopping_.load(std::memory_order_acquire); });
                lk.unlock();
                if (!st.stop_requested() && !stopping_.load(std::memory_order_acquire)) (void)check_now(false);
            }
        }

        auto next_wait_ms() const noexcept -> long long {
            std::lock_guard lk(state_mu_);
            if (!pending_) return poll_interval_.count();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - pending_since_);
            auto rem = debounce_ - elapsed;
            return std::clamp<long long>(rem.count(), 10, poll_interval_.count());
        }

    public:
        ~StaticCertReloader() { stop(); }
        StaticCertReloader(StaticCertReloader const&) = delete;
        auto operator=(StaticCertReloader const&) -> StaticCertReloader& = delete;

        [[nodiscard]] static auto create(std::string cert_path, std::string key_path,
            logging::Runtime const* logs = nullptr,
            std::chrono::milliseconds poll_interval = std::chrono::milliseconds(5000),
            std::chrono::milliseconds debounce = std::chrono::milliseconds(500))
            -> std::expected<std::unique_ptr<StaticCertReloader>, std::string> {
            auto initial_cred = tls::load_server_credential(cert_path, key_path);
            if (!initial_cred) return std::unexpected(initial_cred.error());
            auto atomic = std::make_shared<tls::AtomicServerCredential>();
            (void)atomic->update(std::move(*initial_cred));
            PairStamp stamp{stat_cert_file(cert_path), stat_cert_file(key_path)};
            return std::unique_ptr<StaticCertReloader>(new StaticCertReloader(
                std::move(cert_path), std::move(key_path), std::move(atomic), stamp,
                logs, poll_interval, debounce));
        }

        auto start() -> void {
            if (watcher_.joinable()) return;
            stopping_.store(false, std::memory_order_release);
            watcher_ = std::jthread([this](std::stop_token st) { watch_loop(st); });
        }

        auto stop() noexcept -> void {
            if (stopping_.exchange(true, std::memory_order_acq_rel)) return;
            watcher_.request_stop();
            cv_.notify_all();
            if (watcher_.joinable()) watcher_.join();
        }

        [[nodiscard]] auto check_now(bool bypass_debounce = true) -> bool {
            auto cur = current_stamp();
            std::lock_guard lk(state_mu_);
            if (cur == applied_) {
                pending_.reset();
                return false;
            }
            if (!cur.cert.exists || !cur.key.exists) return false;
            auto now = Clock::now();
            if (!bypass_debounce) {
                if (!pending_ || *pending_ != cur) {
                    pending_ = cur;
                    pending_since_ = now;
                    return false;
                }
                if (now - pending_since_ < debounce_) return false;
                if (failed_stamp_ && *failed_stamp_ == cur) return false;
            }
            return try_apply_locked(cur);
        }

        [[nodiscard]] auto credential() const noexcept -> std::shared_ptr<tls::AtomicServerCredential> { return credential_; }
        [[nodiscard]] auto credential_erased() const noexcept -> std::shared_ptr<void> { return std::static_pointer_cast<void>(credential_); }
        [[nodiscard]] auto generation() const noexcept -> std::uint64_t { return credential_->generation(); }
        [[nodiscard]] auto reload_failures() const noexcept -> std::uint64_t {
            std::lock_guard lk(state_mu_);
            return reload_failures_;
        }
    };

    class CertReloaderHub {
        std::vector<std::unique_ptr<StaticCertReloader>> reloaders_;
    public:
        CertReloaderHub() = default;
        ~CertReloaderHub() { stop(); }
        CertReloaderHub(CertReloaderHub const&) = delete;
        auto operator=(CertReloaderHub const&) -> CertReloaderHub& = delete;
        CertReloaderHub(CertReloaderHub&&) noexcept = default;
        auto operator=(CertReloaderHub&&) noexcept -> CertReloaderHub& = default;

        [[nodiscard]] auto watch(std::string cert_path, std::string key_path, logging::Runtime const* logs = nullptr,
            bool start_thread = true) -> std::expected<std::shared_ptr<void>, std::string> {
            auto r = StaticCertReloader::create(std::move(cert_path), std::move(key_path), logs);
            if (!r) return std::unexpected(std::move(r.error()));
            if (start_thread) (*r)->start();
            auto erased = (*r)->credential_erased();
            reloaders_.push_back(std::move(*r));
            return erased;
        }
        auto stop() noexcept -> void {
            for (auto& r : reloaders_) if (r) r->stop();
            reloaders_.clear();
        }
        [[nodiscard]] auto active_count() const noexcept -> std::size_t { return reloaders_.size(); }
    };
}
