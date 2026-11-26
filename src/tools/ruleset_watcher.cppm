// Portable local rule-set file watcher (Linux inotify + cross-platform stat fallback with debounce).
module;
#if defined(__linux__)
#include <poll.h>
#include <sys/inotify.h>
#endif
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

export module cli.ruleset_watcher;
import std;
import cli.route_files;
import config;
import logging;
import logging.cli;

export namespace cli::run_detail {
    struct RulesetFileStamp {
        bool exists = false;
        std::uint64_t size = 0;
        std::int64_t mtime_ns = 0;
        std::uint64_t dev = 0;
        std::uint64_t ino = 0;
        auto operator==(RulesetFileStamp const&) const -> bool = default;
    };

    [[nodiscard]] inline auto stat_ruleset_file(std::string const& path) noexcept -> RulesetFileStamp {
        RulesetFileStamp out{};
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

    [[nodiscard]] inline auto resolve_local_ruleset_path(std::string_view config_path, std::string_view path)
        -> std::string {
        std::filesystem::path target(path);
        if (!target.is_absolute()) {
            if (auto wd = cli::working_directory()) {
                target = *wd / target;
            } else {
                std::error_code ec;
                auto base = std::filesystem::absolute(std::filesystem::path(config_path), ec);
                if (!ec) {
                    if (!std::filesystem::is_directory(base, ec)) base = base.parent_path();
                    target = base / target;
                }
            }
        }
        return target.lexically_normal().string();
    }

    [[nodiscard]] inline auto collect_local_ruleset_paths(config::Config const& cfg, std::string_view config_path)
        -> std::vector<std::string> {
        std::vector<std::string> out;
        auto add = [&](config::BlockRules const& spec) {
            if (spec.inline_rules || !spec.url.empty() || spec.path.empty()) return;
            auto resolved = resolve_local_ruleset_path(config_path, spec.path);
            if (!resolved.empty()) out.push_back(std::move(resolved));
        };
        for (auto const& r : cfg.routes) add(r.file);
        if (cfg.ordered_tcp) {
            for (auto const& [tag, spec] : cfg.ordered_tcp->sets) add(spec);
            for (auto const& rule : cfg.ordered_tcp->rules)
                if (rule.file) add(*rule.file);
        }
        if (cfg.dns) for (auto const& ref : cfg.dns->rule_files) add(ref.file);
        std::ranges::sort(out);
        out.erase(std::unique(out.begin(), out.end()), out.end());
        return out;
    }

    class LocalRulesetWatcher {
        using Clock = std::chrono::steady_clock;
        using WakeFn = void (*)() noexcept;

        std::chrono::milliseconds debounce_;
        std::chrono::milliseconds poll_interval_;
        WakeFn on_updated_;

        mutable std::mutex state_mu_;
        std::vector<std::string> paths_;
        std::vector<RulesetFileStamp> applied_;
        std::optional<std::vector<RulesetFileStamp>> pending_;
        Clock::time_point pending_since_{};
        logging::Runtime const* logs_ = nullptr;

        std::atomic_bool updated_{false};
        std::atomic_bool stopping_{false};
        std::mutex cv_mu_;
        std::condition_variable_any cv_;
        std::jthread worker_;

        [[nodiscard]] static auto snapshot_stamps(std::vector<std::string> const& paths) -> std::vector<RulesetFileStamp> {
            std::vector<RulesetFileStamp> stamps;
            stamps.reserve(paths.size());
            for (auto const& p : paths) stamps.push_back(stat_ruleset_file(p));
            return stamps;
        }

        [[nodiscard]] auto next_wait_ms() const noexcept -> long long {
            std::lock_guard lk(state_mu_);
            if (!pending_) return poll_interval_.count();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - pending_since_);
            auto rem = debounce_ - elapsed;
            return std::clamp<long long>(rem.count(), 10, poll_interval_.count());
        }

        auto watch_loop(std::stop_token st, std::vector<std::string> watched_paths) -> void {
#if defined(__linux__)
            int ifd = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
            if (ifd >= 0) {
                std::vector<std::string> dirs;
                dirs.reserve(watched_paths.size());
                for (auto const& p : watched_paths) {
                    auto dir = std::filesystem::path(p).parent_path().string();
                    if (dir.empty()) dir = ".";
                    dirs.push_back(std::move(dir));
                }
                std::ranges::sort(dirs);
                dirs.erase(std::unique(dirs.begin(), dirs.end()), dirs.end());
                for (auto const& dir : dirs)
                    (void)::inotify_add_watch(ifd, dir.c_str(),
                        IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_ATTRIB | IN_MODIFY);
            }
            struct CloseIfd { int fd; ~CloseIfd() { if (fd >= 0) ::close(fd); } } guard{ifd};
#else
            (void)watched_paths;
#endif
            while (!st.stop_requested() && !stopping_.load(std::memory_order_acquire)) {
                auto wait_ms = next_wait_ms();
#if defined(__linux__)
                if (ifd >= 0) {
                    auto slice = std::min<long long>(wait_ms, 200);
                    pollfd pfd{ifd, POLLIN, 0};
                    if (::poll(&pfd, 1, static_cast<int>(std::max<long long>(slice, 10))) > 0 && (pfd.revents & POLLIN)) {
                        alignas(inotify_event) std::array<char, 2048> drain{};
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

    public:
        explicit LocalRulesetWatcher(std::chrono::milliseconds debounce = std::chrono::milliseconds(200),
            std::chrono::milliseconds poll_interval = std::chrono::milliseconds(1000),
            WakeFn on_updated = nullptr) noexcept
            : debounce_(debounce), poll_interval_(poll_interval), on_updated_(on_updated) {}

        ~LocalRulesetWatcher() { stop(); }
        LocalRulesetWatcher(LocalRulesetWatcher const&) = delete;
        auto operator=(LocalRulesetWatcher const&) -> LocalRulesetWatcher& = delete;

        auto start(std::vector<std::string> paths, logging::Runtime const* logs = nullptr) -> void {
            std::ranges::sort(paths);
            paths.erase(std::unique(paths.begin(), paths.end()), paths.end());
            {
                std::lock_guard lk(state_mu_);
                if (worker_.joinable() && paths == paths_) {
                    logs_ = logs;
                    return;
                }
            }
            stop();
            if (paths.empty()) {
                std::lock_guard lk(state_mu_);
                paths_.clear();
                applied_.clear();
                pending_.reset();
                logs_ = logs;
                return;
            }
            auto initial = snapshot_stamps(paths);
            {
                std::lock_guard lk(state_mu_);
                paths_ = paths;
                applied_ = std::move(initial);
                pending_.reset();
                logs_ = logs;
            }
            stopping_.store(false, std::memory_order_release);
            worker_ = std::jthread([this, list = std::move(paths)](std::stop_token st) { watch_loop(st, list); });
        }

        auto start(config::Config const& cfg, std::string_view config_path, logging::Runtime const* logs = nullptr) -> void {
            start(collect_local_ruleset_paths(cfg, config_path), logs);
        }

        auto stop() noexcept -> void {
            stopping_.store(true, std::memory_order_release);
            if (worker_.joinable()) {
                worker_.request_stop();
                cv_.notify_all();
                worker_.join();
            }
        }

        [[nodiscard]] auto check_now(bool bypass_debounce = true) -> bool {
            std::vector<std::string> paths_copy;
            {
                std::lock_guard lk(state_mu_);
                if (paths_.empty()) return false;
                paths_copy = paths_;
            }
            auto cur = snapshot_stamps(paths_copy);
            logging::Runtime const* log_ptr = nullptr;
            {
                std::lock_guard lk(state_mu_);
                if (paths_ != paths_copy || cur.size() != applied_.size()) return false;
                if (cur == applied_) {
                    pending_.reset();
                    return false;
                }
                // Wait out transient mid-replacement disappearance when a previously present file is momentarily missing.
                for (std::size_t i = 0; i < cur.size(); ++i) {
                    if (applied_[i].exists && !cur[i].exists) return false;
                }
                auto now = Clock::now();
                if (!bypass_debounce) {
                    if (!pending_ || *pending_ != cur) {
                        pending_ = std::move(cur);
                        pending_since_ = now;
                        return false;
                    }
                    if (now - pending_since_ < debounce_) return false;
                }
                applied_ = std::move(cur);
                pending_.reset();
                log_ptr = logs_;
            }
            updated_.store(true, std::memory_order_release);
            if (log_ptr)
                log_ptr->emit(logging::Level::info, logging::Domain::route, 102, {},
                    "local rule-set file changed; scheduling hot-reload");
            if (on_updated_) on_updated_();
            return true;
        }

        [[nodiscard]] auto consume_updated() noexcept -> bool {
            return updated_.exchange(false, std::memory_order_acq_rel);
        }

        [[nodiscard]] auto watched_count() const noexcept -> std::size_t {
            std::lock_guard lk(state_mu_);
            return paths_.size();
        }
    };
}
