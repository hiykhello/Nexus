module cli.proxy_ntp;
import std;
import config;
import logging;
import logging.cli;
import ntp;

namespace cli {
    struct NtpRuntime::Impl {
        std::jthread worker;
        std::mutex mutex;
        std::condition_variable cv;
        bool stop{false};

        auto shutdown() noexcept -> void {
            if (worker.joinable()) worker.request_stop();
            {
                std::lock_guard lock(mutex);
                stop = true;
            }
            cv.notify_all();
            if (worker.joinable()) worker.join();
        }
        ~Impl() { shutdown(); }
    };

    NtpRuntime::NtpRuntime() = default;
    NtpRuntime::~NtpRuntime() { stop(); }

    auto NtpRuntime::start(std::optional<config::NtpConfig> const& cfg, logging::Runtime& logs)
        -> std::expected<void, std::string> {
        stop();
        if (!cfg) return {};
        auto opts = *cfg;
        impl_ = std::make_unique<Impl>();
        auto* state = impl_.get();
        state->worker = std::jthread([state, opts, &logs](std::stop_token stoken) {
            auto run_one = [&](bool initial) {
                auto sample = ntp::sync_once(opts.host, opts.port, opts.timeout_ms, stoken);
                if (sample) {
                    ntp::global_calibrator().apply(*sample);
                    logs.emit(logging::Level::info, logging::Domain::core, 109, {},
                        "ntp synced host={} port={} offset_ms={} delay_ms={} stratum={}",
                        opts.host, opts.port, sample->offset_ms, sample->delay_ms, sample->stratum);
                } else if (!stoken.stop_requested()) {
                    logs.emit(logging::Level::warn, logging::Domain::core, 109, {},
                        "{} host={} port={} code={}",
                        initial ? "ntp initial sync failed" : "ntp sync failed",
                        opts.host, opts.port, static_cast<int>(sample.error()));
                }
            };
            run_one(true);
            auto interval = std::chrono::milliseconds(opts.interval_ms);
            std::unique_lock lock(state->mutex);
            while (!state->stop && !stoken.stop_requested()) {
                if (state->cv.wait_for(lock, interval, [&] { return state->stop || stoken.stop_requested(); })) break;
                lock.unlock();
                run_one(false);
                lock.lock();
            }
        });
        return {};
    }

    auto NtpRuntime::stop() noexcept -> void {
        if (impl_) {
            impl_->shutdown();
            impl_.reset();
        }
    }
}
