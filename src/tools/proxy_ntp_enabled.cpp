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
        if (!cfg) return {};
        auto opts = *cfg;
        auto initial = ntp::sync_once(opts.host, opts.port, opts.timeout_ms);
        if (initial) {
            ntp::global_calibrator().apply(*initial);
            logs.emit(logging::Level::info, logging::Domain::core, 109, {},
                "ntp synced host={} port={} offset_ms={} delay_ms={} stratum={}",
                opts.host, opts.port, initial->offset_ms, initial->delay_ms, initial->stratum);
        } else {
            logs.emit(logging::Level::warn, logging::Domain::core, 109, {},
                "ntp initial sync failed host={} port={} code={}",
                opts.host, opts.port, static_cast<int>(initial.error()));
        }
        impl_ = std::make_unique<Impl>();
        auto* state = impl_.get();
        state->worker = std::jthread([state, opts, &logs]() {
            auto interval = std::chrono::milliseconds(opts.interval_ms);
            std::unique_lock lock(state->mutex);
            while (!state->stop) {
                if (state->cv.wait_for(lock, interval, [&] { return state->stop; })) break;
                lock.unlock();
                auto sample = ntp::sync_once(opts.host, opts.port, opts.timeout_ms);
                if (sample) {
                    ntp::global_calibrator().apply(*sample);
                    logs.emit(logging::Level::info, logging::Domain::core, 109, {},
                        "ntp synced host={} port={} offset_ms={} delay_ms={} stratum={}",
                        opts.host, opts.port, sample->offset_ms, sample->delay_ms, sample->stratum);
                } else {
                    logs.emit(logging::Level::warn, logging::Domain::core, 109, {},
                        "ntp sync failed host={} port={} code={}",
                        opts.host, opts.port, static_cast<int>(sample.error()));
                }
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
