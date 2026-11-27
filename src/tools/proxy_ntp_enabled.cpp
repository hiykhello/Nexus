module cli.proxy_ntp;
import std;
import capy;
import corosio;
import config;
import logging;
import logging.cli;
import ntp;

namespace cli {
    namespace {
        auto run_ntp_loop(corosio::io_context& io, config::NtpConfig opts, logging::Runtime& logs,
            std::stop_token stop) -> capy::task<void> {
            auto const interval = std::chrono::milliseconds(opts.interval_ms);
            bool initial = true;
            while (!stop.stop_requested()) {
                auto sample = co_await ntp::sync_once_async(io, opts.host, opts.port, opts.timeout_ms, stop);
                if (stop.stop_requested()) co_return;
                if (sample) {
                    ntp::global_calibrator().apply(*sample);
                    logs.emit(logging::Level::info, logging::Domain::core, 109, {},
                        "ntp synced host={} port={} offset_ms={} delay_ms={} stratum={}",
                        opts.host, opts.port, sample->offset_ms, sample->delay_ms, sample->stratum);
                } else {
                    logs.emit(logging::Level::warn, logging::Domain::core, 109, {},
                        "{} host={} port={} code={}",
                        initial ? "ntp initial sync failed" : "ntp sync failed",
                        opts.host, opts.port, static_cast<int>(sample.error()));
                }
                initial = false;
                auto [ec] = co_await corosio::delay(interval);
                if (ec || stop.stop_requested()) co_return;
            }
        }
    }

    struct NtpRuntime::Impl {
        corosio::io_context io;
        std::stop_source stop_src;
        std::jthread worker;

        auto shutdown() noexcept -> void {
            stop_src.request_stop();
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
        state->worker = std::jthread([state, opts = std::move(opts), &logs]() {
            auto tok = state->stop_src.get_token();
            capy::run_async(state->io.get_executor(), tok, []() noexcept {},
                [](std::exception_ptr) noexcept {})(run_ntp_loop(state->io, opts, logs, tok));
            state->io.run();
        });
        return {};
    }

    auto NtpRuntime::stop() noexcept -> void {
        if (impl_) {
            impl_->shutdown();
            impl_.reset();
        }
        ntp::reset_offset();
    }
}
