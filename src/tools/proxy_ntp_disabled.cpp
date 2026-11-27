module cli.proxy_ntp;
import std;
import config;
import logging.cli;
import platform.wall_clock;

namespace cli {
    struct NtpRuntime::Impl {};
    NtpRuntime::NtpRuntime() = default;
    NtpRuntime::~NtpRuntime() { stop(); }

    auto NtpRuntime::start(std::optional<config::NtpConfig> const& cfg, logging::Runtime&)
        -> std::expected<void, std::string> {
        if (!cfg) {
            platform::set_wall_clock_offset_ms(0);
            return {};
        }
        return std::unexpected("NTP is not available in this build");
    }

    auto NtpRuntime::stop() noexcept -> void {
        platform::set_wall_clock_offset_ms(0);
    }
}
