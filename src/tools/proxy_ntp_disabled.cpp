module cli.proxy_ntp;
import std;
import config;
import logging.cli;

namespace cli {
    struct NtpRuntime::Impl {};
    NtpRuntime::NtpRuntime() = default;
    NtpRuntime::~NtpRuntime() = default;

    auto NtpRuntime::start(std::optional<config::NtpConfig> const& cfg, logging::Runtime&)
        -> std::expected<void, std::string> {
        if (!cfg) return {};
        return std::unexpected("NTP is not available in this build");
    }

    auto NtpRuntime::stop() noexcept -> void {}
}
