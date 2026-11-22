export module cli.proxy_ntp;
import std;
import config;
import logging.cli;

export namespace cli {
    class NtpRuntime {
        struct Impl;
        std::unique_ptr<Impl> impl_;
    public:
        NtpRuntime();
        ~NtpRuntime();
        NtpRuntime(NtpRuntime const&) = delete;
        auto operator=(NtpRuntime const&) -> NtpRuntime& = delete;

        [[nodiscard]] auto start(std::optional<config::NtpConfig> const& cfg, logging::Runtime& logs)
            -> std::expected<void, std::string>;
        auto stop() noexcept -> void;
    };
}
