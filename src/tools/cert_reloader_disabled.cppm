export module cli.cert_reloader;
import std;
import logging;
import logging.cli;

export namespace cli {
    inline auto make_atomic_credential_erased() noexcept -> std::shared_ptr<void> { return {}; }
    class CertReloaderHub {
    public:
        CertReloaderHub() = default;
        [[nodiscard]] auto watch(std::string, std::string, logging::Runtime const* = nullptr, bool = true)
            -> std::expected<std::shared_ptr<void>, std::string> {
            return std::unexpected("TLS cert-hot-reload requires the tls build feature");
        }
        auto stop() noexcept -> void {}
        [[nodiscard]] auto active_count() const noexcept -> std::size_t { return 0; }
    };
}
