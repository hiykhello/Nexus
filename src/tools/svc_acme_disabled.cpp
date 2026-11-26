module cli.proxy_services;
import std;
import config;
import logging.cli;

namespace cli {
    auto init_acme_service(config::AcmeServiceConfig const&, logging::Runtime&, AcmeHooks)
        -> std::expected<ServiceHandle, std::string> {
        return std::unexpected("acme service requires the acme build feature");
    }
    auto acme_http01_port(ServiceHandle const&) noexcept -> std::uint16_t { return 0; }
    auto acme_alpn01_port(ServiceHandle const&) noexcept -> std::uint16_t { return 0; }
    auto acme_credential_generation(ServiceHandle const&) noexcept -> std::uint64_t { return 0; }
    auto acme_has_valid_credential(ServiceHandle const&) noexcept -> bool { return false; }
    auto acme_credential_provider_erased(ServiceHandle const&) noexcept -> std::shared_ptr<void> { return {}; }
    auto acme_dns01_record(ServiceHandle const&, std::string_view) -> std::optional<std::string> { return std::nullopt; }
}
