export module cli.tuic_enabled;
import std;
import config;
import relay;
import relay.tuic_host;
import tuic.wire;
import tuic.application;
import tuic.transport_options;
import tls.ech_server;
import tls.server_credential;
import tls.profiles;
import cli.cert_reloader;
import logging.cli;
import rulefile;
import crypto;

export namespace cli::tuic_enabled {
    class Runtime {
        struct Profile {
            std::optional<tls::ServerCredential> credential;
            std::shared_ptr<tls::AtomicServerCredential> atomic_credential;
            std::shared_ptr<tls::EchServerKeys const> ech_keys;
            std::vector<tuic::UserCredential> users;
            tuic::ClientTransportOptions options;
            std::array<std::uint8_t, 16> listen_address{};
            std::unique_ptr<relay::TuicHost> host;
            Profile() = default;
        };
        std::vector<std::unique_ptr<Profile>> profiles_;
        std::optional<std::string> failure_;
    public:
        Runtime() = default;
        Runtime(Runtime const&) = delete;
        auto operator=(Runtime const&) -> Runtime& = delete;
        ~Runtime();
        auto resize(std::size_t) -> void;
        auto configure(std::size_t, config::InboundConfig const&, std::shared_ptr<void> const& acme_credential = {},
            cli::CertReloaderHub* cert_reloaders = nullptr, logging::Runtime const* logs = nullptr) -> std::expected<void, std::string>;
        auto start(std::size_t, relay::Server&, std::uint16_t, bool, unsigned) -> std::expected<std::uint16_t, std::string>;
        auto healthy() const noexcept -> bool;
        [[nodiscard]] auto queue_outbound_probe(std::size_t,std::shared_ptr<relay::OutboundProbe>) -> bool;
        auto failure() const -> std::optional<std::string>;
        auto stop() noexcept -> void;
    };
}
