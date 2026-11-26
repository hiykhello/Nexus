export module cli.hy2_enabled;
import std;
import config;
import relay;
import relay.hysteria2_host;
import hysteria2.credential;
import hysteria2.transport_options;
import tls.ech_server;
import tls.server_credential;
import tls.profiles;
import cli.cert_reloader;
import logging.cli;
import rulefile;
import crypto;

export namespace cli::hy2_enabled {
    class Runtime {
        struct Profile {
            std::optional<tls::ServerCredential> credential;
            std::shared_ptr<tls::AtomicServerCredential> atomic_credential;
            std::shared_ptr<tls::EchServerKeys const> ech_keys;
            std::vector<hysteria2::Password> passwords;
            std::optional<hysteria2::SalamanderKey> salamander;
            std::vector<std::string> names;
            hysteria2::TransportOptions options;
            config::Hysteria2Masquerade masquerade;
            std::array<std::uint8_t,16> listen_address{};
            std::unique_ptr<relay::Hysteria2Host> host;
            Profile() = default;
        };
        std::vector<std::unique_ptr<Profile>> profiles_;
        std::optional<std::string> failure_;
    public:
        Runtime()=default;
        Runtime(Runtime const&)=delete;auto operator=(Runtime const&)->Runtime& = delete;
        ~Runtime();
        auto resize(std::size_t) -> void;
        auto configure_outbound(config::Config const&) -> std::expected<void,std::string>;
        auto configure(std::size_t,config::InboundConfig const&,std::shared_ptr<void> const& acme_credential={},
            cli::CertReloaderHub* cert_reloaders=nullptr,logging::Runtime const* logs=nullptr) -> std::expected<void,std::string>;
        auto start(std::size_t,relay::Server&,std::uint16_t,bool,unsigned) -> std::expected<std::uint16_t,std::string>;
        auto healthy() const noexcept -> bool;
        [[nodiscard]] auto queue_outbound_probe(std::size_t,std::shared_ptr<relay::OutboundProbe>) -> bool;
        auto failure() const -> std::optional<std::string>;
        auto stop() noexcept -> void;
    };
}
