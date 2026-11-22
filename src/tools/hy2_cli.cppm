export module cli.hy2_enabled;
import std;
import config;
import proxy;
import proxy.hysteria2_host;
import hysteria2.credential;
import hysteria2.transport_options;
import tls.server_credential;
import tls.profiles;
import rulefile;
import crypto;

export namespace cli::hy2_enabled {
    class Runtime {
        struct Profile {
            tls::ServerCredential credential;
            std::vector<hysteria2::Password> passwords;
            std::optional<hysteria2::SalamanderKey> salamander;
            std::vector<std::string> names;
            hysteria2::TransportOptions options;
            std::array<std::uint8_t,16> listen_address{};
            std::unique_ptr<proxy::Hysteria2Host> host;
            explicit Profile(tls::ServerCredential&& value):credential(std::move(value)){}
        };
        std::vector<std::unique_ptr<Profile>> profiles_;
        std::optional<std::string> failure_;
    public:
        Runtime()=default;
        Runtime(Runtime const&)=delete;auto operator=(Runtime const&)->Runtime& = delete;
        ~Runtime();
        auto resize(std::size_t) -> void;
        auto configure_outbound(config::Config const&) -> std::expected<void,std::string>;
        auto configure(std::size_t,config::InboundConfig const&) -> std::expected<void,std::string>;
        auto start(std::size_t,proxy::Server&,std::uint16_t,bool,unsigned) -> std::expected<std::uint16_t,std::string>;
        auto healthy() const noexcept -> bool;
        [[nodiscard]] auto queue_outbound_probe(std::size_t,std::shared_ptr<proxy::OutboundProbe>) -> bool;
        auto failure() const -> std::optional<std::string>;
        auto stop() noexcept -> void;
    };
}
