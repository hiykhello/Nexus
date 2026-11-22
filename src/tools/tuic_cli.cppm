export module cli.tuic_enabled;
import std;
import config;
import proxy;
import proxy.tuic_host;
import tuic.wire;
import tuic.application;
import tuic.transport_options;
import tls.server_credential;
import tls.profiles;
import rulefile;
import crypto;

export namespace cli::tuic_enabled {
    class Runtime {
        struct Profile {
            tls::ServerCredential credential;
            std::vector<tuic::UserCredential> users;
            tuic::ClientTransportOptions options;
            std::array<std::uint8_t, 16> listen_address{};
            std::unique_ptr<proxy::TuicHost> host;
            explicit Profile(tls::ServerCredential&& cred) : credential(std::move(cred)) {}
        };
        std::vector<std::unique_ptr<Profile>> profiles_;
        std::optional<std::string> failure_;
    public:
        Runtime() = default;
        Runtime(Runtime const&) = delete;
        auto operator=(Runtime const&) -> Runtime& = delete;
        ~Runtime();
        auto resize(std::size_t) -> void;
        auto configure(std::size_t, config::InboundConfig const&) -> std::expected<void, std::string>;
        auto start(std::size_t, proxy::Server&, std::uint16_t, bool, unsigned) -> std::expected<std::uint16_t, std::string>;
        auto healthy() const noexcept -> bool;
        [[nodiscard]] auto queue_outbound_probe(std::size_t,std::shared_ptr<proxy::OutboundProbe>) -> bool;
        auto failure() const -> std::optional<std::string>;
        auto stop() noexcept -> void;
    };
}
