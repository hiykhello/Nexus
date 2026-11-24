export module relay.tuic_host;
import std;
import relay;
import tuic.application;
import tuic.transport_options;
import tls.server_credential;
import corosio;

export namespace relay {
    class TuicHost {
        struct Impl;
        std::unique_ptr<Impl> impl_;
    public:
        TuicHost(Server& routing_source, tls::ServerCredential const& credential,
                 std::vector<tuic::UserCredential> users, tuic::ClientTransportOptions options);
        ~TuicHost();
        TuicHost(TuicHost const&) = delete;
        auto operator=(TuicHost const&) -> TuicHost& = delete;

        [[nodiscard]] auto start(corosio::endpoint listen_ep, unsigned workers)
            -> std::expected<std::uint16_t, std::string>;
        [[nodiscard]] auto healthy() const noexcept -> bool;
        [[nodiscard]] auto queue_outbound_probe(std::shared_ptr<OutboundProbe>) -> bool;
        auto stop() noexcept -> void;
    };
}
