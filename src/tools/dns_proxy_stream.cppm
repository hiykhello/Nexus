export module cli.dns_proxy_stream;
import std;
import dns.corosio_query;
import relay;
import relay.session_quota;
import tls.connector;
import tls.profiles;

export namespace cli::dns_proxy_detail {
    using Clock=std::chrono::steady_clock;
    using Error=dns::detail::UdpError;
    using Io=dns::detail::dns_io::io_context;
    using Endpoint=dns::detail::dns_io::endpoint;
    using ConnectResult=tls::detail::ConnectResult;
    namespace capy=dns::detail::dns_capy;

    struct Stream {
        relay::Server& server;
        relay::Session& session;
        std::size_t outbound;
        Endpoint endpoint;

        struct Candidates {};

        auto connect(Clock::time_point deadline,Candidates&) -> capy::task<ConnectResult> {
            switch (co_await server.open_stream(session,outbound,endpoint,deadline)) {
            case relay::PacketConnectResult::connected: co_return ConnectResult::connected;
            case relay::PacketConnectResult::retryable: co_return ConnectResult::retryable;
            case relay::PacketConnectResult::timeout: co_return ConnectResult::timeout;
            case relay::PacketConnectResult::failed: co_return ConnectResult::failed;
            }
            std::unreachable();
        }

        // The DNS bootstrap caller owns endpoint selection and retry.
        auto retry() noexcept -> bool { return false; }
        auto cancel() noexcept -> void { session.close(); }
        auto read(std::span<std::uint8_t> bytes) { return session.tunnel->read(bytes); }
        auto send(std::span<std::uint8_t const> bytes) { return session.tunnel->send(bytes); }
        auto close_output() { return session.tunnel->close_output(); }
    };

    using Connector=tls::detail::LayerConnector<Stream,tls::ClientProfile>;

    struct Route {
        tls::ClientProfile profile;
        std::size_t outbound;

        template<class Exchange>
        auto query(Io& context,Endpoint peer,Clock::time_point deadline,std::stop_token stop,Exchange exchange) const
            -> capy::task<std::expected<dns::Response,Error>> {
            if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
            if (Clock::now()>=deadline) co_return std::unexpected(Error::timeout);
            auto* server=relay::Server::from_context(context);
            if (!server) co_return std::unexpected(Error::transport);
            auto lease=server->acquire_session();
            if (!lease) co_return std::unexpected(Error::budget_exhausted);
            relay::Session session(context);
            server->attach_session(session,std::move(*lease));
            struct Finish {
                relay::Session& session;
                ~Finish() { session.close(); }
            } finish{session};
            Connector connector(profile,*server,session,outbound,peer);
            std::stop_callback cancellation(stop,[&connector] noexcept { connector.cancel(); });
            auto connected=co_await connector.start(deadline);
            if (connected!=ConnectResult::connected)
                co_return std::unexpected(stop.stop_requested() ? Error::canceled :
                    connected==ConnectResult::timeout ? Error::timeout : Error::transport);
            co_return co_await exchange(connector);
        }
    };
}
