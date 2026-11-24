module cli.dns_proxy_tls;
import std;
import proxy.v4;
import cli.dns_proxy_stream;
import dns.corosio_query;
import dns.tls_query;
import relay;
import relay.session_quota;
import tls.byte_stream;
import tls.profiles;

namespace cli {
    namespace {
        using namespace dns_proxy_detail;

        class RoutedTlsStream {
            relay::Session session_;
            Connector connector_;
            std::optional<tls::detail::ByteStream<Connector::Socket>> stream_;

        public:
            RoutedTlsStream(Io& context,relay::Server& server,relay::SessionQuota::Lease lease,std::size_t outbound,
                Endpoint peer,tls::ClientProfile const& profile,std::shared_ptr<dns::detail::TransportSnapshot const> snapshot)
                :session_(context),connector_(profile,server,session_,outbound,peer) {
                server.attach_session(session_,std::move(lease));
                session_.dns_transport_override=std::move(snapshot);
            }
            ~RoutedTlsStream() {cancel();}

            auto start(Clock::time_point deadline) -> capy::task<bool> {
                if (co_await connector_.start(deadline)!=ConnectResult::connected || session_.closed) co_return false;
                stream_.emplace(*connector_.application());
                session_.relaying=true;
                co_return true;
            }
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::size_t> {
                auto result=co_await stream_->read(bytes);
                co_return result.value_or(0);
            }
            auto send(std::span<std::uint8_t const> bytes,Clock::time_point deadline) -> capy::task<bool> {
                session_.touched=Clock::now();
                return stream_->send(bytes,deadline);
            }
            auto cancel() noexcept -> void {connector_.cancel();}
        };
    }

    auto prepare_proxy_tls(std::string_view server_name,std::string_view ca_file,std::size_t outbound,dns::detail::TransportSnapshotRef snapshot)
        -> std::expected<dns::detail::ProtectedQuery,std::string> {
        auto profile=tls::ClientProfile::load(server_name,ca_file);
        if (!profile) return std::unexpected(std::move(profile.error()));
        auto create=[profile=std::move(*profile),outbound,snapshot=std::move(snapshot)](Io& context,Endpoint peer) -> dns::TlsDnsStream {
            auto transport=snapshot ? snapshot->lock() : nullptr;
            if (snapshot && !transport) return {};
            auto* server=relay::Server::from_context(context);
            if (!server) return {};
            auto lease=server->acquire_session();
            if (!lease) return {};
            return pro::make_proxy<dns::TlsDnsStreamFacade,RoutedTlsStream>(context,*server,std::move(*lease),outbound,peer,profile,std::move(transport));
        };
        return dns::make_routed_tls_query(std::move(create),std::chrono::seconds(5));
    }
}
