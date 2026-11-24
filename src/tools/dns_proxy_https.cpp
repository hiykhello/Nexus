module cli.dns_proxy_https;
import std;
import proxy.v4;
import cli.dns_proxy_stream;
import dns.corosio_query;
import dns.doh_exchange;
import dns.doh_pool;
import relay;
import relay.session_quota;
import tls.profiles;

namespace cli {
    namespace {
        using namespace dns_proxy_detail;

        struct Layered {
            relay::Session session;
            Connector connector;

            Layered(Io& context,relay::Server& server,relay::SessionQuota::Lease lease,std::size_t outbound,
                Endpoint peer,tls::ClientProfile const& profile,std::shared_ptr<dns::detail::TransportSnapshot const> snapshot)
                :session(context),connector(profile,server,session,outbound,peer) {
                server.attach_session(session,std::move(lease));
                session.dns_transport_override=std::move(snapshot);
            }
            ~Layered(){session.close();}
            auto connected() noexcept -> void {session.relaying=true;}
            auto used() noexcept -> void {session.touched=Clock::now();}
        };
    }

    auto prepare_proxy_https(std::string_view server_name,std::string_view ca_file,std::string_view path,std::size_t outbound,dns::detail::TransportSnapshotRef snapshot)
        -> std::expected<dns::detail::ProtectedQuery,std::string> {
        if (!dns::doh_detail::valid_path(path)) return std::unexpected("invalid DoH request path");
        constexpr std::array<std::string_view,2> protocols{"h2","http/1.1"};
        auto profile=tls::ClientProfile::load(server_name,ca_file,0x001d,false,protocols);
        if (!profile) return std::unexpected(std::move(profile.error()));
        auto factory=[profile=std::move(*profile),outbound,snapshot=std::move(snapshot)](Io& context,Endpoint peer)
            -> dns::doh_detail::NewStream {
            auto transport=snapshot ? snapshot->lock() : nullptr;
            if (snapshot && !transport) return std::unexpected(Error::canceled);
            auto* server=relay::Server::from_context(context);
            if (!server) return std::unexpected(Error::transport);
            auto lease=server->acquire_session();
            if (!lease) return std::unexpected(Error::budget_exhausted);
            return pro::make_proxy<dns::doh_detail::StreamFacade,dns::doh_detail::StreamAdapter<Layered>>(context,*server,
                std::move(*lease),outbound,peer,profile,std::move(transport));
        };
        return dns::doh_detail::pooled_query(std::move(factory),std::string(server_name),std::string(path),std::nullopt);
    }
}
