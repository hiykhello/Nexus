module dns.https_query;
import std;
import proxy.v4;
import dns.corosio_query;
import dns.doh_exchange;
import dns.doh_pool;
import dns.doh3_pool;
import platform.socket_options;
import tls.connector;
import tls.profiles;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace dns {
    namespace {
        using namespace doh_detail;

        struct FixedResolver {
            Endpoint endpoint;
            auto cancel() noexcept -> void {}
            auto operator()(Clock::time_point) const -> capy::task<std::optional<std::vector<Endpoint>>> {
                co_return std::vector{endpoint};
            }
        };

        template<class Connector>
        struct Physical {
            Connector connector;
            Physical(Io& context,Endpoint peer,tls::ClientProfile const& tls,platform::TcpSocketOptions const& options)
                :connector(context,FixedResolver{peer},tls,options) {}
        };
        using PhysicalTcp=Physical<tls::detail::PhysicalConnector<FixedResolver,tls::ClientProfile>>;
        using PhysicalFastOpen=Physical<tls::detail::FastOpenPhysicalConnector<FixedResolver,tls::ClientProfile>>;
    }

    auto stop_https_queries(nex::corosio::io_context& context) noexcept -> void {
        doh_detail::stop_pool(context);
#ifdef NEXUS_DNS_DOH3
        stop_https3_queries(context);
#endif
    }
    auto resume_https_queries(nex::corosio::io_context& context) noexcept -> void {
        doh_detail::resume_pool(context);
#ifdef NEXUS_DNS_DOH3
        resume_https3_queries(context);
#endif
    }
    auto reap_idle_https_queries(nex::corosio::io_context& context,std::chrono::steady_clock::time_point now) noexcept -> void {
        doh_detail::reap_pool(context,now);
#ifdef NEXUS_DNS_DOH3
        reap_idle_https3_queries(context,now);
#endif
    }

    auto make_https_query(std::string_view server_name,std::string_view ca_file,std::string_view path,
        platform::TcpSocketOptions options,std::optional<std::chrono::milliseconds> connect_timeout)
        -> std::expected<dns::detail::ProtectedQuery,std::string> {
        if (!doh_detail::valid_path(path)) return std::unexpected("invalid DoH request path");
        constexpr std::array<std::string_view,2> protocols{"h2","http/1.1"};
        auto profile=tls::ClientProfile::load(server_name,ca_file,0x001d,false,protocols);
        if (!profile) return std::unexpected(std::move(profile.error()));
        auto factory=[profile=std::move(*profile),options=std::move(options)](Io& context,Endpoint peer)
            -> doh_detail::NewStream {
            if (options.tcp_fast_open.value_or(false))
                return pro::make_proxy<doh_detail::StreamFacade,doh_detail::StreamAdapter<PhysicalFastOpen>>(context,peer,profile,options);
            return pro::make_proxy<doh_detail::StreamFacade,doh_detail::StreamAdapter<PhysicalTcp>>(context,peer,profile,options);
        };
        return doh_detail::pooled_query(std::move(factory),std::string(server_name),std::string(path),connect_timeout);
    }
}
