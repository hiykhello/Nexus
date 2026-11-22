module;
#include <boost/corosio/io_context.hpp>
#include <proxy/proxy_macros.h>
module http.named_client;

import std;
import proxy.v4;
import cli.dns_transports;
import cli.outbounds;
import cli.rule_fetch_h2;
import cli.rule_fetch_h3;
import cli.rule_fetch_response;
import config;
import dns.https_query;
import dns.local_config;
import dns.message;
import dns.message_program;
import dns.response_addresses;
import http.connect;
import http.corosio_https;
import http.header;
import net.connection_pool;
import platform.network_selection;
import platform.network_state;
import platform.socket_options;
import proxy;
import proxy.session_quota;
import tls.connector;
import tls.byte_stream;
import tls.fingerprint;
import tls.profiles;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace http {
namespace {
    namespace io=nex::corosio;
    namespace capy=nex::capy;
    namespace fetch=cli::rule_fetch;
    using Protocol=config::HttpProtocol;
    using Clock=std::chrono::steady_clock;

#include "rule_fetch_connection.hpp"

#include "named_http1_pool.hpp"

    template<class Connector>
    struct PhysicalStream {
        Connector connector;

        PhysicalStream(io::io_context& context,Resolver resolver,tls::ShapedClientProfile const& profile,
            platform::TcpSocketOptions const& options) :connector(context,std::move(resolver),profile,options) {}
    };

    struct ProxyTcpStream {
        proxy::Session session;
        tls::detail::LayerConnector<ProxyStream,tls::ShapedClientProfile> connector;

        ProxyTcpStream(io::io_context& context,proxy::Server& server,proxy::SessionQuota::Lease lease,
            tls::ShapedClientProfile const& profile,std::size_t outbound,Resolver resolver)
            :session(context),connector(profile,server,session,outbound,std::move(resolver)) {
            server.attach_session(session,std::move(lease));
        }
        ~ProxyTcpStream(){session.close();}
    };

    template<class Owner>
    struct PooledStream {
        using Connector=decltype(Owner::connector);
        std::unique_ptr<Owner> owner;
        tls::detail::ByteStream<typename Connector::Socket> stream;

        explicit PooledStream(std::unique_ptr<Owner> value)
            :owner(std::move(value)),stream(*owner->connector.application()) {
            if constexpr (requires {owner->session;}) owner->session.relaying=true;
        }

        auto read(std::span<std::uint8_t> bytes,fetch::Http2Deadline deadline)
            -> capy::task<std::expected<std::size_t,tls::detail::ByteStreamError>> {
            return stream.read(bytes,deadline);
        }
        auto send(std::span<std::uint8_t const> bytes,fetch::Http2Deadline deadline) -> capy::task<bool> {
            if constexpr (requires {owner->session;}) owner->session.touched=Clock::now();
            return stream.send(bytes,deadline);
        }
        auto close_output(fetch::Http2Deadline deadline) -> capy::task<bool> {
            return stream.close_output(deadline);
        }
        auto cancel() noexcept -> void {owner->connector.cancel();}
    };

    template<class Owner>
    auto request_tcp(std::unique_ptr<Owner> owner,Protocol protocol,Clock::time_point connect_by,
        io::io_context& context,fetch::Http2Pool& h2_pool,Http1Pool& h1_pool,fetch::Transfer transfer) -> capy::task<fetch::TransferResult> {
        auto& connector=owner->connector;
        if (co_await connector.start(connect_by)!=tls::detail::ConnectResult::connected)
            co_return std::unexpected("HTTPS resolution, connection or certificate verification failed");
        auto* negotiated=connector.negotiated();
        constexpr std::array<std::uint8_t,2> h2{'h','2'};
        if (negotiated && negotiated->alpn && std::ranges::equal(*negotiated->alpn,h2)) {
            if constexpr (fetch::http2_enabled) {
                auto stream=pro::make_proxy<fetch::Http2StreamFacade,PooledStream<Owner>>(std::move(owner));
                auto result=co_await h2_pool.request(context,transfer,std::move(stream));
                if (result) co_return std::move(*result);
            }
            co_return std::unexpected("HTTP/2 rule fetch is unavailable in this build");
        }
        if (protocol==Protocol::http2) co_return std::unexpected("peer did not negotiate HTTP/2");
        co_return co_await h1_pool.fresh(context,std::move(owner),transfer);
    }

}

struct NamedHttpClient::Impl {
    config::Config config;
    std::size_t index;
    ConnectRequest destination;
    std::string authority;
    tls::ShapedClientProfile tls;
    std::vector<cli::DnsProtection> dns_transports;
    std::optional<io::io_context> direct;
    std::unique_ptr<proxy::Server> server;
    std::size_t active=0;
    fetch::Http2Pool h2;
    fetch::Http3Pool h3;
    Http1Pool h1;

    Impl(config::Config value,std::size_t selected,ConnectRequest target,std::string host,
        tls::ShapedClientProfile profile,std::vector<cli::DnsProtection> transports)
        :config(std::move(value)),index(selected),destination(std::move(target)),authority(std::move(host)),
         tls(std::move(profile)),dns_transports(std::move(transports)) {}

    ~Impl() {
        h3.stop();
        h2.stop();
        h1.stop();
        if (server) server->stop();
        else if (direct) {
            dns::stop_https_queries(*direct);
            direct->restart();
            (void)direct->run();
        }
    }
    auto executor() noexcept -> io::io_context& {return server ? server->executor_context() : *direct;}
    auto settings() const noexcept -> config::NamedHttpClient const& {return config.http_clients[index];}
};

NamedHttpClient::NamedHttpClient(std::unique_ptr<Impl> owner) noexcept :impl_(std::move(owner)) {}
NamedHttpClient::~NamedHttpClient()=default;

auto NamedHttpClient::create(config::Config config,std::string_view name,std::string_view authority)
    -> std::expected<std::unique_ptr<NamedHttpClient>,std::string> {
    auto selected=std::ranges::find(config.http_clients,name,&config::NamedHttpClient::name);
    if (selected==config.http_clients.end() || !config.dns) return std::unexpected("invalid named HTTP client");
    if (authority.empty() || std::ranges::any_of(authority,[](unsigned char c) {
        return c<=0x20 || c>=0x7f || c=='@' || c=='#' || c=='\\' || c=='/' || c=='?';
    })) return std::unexpected("invalid HTTPS authority");
    auto endpoint=std::string(authority);
    if (authority.ends_with(']') || !authority.contains(':')) endpoint+=":443";
    auto destination=parse_destination_authority(endpoint);
    if (destination.status!=ConnectStatus::accepted) return std::unexpected("invalid HTTPS authority");

    if (selected->protocol==Protocol::http3 && !fetch::http3_enabled)
        return std::unexpected("HTTP/3 rule fetch is unavailable in this build");
    if (selected->protocol==Protocol::http2 && !fetch::http2_enabled)
        return std::unexpected("HTTP/2 rule fetch is unavailable in this build");

    if (config.direct_network) {
        namespace network = ::platform::network;
        auto monitor=std::make_shared<network::Monitor>();
        if (!monitor->start(network::Clock::now()+std::chrono::milliseconds(20)))
            return std::unexpected("cannot read the Linux network snapshot");
        auto& binding=config.direct_tcp_options.binding;
        binding.network=std::make_shared<network::InterfaceSelection>(
            network::SystemInterfaceSelection(std::move(monitor),*config.direct_network,binding));
    }

    constexpr std::array<std::string_view,2> protocols{"h2","http/1.1"};
    std::span<std::string_view const> offer=protocols;
    if (selected->protocol==Protocol::http2) offer=offer.first(1);
    else if (selected->protocol==Protocol::http1 || !fetch::http2_enabled) offer=offer.last(1);
    auto exchange=selected->key_exchange;
    using KeyExchange=config::TlsKeyExchange;
    auto profile=tls::ClientProfile::load(destination.host,selected->ca_file,
        exchange==KeyExchange::x25519 ? 0x001d : 0x11ec,exchange==KeyExchange::x25519_mlkem768_only,offer);
    if (!profile) return std::unexpected(std::move(profile.error()));
    auto fingerprint=tls::parse_fingerprint(config::tls_fingerprint_name(selected->fingerprint));
    if (!fingerprint) return std::unexpected("invalid HTTP client TLS fingerprint");
    auto shaped=tls::ShapedClientProfile::create(std::move(*profile),*fingerprint,selected->record_size_limit);
    if (!shaped) return std::unexpected(std::move(shaped.error()));

    auto transports=cli::prepare_dns_transports(config);
    if (!transports) return std::unexpected(std::move(transports.error()));
    auto index=static_cast<std::size_t>(selected-config.http_clients.begin());
    auto impl=std::make_unique<Impl>(std::move(config),index,std::move(destination),std::string(authority),
        std::move(*shaped),std::move(*transports));
    if (impl->settings().outbound_index!=0 || cli::uses_proxy_dns(impl->config.dns)) {
        auto created=proxy::Server::create();
        if (!created) return std::unexpected("cannot initialize HTTP outbound: "+created.error().message());
        impl->server=std::move(*created);
        auto outbounds=cli::configure_outbounds(*impl->server,impl->config,impl->dns_transports);
        if (!outbounds) return std::unexpected(std::move(outbounds.error()));
        if (!impl->server->prepare_routing(1) || !impl->server->activate_context())
            return std::unexpected("cannot start HTTP outbound context");
    } else {
#if BOOST_COROSIO_HAVE_LIBURING
        impl->direct.emplace(io::uring);
#else
        impl->direct.emplace();
#endif
    }
    return std::unique_ptr<NamedHttpClient>(new NamedHttpClient(std::move(impl)));
}

auto NamedHttpClient::executor() noexcept -> io::io_context& {return impl_->executor();}
auto NamedHttpClient::settings() const noexcept -> config::NamedHttpClient const& {return impl_->settings();}
auto NamedHttpClient::allows_http3_alternative() const noexcept -> bool {
    return fetch::http3_enabled && settings().protocol==Protocol::automatic;
}

auto NamedHttpClient::get(NamedHttpRequest request,HttpBodyConsumer body,std::optional<HttpHeaderConsumer> headers)
    -> capy::task<std::expected<unsigned,std::string>> {
    if (!request.target.starts_with('/') ||
        std::ranges::any_of(request.target,[](unsigned char c) {
            return c<=0x20 || c>=0x7f || c=='#' || c=='\\';
        })) co_return std::unexpected("invalid HTTPS request target");
    if (request.alternative_port && (!*request.alternative_port || !allows_http3_alternative()))
        co_return std::unexpected("HTTP/3 alternative is unavailable for this client");
    if (Clock::now()>=request.deadline)
        co_return std::unexpected("HTTPS request deadline expired");
    constexpr std::array<std::string_view,14> reserved{
        "accept-encoding","connection","content-length","expect","host","http2-settings",
        "keep-alive","proxy-authenticate","proxy-authorization","proxy-connection","te","trailer",
        "transfer-encoding","upgrade"
    };
    std::size_t header_bytes=0;
    for (auto const& field:request.headers) {
        if (field.name.empty() || !std::ranges::all_of(field.name,[](char c) {
            return !(c>='A' && c<='Z') && header_token(c);
        }) || !valid_header_field_value(field.value) ||
            std::ranges::find(reserved,field.name)!=reserved.end())
            co_return std::unexpected("invalid HTTP request header");
        auto remaining=8192-header_bytes;
        if (remaining<32 || field.name.size()>remaining-32 || field.value.size()>remaining-32-field.name.size())
            co_return std::unexpected("HTTP request headers exceed their limit");
        header_bytes+=32+field.name.size()+field.value.size();
    }

    auto& owner=*impl_;
    auto const& selected=owner.settings();
    auto now=Clock::now();
    auto started=std::min(now,request.started.value_or(now));
    request.deadline=std::min(request.deadline,started+std::chrono::milliseconds(selected.timeout_ms));
    if (now>=request.deadline) co_return std::unexpected("HTTPS request deadline expired");
    if (owner.active>=16) co_return std::unexpected("HTTP client request limit reached");
    ++owner.active;
    struct Release {
        std::size_t& active;
        ~Release(){--active;}
    } release{owner.active};
    std::vector<HeaderField> fields;
    fields.reserve(selected.headers.size()+request.headers.size());
    for (auto const& [name,value]:selected.headers) fields.push_back({name,value});
    fields.append_range(request.headers);
    auto proxy_http=selected.outbound_index!=0;
    auto connect_by=proxy_http ? request.deadline : std::min(request.deadline,
        started+std::chrono::milliseconds(owner.config.direct_connect_timeout_ms));
    auto& context=owner.executor();
    auto destination=owner.destination;
    if (request.alternative_port) destination.port=*request.alternative_port;
    Resolver resolver{context,*owner.config.dns,selected.resolver_index,destination,owner.dns_transports};
    auto policy=fetch::ResponsePolicy{request.allow_not_modified,request.allow_redirect};
    auto const* observe=headers ? &*headers : nullptr;
    fetch::Transfer transfer{owner.authority,request.target,selected.max_bytes,request.deadline,
        fields,policy,observe,body};
    if (selected.protocol==Protocol::http3 || request.alternative_port) {
        fetch::Http3TunnelFactory make_tunnel;
        if (proxy_http) make_tunnel=[&] -> std::unique_ptr<fetch::Http3Tunnel> {
            auto quota=owner.server->acquire_session();
            if (!quota) return {};
            auto route=std::make_unique<fetch::Http3Tunnel>();
            route->session=std::make_unique<proxy::Session>(context);
            owner.server->attach_session(*route->session,std::move(*quota));
            route->session->relaying=true;
            route->tunnel=owner.server->open_packet_tunnel(*route->session,selected.outbound_index);
            if (!route->tunnel) return {};
            return route;
        };
        fetch::Http3Dial dial{context,owner.tls,owner.config.direct_tcp_options.binding,
            selected.ech_config_file,selected.max_udp_payload,selected.disable_path_mtu_discovery.value_or(false),
            connect_by,destination.port};
        co_return co_await owner.h3.request(std::ref(resolver),dial,std::move(make_tunnel),transfer);
    }

    if (selected.protocol!=Protocol::http1) {
        if (auto pooled=co_await owner.h2.request(context,transfer))
            co_return std::move(*pooled);
    }
    if (selected.protocol!=Protocol::http2) {
        if (auto pooled=co_await owner.h1.request(transfer); pooled && !pooled->retry)
            co_return std::move(pooled->result);
    }
    auto const& options=owner.config.direct_tcp_options;
    if (proxy_http) {
        auto lease=owner.server->acquire_session();
        if (!lease) co_return std::unexpected("HTTP outbound session limit reached");
        auto stream=std::make_unique<ProxyTcpStream>(context,*owner.server,std::move(*lease),owner.tls,
            selected.outbound_index,std::move(resolver));
        co_return co_await request_tcp(std::move(stream),selected.protocol,connect_by,context,owner.h2,owner.h1,transfer);
    }
    if (options.tcp_fast_open.value_or(false)) {
        using Connector=tls::detail::FastOpenPhysicalConnector<Resolver,tls::ShapedClientProfile>;
        auto stream=std::make_unique<PhysicalStream<Connector>>(context,std::move(resolver),owner.tls,options);
        co_return co_await request_tcp(std::move(stream),selected.protocol,connect_by,context,owner.h2,owner.h1,transfer);
    }
    using Connector=tls::detail::PhysicalConnector<Resolver,tls::ShapedClientProfile>;
    auto stream=std::make_unique<PhysicalStream<Connector>>(context,std::move(resolver),owner.tls,options);
    co_return co_await request_tcp(std::move(stream),selected.protocol,connect_by,context,owner.h2,owner.h1,transfer);
}
}
