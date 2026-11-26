module;
#include <boost/capy/ex/run.hpp>
#include <boost/corosio/socket_option.hpp>

module relay;
import std;
import proxy.v4;
import crypto;
import http.connect;
import http.header;
import http2.driver;
import http2.server_streams;
import http2.client_types;
import http2.headers;
import hysteria2.transport_options;
import masque.session;
import quic.cid_registry;
import quic.datagram_port;
import quic.datagram_session;
import quic.native_memory;
import quic.retry_admission;
import quic.retry_token;
import quic.tls_server;
import net.datagram_driver;
import tls.profiles;
import tls.server_credential;
import tls.ech_server;
import nghttp3;
import ngtcp2;
import memory.budget;
import net.socket_stream;
import reality.server_profile;
import reality.server_probe;
import reality.fallback;
import rules;
import socks5;
import tls.byte_stream;
import tls.corosio_application;
import tls.corosio_server_handshake;
import vless;
import vless.server_profile;
import vless.tls_server;
import xhttp.client;
import xhttp.config;
import xhttp.server;
import xhttp.wire;
import relay.stream_relay;
import relay.vless_mux;
import capy;
import corosio;
import :xhttp_http1;
import :reality_tcp_server;
import :xhttp_inbound_types;
import :xhttp_http1_ingress;
import :xhttp_http2_server;
import :xhttp_http3_listener;

namespace relay {
    namespace vless_xhttp {
        auto serve(Session& session,corosio::io_context& context,rules::RouteMatcher const& policy,
            InboundProfile& profile) -> capy::task<> {
            struct Done {
                Session& session;
                ~Done(){session.close();session.done=true;}
            } done{session};
            if (session.ordered_tcp) co_return;
            std::optional<tls::detail::ApplicationConnection<Socket>> connection;
            Lower lower(session.client);
            if (profile.secure) {
                auto limit=session.started+std::chrono::seconds(10);
                auto ms=[](Clock::time_point when) {return std::chrono::duration_cast<std::chrono::milliseconds>(when.time_since_epoch()).count();};
                auto budget=std::make_shared<memory::Budget>(8*1024*1024);
                auto protocol=profile.transport.endpoint.version==xhttp::HttpVersion::http2 ? "h2" : "";
                auto establish=[&]() -> capy::task<std::optional<tls::detail::ServerAsyncResult>> {
                    if (profile.reality)
                        co_return co_await reality_tcp::establish(session,context,*profile.reality,budget,ms(session.started),ms(limit),protocol);
                    auto handshake=profile.vless.tls_handshake(ms(session.started),ms(limit),budget,protocol);
                    if (!handshake) co_return std::nullopt;
                    auto accepted=co_await tls::detail::server_handshake(session.client,*handshake,budget);
                    if (!accepted) co_return std::nullopt;
                    co_return std::move(*accepted);
                };
                auto accepted=co_await establish();
                if (!accepted || session.closed) co_return;
                connection.emplace(session.client,std::move(accepted->records),std::move(accepted->unread));
                if (!accepted->release_unread_reservation()) co_return;
                lower.attach(*connection);
            }
            if (profile.transport.endpoint.version==xhttp::HttpVersion::http1) {
                co_await process(session,context,policy,profile,lower);
                co_return;
            }
            http2::ClientLimits limits;
            limits.header_bytes=http::max_header_bytes;
            auto native=H2Session::create(limits);
            if (!native) co_return;
            H2Driver driver(lower,std::move(*native));
            RelaySlots slots;
            session.relaying=true;
            auto run=[&]() -> capy::task<capy::results<>> {
                auto result=co_await driver.run();
                session.close();
                co_return result;
            };
            std::vector<capy::task<capy::results<>>> workers;
            workers.reserve(17);
            workers.push_back(run());
            for (unsigned i=0;i<16;++i) workers.push_back(h2_worker(session,context,policy,profile,driver,slots));
            try {(void)co_await capy::when_all(std::move(workers));}
            catch (...) {driver.cancel();}
        }
    }

    static auto load_xhttp_inbound(std::string_view certificate,std::string_view key,std::span<std::string const> users,
        std::span<std::string const> names,xhttp::Profile transport,std::optional<RealityInbound> reality,
        InboundTlsRuntime const& tls_rt = {})
        -> std::expected<std::unique_ptr<vless_xhttp::InboundProfile>,std::string> {
        using namespace vless_xhttp;
        if (!transport.limits.valid() || !xhttp::valid_padding(transport.padding) || transport.download)
            return std::unexpected("invalid VLESS XHTTP inbound options");
        if (transport.endpoint.version==xhttp::HttpVersion::http1 &&
            transport.mode!=xhttp::Mode::automatic && transport.mode!=xhttp::Mode::packet_up)
            return std::unexpected("VLESS XHTTP HTTP/1.1 requires packet-up");
        if (!names.empty() && names.size()!=users.size()) return std::unexpected("VLESS user names do not match UUIDs");
        for (std::size_t i=0;i<names.size();++i)
            if (names[i].empty() || names[i].size()>255 || names[i].contains('\0') ||
                std::find(names.begin(),names.begin()+i,names[i])!=names.begin()+i)
                return std::unexpected("invalid or duplicate VLESS user name");
        auto secure=reality || !certificate.empty() || bool(tls_rt.atomic_credential);
        auto pki_tcp=secure && !reality && transport.endpoint.version!=xhttp::HttpVersion::http3;
        auto auth=pki_tcp
            ? (tls_rt.atomic_credential
                ? vless::ServerProfile::load_dynamic(std::static_pointer_cast<tls::AtomicServerCredential>(tls_rt.atomic_credential),users)
                : vless::ServerProfile::load(certificate,key,users))
            : vless::ServerProfile::load_users(users);
        if (!auth) return std::unexpected(auth.error());
        if (pki_tcp) {
            if (!tls_rt.alpn.empty()) auth->set_alpn(tls_rt.alpn);
            if (!tls_rt.ech_key_file.empty()) {
                auto ech=tls::load_ech_server_keys_file(tls_rt.ech_key_file);
                if (!ech) return std::unexpected("XHTTP VLESS ECH key: "+ech.error());
                auth->set_ech_keys(std::move(*ech));
            }
        }
        auto budget=std::make_shared<memory::Budget>(transport.limits.buffer_bytes+128u*transport.limits.buffered_posts);
        auto profile=std::unique_ptr<InboundProfile>(new InboundProfile{std::move(*auth),std::move(transport),
            {names.begin(),names.end()},std::move(budget),{},secure,{}});
        if (reality) {
            auto authenticated=RealityTcpProfile::load(std::move(*reality));
            if (!authenticated) return std::unexpected(authenticated.error());
            profile->reality.emplace(std::move(*authenticated));
        }
        return profile;
    }

    auto make_vless_xhttp_inbound_factory(std::string_view certificate,std::string_view key,std::span<std::string const> users,
        std::span<std::string const> names,xhttp::Profile transport,std::optional<RealityInbound> reality,InboundTlsRuntime const& tls_rt)
        -> std::expected<InboundFactory,std::string> {
        auto profile=load_xhttp_inbound(certificate,key,users,names,std::move(transport),std::move(reality),tls_rt);
        if (!profile) return std::unexpected(profile.error());
        return InboundFactory{[profile=std::move(*profile)](Session& session,corosio::io_context& context,rules::RouteMatcher const& policy) {
            return vless_xhttp::serve(session,context,policy,*profile);
        }};
    }

    auto Server::prepare_xhttp3(std::string_view certificate,std::string_view key,std::span<std::string const> users,
        std::span<std::string const> names,xhttp::Profile transport) -> std::expected<void,std::string> {
        auto profile=load_xhttp_inbound(certificate,key,users,names,std::move(transport),{},inbound_tls_runtime);
        if (!profile) return std::unexpected(profile.error());
        std::string alpn=!inbound_tls_runtime.alpn.empty() ? inbound_tls_runtime.alpn.front() : "h3";
        if (inbound_tls_runtime.atomic_credential) {
            auto atomic=std::static_pointer_cast<tls::AtomicServerCredential>(inbound_tls_runtime.atomic_credential);
            xhttp3_inbound=std::make_shared<Xhttp3Inbound>(*this,std::move(*profile),std::nullopt,std::move(atomic),std::move(alpn));
        } else {
            auto credential=tls::load_server_credential(certificate,key);
            if (!credential) return std::unexpected(credential.error());
            xhttp3_inbound=std::make_shared<Xhttp3Inbound>(*this,std::move(*profile),std::move(*credential),nullptr,std::move(alpn));
        }
        vless_xhttp_inbound=true;
        return {};
    }

    auto Server::start_xhttp3(corosio::endpoint endpoint) -> std::expected<std::uint16_t,std::error_code> {
        if (ordered_tcp || admission) return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
        if (auto active=activate_context();!active) {stop();return std::unexpected(active.error());}
        try {
            if (auto owner=xhttp3_inbound->restart_owner()) xhttp3_inbound=std::move(owner);
            auto bound=xhttp3_inbound->start(endpoint,[this] {record_failure({FailureKind::accept_task,{}});});
            if (!bound) {stop();return std::unexpected(bound.error());}
            bound_listener=*bound;
            inbound_type=Inbound::vless;
            accepting=true;
            return bound->port();
        } catch (...) {
            stop();
            throw;
        }
    }

    auto Server::drain_xhttp3() noexcept -> void {if (xhttp3_inbound) xhttp3_inbound->drain();}
    auto Server::stop_xhttp3() noexcept -> void {if (xhttp3_inbound) xhttp3_inbound->stop();}
}
