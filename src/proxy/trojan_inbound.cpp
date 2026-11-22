module proxy;
import std;
import trojan;
import trojan.auth;
import trojan.stream;
import httpupgrade;
import httpupgrade.stream;
import websocket.stream;
import grpc.headers;
import grpc.session;
import grpc.stream;
import grpc.multiplex;
import grpc.multiplex_channel;
import grpc.connection;
import platform.ip_address;
import sniff.tcp;
import sniff.tcp_io;
import sniff.route_tcp;
import tls.byte_stream;
import tls.profiles;
import tls.server_credential;
import tls.corosio_application;
import tls.corosio_server_handshake;
import proxy.stream_relay;
import proxy.dns_state;
import rules;
import socks5;
import net.stream_datagrams;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

#include "transport_helpers.hpp"

namespace proxy {
    namespace {
        struct Profile {
            tls::ServerCredential credential;
            std::vector<trojan::PasswordKey> users;
            std::vector<std::string> names;
            std::optional<httpupgrade::Profile> transport;
            std::optional<transport_detail::GrpcSettings> grpc;
        };
        using WsStream=websocket::VlessByteStream<nex::corosio::tcp_socket>;
        using Incoming=trojan::detail::Inbound<nex::corosio::tcp_socket,WsStream>;
        template<class In>
        auto sniff_plaintext(void* context,sniff::TcpSniffer& sniffer,Clock::time_point deadline)
            -> nex::capy::task<sniff::TcpReadResult> {
            auto& incoming=*static_cast<In*>(context);
            std::array<std::uint8_t,4096> buffer{};
            for(;;) {
                auto state=sniffer.limit();
                if(state.status!=sniff::TcpStatus::need_more)co_return {sniff::TcpReadStop::classified,state,{}};
                if(Clock::now()>=deadline)co_return {sniff::TcpReadStop::deadline,state,{}};
                auto result=co_await incoming.read_sniff(std::span(buffer).first(std::min(buffer.size(),sniffer.remaining())),deadline);
                if(!result) {
                    if(result.error()==tls::detail::ByteStreamError::timeout)co_return {sniff::TcpReadStop::deadline,sniffer.current(),{}};
                    co_return {sniff::TcpReadStop::io_error,sniffer.current(),std::make_error_code(std::errc::io_error)};
                }
                if(!*result)co_return {sniff::TcpReadStop::eof,sniffer.finish(),{}};
                auto accepted=sniffer.feed(std::span(buffer).first(*result));
                if(accepted.consumed!=*result)co_return {sniff::TcpReadStop::io_error,accepted,std::make_error_code(std::errc::protocol_error)};
            }
        }
        template<class In>
        auto serve_trojan_stream(Session& session,nex::corosio::io_context& context,rules::RouteMatcher const& policy,
            Profile const& profile,In& incoming,Clock::time_point deadline) -> nex::capy::task<> {
            auto accepted=co_await incoming.read_request(deadline);
            if (!accepted || session.closed || accepted->user>=profile.users.size()) co_return;
            if (!profile.names.empty() && !session.admit_principal(profile.names[accepted->user])) co_return;
            if (accepted->request.command==trojan::Command::udp) {
                if(session.ordered_tcp && !session.ordered_tcp->udp) co_return;
                session.begin_traffic(TrafficProtocol::trojan_udp,0);
                session.select_traffic_path(ConnectPath::datagrams);
                session.relaying=true; session.touched=Clock::now();
                auto resolver=[&](std::string name,std::uint16_t port,Clock::time_point limit) {
                    return resolve_udp_domain(session,context,std::move(name),port,limit);
                };
                auto source=source_endpoint(session,session.ordered_tcp || policy.needs_source() || session.dns_requirements().source);
                auto router=session.ordered_tcp ? ordered_datagram_router(session,context,source) : net::stream_datagrams::OrderedRouter{};
                net::stream_datagrams::Server state(session,context,incoming,policy,resolver,trojan::datagram_framing,
                    net::ProxyAddress{},source,std::move(router));
                try { (void)co_await nex::capy::when_all(net::stream_datagrams::tasks(state)); }
                catch (...) { session.close(); state.cancel(); throw; }
                co_return;
            }
            auto const& destination=accepted->request.destination;
            socks5::Request target; target.status=socks5::Status::accepted;
            target.address_type=destination.family==trojan::Family::ipv4 ? 1 : destination.family==trojan::Family::ipv6 ? 4 : 3;
            target.address_length=destination.length; target.port=destination.port;
            std::copy_n(destination.bytes.begin(),destination.length,target.address.begin());
            session.begin_traffic(TrafficProtocol::trojan,target.port);
            if(session.ordered_tcp) {
                OrderedTcpRequest request;
                if(!request.prepare(session,target)) co_return;
                std::array<std::uint8_t,16384> wire{},scratch{};
                sniff::TcpSniffer sniffer(wire,scratch);rules::ProgramCursor cursor;
                auto const& ordered=*session.ordered_tcp;
                OrderedTcpResult result;
                if (session.transport_owner) {
                    result=co_await execute_ordered_tcp(session,context,ordered.program,cursor,request.input,sniffer,
                        request.candidates,request.endpoints,ordered.fallback,std::min(deadline,Clock::now()+ordered.sniff_timeout),
                        deadline,ordered.unknown_policy,&incoming,&sniff_plaintext<In>);
                } else {
                    auto branch=[&]() -> nex::capy::task<nex::capy::results<OrderedTcpResult>> {
                        auto r=co_await execute_ordered_tcp(session,context,ordered.program,cursor,request.input,sniffer,
                            request.candidates,request.endpoints,ordered.fallback,std::min(deadline,Clock::now()+ordered.sniff_timeout),
                            deadline,ordered.unknown_policy,&incoming,&sniff_plaintext<In>);
                        co_return nex::capy::results<OrderedTcpResult>{std::make_error_code(std::errc::operation_canceled),std::move(r)};
                    };
                    auto [signal,r,watch]=co_await nex::capy::when_all(branch(),watch_client_error(session));
                    (void)signal;(void)watch;
                    result=std::move(r);
                }
                if(session.closed || result.stop!=sniff::RouteTcpStop::terminal || result.code) co_return;
                sniff::TcpReplay replay(result.first_sent ? std::span<std::uint8_t const>{} : sniffer.wire());
                if(!co_await replay_ordered_tcp(session,replay,deadline)) co_return;
            } else {
                auto dialed=session.transport_owner
                    ? co_await dial_destination(session,context,policy,target,deadline)
                    : co_await dial(session,context,policy,target);
                if (dialed || session.closed) co_return;
            }
            session.relaying=true; session.touched=Clock::now();
            try {
                (void)co_await nex::capy::when_all(stream_relay::direction(session,stream_relay::upload(session,incoming)),
                    stream_relay::direction(session,stream_relay::download(session,incoming)));
            } catch (...) { session.close(); throw; }
        }
        auto serve(Session& session,nex::corosio::io_context& context,rules::RouteMatcher const& policy,Profile const& profile) -> nex::capy::task<> {
            auto fail=[&] { session.close(); session.done=true; };
            auto deadline=session.started+std::chrono::seconds(10);
            auto milliseconds=[](auto value) { return std::chrono::duration_cast<std::chrono::milliseconds>(value.time_since_epoch()).count(); };
            auto start=milliseconds(session.started),end=milliseconds(deadline);
            if (start<0 || end<=start) { fail(); co_return; }
            auto budget=std::make_shared<memory::Budget>(8u*1024*1024);
            std::string_view req_alpn = profile.grpc ? "h2" : profile.transport ? "http/1.1" : "";
            auto handshake=tls::make_server_handshake(profile.credential,start,end,budget,req_alpn);
            if (!handshake) { fail(); co_return; }
            auto established=co_await tls::detail::server_handshake(session.client,*handshake,budget);
            if (!established || session.closed) { fail(); co_return; }
            tls::detail::ApplicationConnection<nex::corosio::tcp_socket> connection(session.client,std::move(established->records),std::move(established->unread));
            if (!established->release_unread_reservation()) { fail(); co_return; }
            if (profile.grpc) {
                using Lower=tls::detail::ByteStream<nex::corosio::tcp_socket>;
                using Channel=grpc::MultiplexChannel<Lower,16,grpc::detail::ByteStreamReadPolicy>;
                Lower lower(connection);
                auto proto=grpc::MultiplexSession<16>::create(grpc::Role::server,profile.grpc->request,grpc::ResponsePolicy::standard,profile.grpc->limits);
                if (!proto) { fail(); co_return; }
                Channel channel(lower,std::move(*proto));
                session.relaying=true; session.touched=Clock::now();
                auto run_ch=[&]() -> nex::capy::task<nex::capy::results<>> { co_return co_await channel.run(); };
                auto worker=[&]() -> nex::capy::task<nex::capy::results<>> {
                    while (!session.closed) {
                        if (auto ticket=channel.accept()) {
                            typename Channel::Stream rpc(channel,*ticket);
                            transport_detail::GrpcByteStream<typename Channel::Stream> adapted{rpc,&session};
                            Session child(context);
                            child.transport_owner=&session; child.register_child_traffic();
                            child.route_snapshot=session.route_snapshot; child.ordered_tcp=session.ordered_tcp;
                            child.principal_policy=session.principal_policy; child.inbound=session.inbound;
                            child.dns=session.dns; child.local_dns=session.local_dns;
                            child.tunnel_factories=session.tunnel_factories; child.direct_connect_timeout_ms=session.direct_connect_timeout_ms;
                            child.direct_tcp_options=session.direct_tcp_options;
                            child.started=child.touched=Clock::now(); child.handshake_deadline=child.started+std::chrono::seconds(10);
                            std::stop_callback sc(session.stop.get_token(),[&]() noexcept { child.close(); rpc.cancel(); });
                            std::stop_callback sc_child(child.stop.get_token(),[&]() noexcept { rpc.cancel(); });
                            trojan::detail::Inbound<nex::corosio::tcp_socket,decltype(adapted)&> in(adapted,profile.users);
                            try { co_await serve_trojan_stream(child,context,policy,profile,in,child.handshake_deadline); } catch (...) {}
                            child.close(); rpc.cancel();
                            continue;
                        }
                        if (!co_await channel.wait_change()) break;
                    }
                    co_return nex::capy::results<>{};
                };
                std::vector<nex::capy::task<nex::capy::results<>>> tasks;
                tasks.reserve(17); tasks.push_back(run_ch());
                for (unsigned i=0;i<16;++i) tasks.push_back(worker());
                try { (void)co_await nex::capy::when_all(std::move(tasks)); } catch (...) { channel.cancel(); }
                fail(); co_return;
            }
            Incoming incoming(connection,profile.users);
            if (profile.transport) {
                if (!co_await transport_detail::handshake_ws_or_hu(incoming.stream(),*profile.transport,deadline) || session.closed) {
                    fail(); co_return;
                }
            }
            co_await serve_trojan_stream(session,context,policy,profile,incoming,deadline);
            fail();
        }
    }
    auto make_trojan_inbound_factory(std::string_view certificate,std::string_view key,std::span<std::string const> passwords,
        std::span<std::string const> names,std::optional<HttpUpgradeTransport> transport,std::optional<GrpcTransport> grpc_cfg) -> std::expected<InboundFactory,std::string> {
        if (passwords.empty() || passwords.size()>64 || (!names.empty() && names.size()!=passwords.size())) return std::unexpected("invalid Trojan users");
        if (transport && grpc_cfg) return std::unexpected("Trojan inbound accepts at most one transport");
        for (std::size_t i=0;i<names.size();++i)
            if (names[i].empty() || names[i].size()>255 || names[i].find('\0')!=std::string::npos || std::ranges::contains(names.first(i),names[i]))
                return std::unexpected("invalid or duplicate Trojan user name");
        auto credential=tls::load_server_credential(certificate,key);
        if (!credential) return std::unexpected(credential.error());
        auto profile=std::make_unique<Profile>(std::move(*credential));
        if (transport) {
            auto compiled=transport_detail::compile_httpupgrade(*transport,false,{});
            if (!compiled) return std::unexpected(compiled.error());
            profile->transport=std::move(*compiled);
        }
        if (grpc_cfg) {
            auto compiled=transport_detail::compile_grpc(*grpc_cfg,false,{});
            if (!compiled) return std::unexpected(compiled.error());
            profile->grpc=std::move(*compiled);
        }
        for (auto const& path:passwords) {
            auto password=trojan::PasswordKey::load(path);
            if (!password) return std::unexpected(password.error());
            if (trojan::authenticate(profile->users,password->view())) return std::unexpected("duplicate Trojan password");
            profile->users.push_back(std::move(*password));
        }
        profile->names.assign(names.begin(),names.end());
        return InboundFactory{[profile=std::move(profile)](Session& session,nex::corosio::io_context& context,rules::RouteMatcher const& policy) {
            return serve(session,context,policy,*profile);
        }};
    }
}
