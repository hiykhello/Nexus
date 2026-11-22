module;
#include <boost/corosio/socket_option.hpp>
module proxy;
import std;
import proxy.v4;
import socks5;
import rules;
import http.connect;
import vless;
import vless.server_profile;
import vless.tls_server;
import sniff.tcp;
import sniff.tcp_io;
import sniff.route_tcp;
import vless.vision_server;
import reality.server_profile;
import reality.server_probe;
import reality.fallback;
import tls.corosio_server_handshake;
import tls.corosio_application;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import proxy.stream_relay;
import proxy.vless_mux;
import xudp;
import xudp.server_io;
import net.udp_socket;
import net.stream_datagrams;
import net.datagram_frame;
import proxy.dns_state;
import httpupgrade;
#ifdef NEXUS_TEST_VLESS_RELAY_THROW
extern "C" void nexus_test_vless_relay_throw(unsigned);
#endif
#ifdef NEXUS_TEST_VLESS_PROFILE_LIFETIME
extern "C" void nexus_test_vless_profile_enter();
#endif
#ifdef NEXUS_TEST_VLESS_ABANDON
extern "C" void nexus_test_vless_profile_created();
extern "C" void nexus_test_vless_profile_destroyed();
extern "C" void nexus_test_vless_profile_frame_enter();
extern "C" void nexus_test_vless_profile_frame_exit();
extern "C" void nexus_test_vless_relay_frame_enter();
extern "C" void nexus_test_vless_relay_frame_exit();
#endif
#include "reality_tcp_server.hpp"

namespace proxy {
    namespace {
        using Connection=tls::detail::ApplicationConnection<nex::corosio::tcp_socket>;
        using Incoming=vless::detail::TlsInbound<nex::corosio::tcp_socket>;
        using VisionIncoming=vless::detail::VisionInbound<nex::corosio::tcp_socket>;
        auto sniff_vless(void* context,sniff::TcpSniffer& sniffer,Clock::time_point deadline) -> nex::capy::task<sniff::TcpReadResult> {
            auto& incoming=*static_cast<Incoming*>(context);std::array<std::uint8_t,4096> buffer{};
            for(;;) {
                auto state=sniffer.limit();
                if(state.status!=sniff::TcpStatus::need_more)co_return {sniff::TcpReadStop::classified,state,{}};
                if(Clock::now()>=deadline)co_return {sniff::TcpReadStop::deadline,state,{}};
                auto result=co_await incoming.read_sniff(std::span(buffer).first(std::min(buffer.size(),sniffer.remaining())),deadline);
                if(!result) {
                    if(result.error()==vless::detail::TlsInboundError::timeout)co_return {sniff::TcpReadStop::deadline,sniffer.current(),{}};
                    co_return {sniff::TcpReadStop::io_error,sniffer.current(),std::make_error_code(std::errc::io_error)};
                }
                if(!*result)co_return {sniff::TcpReadStop::eof,sniffer.finish(),{}};
                auto fed=sniffer.feed(std::span(buffer).first(*result));
                if(fed.consumed!=*result)co_return {sniff::TcpReadStop::io_error,fed,std::make_error_code(std::errc::protocol_error)};
            }
        }
        struct OwnedProfile {
            vless::ServerProfile value;
            std::vector<std::string> names;
            std::optional<RealityTcpProfile> reality;
            std::optional<httpupgrade::Profile> transport;
            explicit OwnedProfile(vless::ServerProfile&& profile) : value(std::move(profile)) {
#ifdef NEXUS_TEST_VLESS_ABANDON
                nexus_test_vless_profile_created();
#endif
            }
#ifdef NEXUS_TEST_VLESS_ABANDON
            ~OwnedProfile() { nexus_test_vless_profile_destroyed(); }
#endif
        };
        struct RelayHooks {
#ifdef NEXUS_TEST_VLESS_RELAY_THROW
            static auto upload() -> void { nexus_test_vless_relay_throw(3); }
            static auto download() -> void { nexus_test_vless_relay_throw(4); }
#endif
#ifdef NEXUS_TEST_VLESS_ABANDON
            RelayHooks() { nexus_test_vless_relay_frame_enter(); }
            ~RelayHooks() { nexus_test_vless_relay_frame_exit(); }
#endif
        };
#ifdef NEXUS_ENABLE_SOCKS_UDP
        struct MuxStream {
            Session& session; Incoming* incoming; VisionIncoming* vision;
            auto read(std::span<std::uint8_t> bytes) -> nex::capy::task<std::expected<std::size_t,int>> {
                auto result=vision ? co_await vision->read(bytes) : co_await incoming->read(bytes);
                if (!result || session.closed) co_return std::unexpected(1);
                if (*result) session.touched=Clock::now(); co_return *result;
            }
            auto write(std::span<std::uint8_t const> bytes) -> nex::capy::task<bool> {
                bool result=vision ? co_await vision->send(bytes) : co_await incoming->send(bytes);
                if (result && !session.closed) session.touched=Clock::now();
                co_return result && !session.closed;
            }
            auto cancel() noexcept -> void { session.close(); }
        };
        struct MuxLookup {
            auto operator()(Session& session,nex::corosio::io_context& context,std::string name,std::uint16_t port,Clock::time_point deadline) const {
                return resolve_udp_domain(session,context,std::move(name),port,deadline);
            }
        };
        using MuxResolver=vless_mux::Resolver<Session,MuxLookup>;
        using MuxServer=vless_mux::Server<MuxStream,MuxResolver>;

        auto serve_udp(Session& session,nex::corosio::io_context& context,rules::RouteMatcher const& policy,
            Incoming& incoming,vless::TcpRequest const& request,Clock::time_point deadline) -> nex::capy::task<> {
            auto accepted=co_await incoming.complete_dial(true,deadline);
            if (!accepted || session.closed) co_return;
            net::ProxyAddress destination;
            destination.family=request.kind==vless::AddressKind::ipv4 ? net::ProxyAddressFamily::ipv4 :
                request.kind==vless::AddressKind::ipv6 ? net::ProxyAddressFamily::ipv6 : net::ProxyAddressFamily::domain;
            bool packetaddr=request.kind==vless::AddressKind::domain &&
                std::ranges::equal(request.address,vless::packetaddr_domain);
            if (!packetaddr) {
                destination.port=request.port;
                destination.length=static_cast<std::uint8_t>(request.address.size());
                std::ranges::copy(request.address,destination.bytes.begin());
            }
            session.begin_traffic(TrafficProtocol::vless,destination.port);
            session.select_traffic_path(ConnectPath::datagrams);
            session.relaying=true; session.touched=Clock::now();
            auto resolver=[&](std::string name,std::uint16_t port,Clock::time_point until) {
                return resolve_udp_domain(session,context,std::move(name),port,until);
            };
            auto source=source_endpoint(session,session.ordered_tcp || policy.needs_source() || session.dns_requirements().source);
            auto router=session.ordered_tcp ? ordered_datagram_router(session,context,source) : net::stream_datagrams::OrderedRouter{};
            auto framing=packetaddr ? net::DatagramFraming{.address=net::AddressWire::packetaddr} :
                net::DatagramFraming{.connected=true};
            net::stream_datagrams::Server state(session,context,incoming,policy,resolver,
                framing,destination,source,std::move(router));
            try { (void)co_await nex::capy::when_all(net::stream_datagrams::tasks(state)); }
            catch (...) { session.close(); state.cancel(); throw; }
        }
#endif
        auto establish(Session& session,nex::corosio::io_context& context,OwnedProfile const& owned,
                       std::shared_ptr<memory::Budget> budget,std::uint64_t start,std::uint64_t deadline)
            -> nex::capy::task<std::optional<tls::detail::ServerAsyncResult>> {
            if (!owned.reality) {
                auto handshake=owned.value.tls_handshake(start,deadline,budget,owned.transport ? "http/1.1" : ""); if (!handshake) co_return std::nullopt;
                auto result=co_await tls::detail::server_handshake(session.client,*handshake,budget);
                if (!result || session.closed) co_return std::nullopt;
                co_return std::move(*result);
            }
            co_return co_await reality_tcp::establish(session,context,*owned.reality,std::move(budget),start,deadline);
        }
        auto serve(Session& session,nex::corosio::io_context& context,rules::RouteMatcher const& policy,
                   OwnedProfile const& owned,bool vision) -> nex::capy::task<> {
#ifdef NEXUS_TEST_VLESS_ABANDON
            struct FrameProbe { ~FrameProbe() { nexus_test_vless_profile_frame_exit(); } } probe;
            nexus_test_vless_profile_frame_enter();
#endif
#ifdef NEXUS_TEST_VLESS_PROFILE_LIFETIME
            nexus_test_vless_profile_enter();
#endif
            auto fail=[&] { session.close(); session.done=true; };
            auto ms=[](Clock::time_point time) { return std::chrono::duration_cast<std::chrono::milliseconds>(time.time_since_epoch()).count(); };
            auto start=ms(session.started), deadline=ms(session.started+std::chrono::seconds(10));
            if (start<0 || deadline<=start) { fail(); co_return; }
            // This bounds the handshake's accounted buffers; it is not a
            // complete per-connection memory limit.
            auto budget=std::make_shared<memory::Budget>(8u*1024*1024);
            auto established=co_await establish(session,context,owned,budget,start,deadline);
            if (!established || session.closed) { fail(); co_return; }
            auto const& profile=owned.value;
            Connection connection(session.client,std::move(established->records),std::move(established->unread));
            if (!established->release_unread_reservation()) { fail(); co_return; }
            auto state=vision ? profile.vision_handshake() : profile.vless_handshake(); if (!state) { fail(); co_return; }
#ifdef NEXUS_ENABLE_SOCKS_UDP
            if (!vision && (!session.ordered_tcp || session.ordered_tcp->udp) && !state->allow_udp()) {
                fail(); co_return;
            }
#endif
            std::unique_ptr<Incoming> incoming;
            std::unique_ptr<VisionIncoming> vision_incoming;
            if (vision) vision_incoming=std::make_unique<VisionIncoming>(session.client,connection,std::move(*state));
            else incoming=std::make_unique<Incoming>(connection,std::move(*state));
            auto limit=session.started+std::chrono::seconds(10);
            tls::detail::ApplicationDeadline request_limit=owned.transport ? tls::detail::ApplicationDeadline(limit) : std::nullopt;
            if (owned.transport) {
                auto upgraded=co_await incoming->upgrade(*owned.transport,limit);
                if (!upgraded || session.closed) { fail(); co_return; }
            }
#ifdef NEXUS_ENABLE_SOCKS_UDP
            if (!(vision ? vision_incoming->allow_mux() : incoming->allow_mux())) { fail(); co_return; }
#endif
            auto header=vision ? co_await vision_incoming->read_header() : co_await incoming->read_header(request_limit);
            if (!header || session.closed) { fail(); co_return; }
            if (!owned.names.empty()) {
                auto const& identity=std::holds_alternative<vless::UserId>(*header) ? std::get<vless::UserId>(*header) : std::get<vless::TcpRequest>(*header).user;
                auto index=profile.user_index(identity);
                if (!index || *index>=owned.names.size() || !session.admit_principal(owned.names[*index])) {
                    fail(); co_return;
                }
            }
            if (std::holds_alternative<vless::UserId>(*header)) {
                if(session.ordered_tcp){fail();co_return;}
#ifdef NEXUS_ENABLE_SOCKS_UDP
                auto accepted=vision ? co_await vision_incoming->complete_dial(true) : co_await incoming->complete_dial(true,request_limit);
                if (!accepted || session.closed) { fail(); co_return; }
                session.relaying=true; session.touched=Clock::now();
                MuxStream stream{session,incoming.get(),vision_incoming.get()}; MuxResolver resolver{session,context};
                auto source=source_endpoint(session,policy);
                MuxServer mux(stream,resolver,policy,256,65535,source ? &*source : nullptr,session.auth_user,
                    session.direct_tcp_options ? &session.direct_tcp_options->binding : nullptr,vless_mux::FlowAccounting(session));
                try { (void)co_await nex::capy::when_all(vless_mux::read(session,mux),vless_mux::poll(session,mux),vless_mux::timeout(session,mux,resolver)); }
                catch (...) { mux.cancel(); }
                fail(); co_return;
#else
                fail(); co_return;
#endif
            }
            auto request=std::get_if<vless::TcpRequest>(&*header);
#ifdef NEXUS_ENABLE_SOCKS_UDP
            if (request->command==vless::TargetCommand::udp) {
                co_await serve_udp(session,context,policy,*incoming,*request,limit);
                fail(); co_return;
            }
#endif
            socks5::Request target; target.status=socks5::Status::accepted; target.port=request->port;
            target.address_type=request->kind==vless::AddressKind::ipv4 ? 1 : request->kind==vless::AddressKind::ipv6 ? 4 : 3;
            target.address_length=static_cast<std::uint8_t>(request->address.size());
            std::copy(request->address.begin(),request->address.end(),target.address.begin());
            session.begin_traffic(TrafficProtocol::vless,target.port);
            if(session.ordered_tcp) {
                if(vision){fail();co_return;}
                OrderedTcpRequest route;if(!route.prepare(session,target)){fail();co_return;}
                std::array<std::uint8_t,16384> wire{},scratch{};sniff::TcpSniffer sniffer(wire,scratch);rules::ProgramCursor cursor;
                auto const& ordered=*session.ordered_tcp;
                auto branch=[&]() -> nex::capy::task<nex::capy::results<OrderedTcpResult>> {
                    auto result=co_await execute_ordered_tcp(session,context,ordered.program,cursor,route.input,sniffer,route.candidates,
                        route.endpoints,ordered.fallback,std::min(limit,Clock::now()+ordered.sniff_timeout),limit,ordered.unknown_policy,incoming.get(),&sniff_vless);
                    co_return nex::capy::results<OrderedTcpResult>{std::make_error_code(std::errc::operation_canceled),std::move(result)};
                };
                auto [signal,result,watch]=co_await nex::capy::when_all(branch(),watch_client_error(session));(void)signal;(void)watch;
                if(session.closed || result.stop!=sniff::RouteTcpStop::terminal || result.code){fail();co_return;}
                auto accepted=co_await incoming->complete_dial(true,request_limit);
                if(!accepted){fail();co_return;}
                sniff::TcpReplay replay(result.first_sent ? std::span<std::uint8_t const>{} : sniffer.wire());if(!co_await replay_ordered_tcp(session,replay,limit)){fail();co_return;}
            } else {
                auto result=co_await dial(session,context,policy,target,owned.transport ? limit : Clock::time_point::max());
                if (result || session.closed) { fail(); co_return; }
                auto accepted=vision ? co_await vision_incoming->complete_dial(true) : co_await incoming->complete_dial(true,request_limit);
                if (!accepted) { fail(); co_return; }
            }
            session.relaying=true; session.touched=Clock::now();
            try {
#ifdef NEXUS_TEST_VLESS_RELAY_THROW
                nexus_test_vless_relay_throw(1);
#endif
                auto first=stream_relay::direction<RelayHooks>(session,vision ?
                    stream_relay::upload<RelayHooks>(session,*vision_incoming) : stream_relay::upload<RelayHooks>(session,*incoming));
#ifdef NEXUS_TEST_VLESS_RELAY_THROW
                nexus_test_vless_relay_throw(2);
#endif
                auto second=stream_relay::direction<RelayHooks>(session,vision ?
                    stream_relay::download<RelayHooks>(session,*vision_incoming) : stream_relay::download<RelayHooks>(session,*incoming));
                (void)co_await nex::capy::when_all(std::move(first),std::move(second));
            } catch (...) {
                session.close();
            }
            fail();
        }
    }
    auto make_vless_inbound_factory(std::string_view certificate,std::string_view key,std::span<std::string const> users, bool vision, std::optional<RealityInbound> reality_config,std::span<std::string const> names,std::optional<HttpUpgradeTransport> transport,std::optional<GrpcTransport> grpc)
        -> std::expected<InboundFactory,std::string> {
        if (grpc) {
            if (transport || vision || reality_config) return std::unexpected("gRPC requires ordinary VLESS TLS and one transport");
#ifdef NEXUS_ENABLE_GRPC_VLESS
            return make_vless_grpc_inbound_factory(certificate,key,users,names,std::move(*grpc));
#else
            return std::unexpected("gRPC VLESS transport is not available in this build");
#endif
        }
        if (transport && (vision || reality_config)) return std::unexpected("HTTPUpgrade requires ordinary VLESS TLS");
        if (!names.empty() && names.size()!=users.size()) return std::unexpected("VLESS user names do not match UUIDs");
        for (std::size_t i=0;i<names.size();++i) {
            if (names[i].empty() || names[i].size()>255 || names[i].find('\0')!=std::string::npos ||
                std::find(names.begin(),names.begin()+i,names[i])!=names.begin()+i)
                return std::unexpected("invalid or duplicate VLESS user name");
        }
        auto profile=reality_config ? vless::ServerProfile::load_users(users) : vless::ServerProfile::load(certificate,key,users);
        if (!profile) return std::unexpected(profile.error());
        auto shared=std::make_unique<OwnedProfile>(std::move(*profile));
        if (transport) {
            std::vector<httpupgrade::Field> headers;
            headers.reserve(transport->headers.size());
            for (auto const& field:transport->headers) headers.push_back({field.name,field.value});
            auto compiled=httpupgrade::Profile::server(transport->host,transport->path,headers,transport->websocket);
            if (!compiled) return std::unexpected("invalid HTTPUpgrade server profile");
            shared->transport.emplace(std::move(*compiled));
        }
        shared->names.assign(names.begin(),names.end());
        if (reality_config) {
            auto authenticated=RealityTcpProfile::load(std::move(*reality_config));
            if (!authenticated) return std::unexpected(authenticated.error());
            shared->reality.emplace(std::move(*authenticated));
        }
        return InboundFactory([shared=std::move(shared),vision](Session& session,nex::corosio::io_context& context,rules::RouteMatcher const& policy) {
            return serve(session,context,policy,*shared,vision);
        });
    }
}
