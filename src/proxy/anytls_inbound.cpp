module proxy;
import std;
import anytls;
import anytls.auth;
import anytls.padding;
import anytls.session;
import anytls.writer;
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
import tls.profiles;
import tls.server_credential;
import tls.byte_stream;
import tls.corosio_application;
import tls.corosio_server_handshake;
import proxy.stream_relay;
import proxy.dns_state;
import sniff.tcp;
import sniff.tcp_io;
import net.stream_datagrams;
import platform.stream_peer;
import rules;
import socks5;
import uot;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

#include "transport_helpers.hpp"

namespace proxy {
    namespace {
        using Application=tls::detail::ApplicationConnection<nex::corosio::tcp_socket>;
        using TlsStream=websocket::VlessByteStream<nex::corosio::tcp_socket>;
        struct Profile {
            tls::ServerCredential credential;
            std::vector<anytls::PasswordKey> users;
            std::vector<std::string> names;
            std::optional<httpupgrade::Profile> transport;
            std::optional<transport_detail::GrpcSettings> grpc;
        };
        struct ParentGuard {
            Session& session;
            ~ParentGuard() { session.done=true; session.close(); }
        };
        template<class LowerStream>
        struct Incoming {
            using Protocol=anytls::Session<LowerStream>;
            Protocol& protocol;
            Session& parent;
            anytls::StreamChannel<LowerStream> channel;
            Incoming(Protocol& owner,Session& connection,std::uint32_t id) : protocol(owner),parent(connection),channel(owner,id) {}
            auto read(std::span<std::uint8_t> bytes,anytls::Deadline deadline={}) {
                parent.touched=Clock::now();
                return channel.read(bytes,deadline ? deadline : Clock::now()+std::chrono::seconds(300));
            }
            auto send(std::span<std::uint8_t const> bytes,anytls::Deadline deadline={}) {
                parent.touched=Clock::now();
                return channel.send(bytes,deadline ? deadline : Clock::now()+std::chrono::seconds(300));
            }
            auto close_output(anytls::Deadline deadline={}) { return channel.close_output(deadline); }
            auto cancel() noexcept -> void { channel.cancel(); }
            auto peer_closed() const noexcept -> bool {
                return parent.closed || protocol.stream_closed(channel.id()) || platform::stream_peer_closed(parent.client.native_handle());
            }
        };
        template<class Protocol>
        struct ChildGuard {
            Session& session;
            Protocol& protocol;
            std::uint32_t id;
            ~ChildGuard() {
                auto* owner=&protocol; auto stream=id;
                session.close(); owner->cancel_stream(stream);
            }
        };
        template<class In>
        auto exact(In& incoming,std::span<std::uint8_t> output,Clock::time_point deadline) -> nex::capy::task<bool> {
            while (!output.empty()) {
                auto received=co_await incoming.read(output,deadline);
                if (!received || !*received || *received>output.size()) co_return false;
                output=output.subspan(*received);
            }
            co_return true;
        }
        template<class In>
        auto destination(In& incoming,Clock::time_point deadline) -> nex::capy::task<std::optional<net::ProxyAddress>> {
            std::array<std::uint8_t,259> bytes{};
            if (!co_await exact(incoming,std::span(bytes).first(1),deadline)) co_return std::nullopt;
            std::size_t prefix=1,remaining=0;
            if (bytes[0]==1) remaining=6;
            else if (bytes[0]==4) remaining=18;
            else if (bytes[0]==3) {
                if (!co_await exact(incoming,std::span(bytes).subspan(1,1),deadline) || !bytes[1]) co_return std::nullopt;
                prefix=2; remaining=std::size_t(bytes[1])+2;
            } else co_return std::nullopt;
            if (!co_await exact(incoming,std::span(bytes).subspan(prefix,remaining),deadline)) co_return std::nullopt;
            auto parsed=net::parse_proxy_address(std::span(bytes).first(prefix+remaining),net::AddressWire::socks);
            co_return parsed.status==net::DatagramStatus::accepted ? std::optional(parsed.address) : std::nullopt;
        }
        template<class Protocol>
        auto watch_stream(Session& child,Protocol& protocol,std::uint32_t id) -> nex::capy::task<nex::capy::results<>> {
            if (co_await protocol.wait_stream_closed(id)) child.close();
            co_return nex::capy::results<>{};
        }
        template<class In>
        auto sniff_stream(void* stream,sniff::TcpSniffer& sniffer,Clock::time_point deadline)
            -> nex::capy::task<sniff::TcpReadResult> {
            auto& incoming=*static_cast<In*>(stream);
            std::array<std::uint8_t,4096> bytes{};
            for (;;) {
                auto state=sniffer.limit();
                if (state.status!=sniff::TcpStatus::need_more) co_return {sniff::TcpReadStop::classified,state,{}};
                if (Clock::now()>=deadline) co_return {sniff::TcpReadStop::deadline,state,{}};
                auto count=co_await incoming.read(std::span(bytes).first(std::min(bytes.size(),sniffer.remaining())),deadline);
                if (!count) {
                    if (count.error()==anytls::SessionError::timeout) co_return {sniff::TcpReadStop::deadline,sniffer.current(),{}};
                    co_return {sniff::TcpReadStop::io_error,sniffer.current(),std::make_error_code(std::errc::io_error)};
                }
                if (!*count) co_return {sniff::TcpReadStop::eof,sniffer.finish(),{}};
                auto step=sniffer.feed(std::span(bytes).first(*count));
                if (step.consumed!=*count)
                    co_return {sniff::TcpReadStop::io_error,step,std::make_error_code(std::errc::protocol_error)};
            }
        }
        template<class In>
        auto dial_stream(Session& child,nex::corosio::io_context& context,rules::RouteMatcher const& policy,
            socks5::Request const& target,In& incoming) -> nex::capy::task<nex::capy::results<std::uint8_t>> {
            std::uint8_t code=1;
            if (child.ordered_tcp) {
                auto connected=co_await route_ordered_stream_tcp(child,context,target,&incoming,&sniff_stream<In>);
                if (connected) code=0;
            } else code=co_await dial_destination(child,context,policy,target);
            co_return nex::capy::results<std::uint8_t>{std::make_error_code(std::errc::operation_canceled),code};
        }
        template<class In>
        auto datagrams(Session& child,nex::corosio::io_context& context,rules::RouteMatcher const& policy,In& incoming,
            Clock::time_point deadline) -> nex::capy::task<> {
            if (child.ordered_tcp && !child.ordered_tcp->udp) {
                (void)co_await incoming.protocol.acknowledge(incoming.channel.id(),false,deadline);
                co_return;
            }
            uot::RequestDecoder request;
            std::array<std::uint8_t,4096> bytes{};
            std::size_t begin=0,end=0;
            while (!child.closed && !request.request()) {
                auto received=co_await incoming.read(bytes,deadline);
                if (!received || !*received || *received>bytes.size()) co_return;
                auto fed=request.feed(std::span(bytes).first(*received));
                if (fed.status!=uot::Status::incomplete && fed.status!=uot::Status::accepted) co_return;
                if (request.request()) { begin=fed.consumed; end=*received; }
            }
            if (child.closed || !request.request() ||
                !co_await incoming.protocol.acknowledge(incoming.channel.id(),true,deadline)) co_return;
            auto config=*request.request();
            child.begin_traffic(TrafficProtocol::anytls_uot,config.connected ? config.destination.port : 0);
            child.select_traffic_path(ConnectPath::datagrams);
            child.relaying=true; child.touched=Clock::now();
            auto resolver=[&](std::string name,std::uint16_t port,Clock::time_point limit) {
                return resolve_udp_domain(child,context,std::move(name),port,limit);
            };
            auto source=source_endpoint(child,child.ordered_tcp || policy.needs_source() || child.dns_requirements().source);
            auto router=child.ordered_tcp ? ordered_datagram_router(child,context,source) : net::stream_datagrams::OrderedRouter{};
            net::stream_datagrams::Server state(child,context,incoming,policy,resolver,
                {net::AddressWire::uot,config.connected,false},config.destination,source,std::move(router));
            try { (void)co_await nex::capy::when_all(net::stream_datagrams::tasks(state,std::span(bytes).subspan(begin,end-begin))); }
            catch (...) { child.close(); state.cancel(); throw; }
        }
        template<class LowerStream>
        auto serve_stream(Session& parent,nex::corosio::io_context& context,rules::RouteMatcher const& policy,anytls::Session<LowerStream>& protocol,
            std::uint32_t id) -> nex::capy::task<> {
            auto lease=parent.quota ? parent.quota->try_acquire() : std::nullopt;
            if (parent.quota && !lease) {
                (void)co_await protocol.acknowledge(id,false,Clock::now()+std::chrono::seconds(5));
                protocol.release(id); co_return;
            }
            Session child(context);
            child.quota=std::move(lease);
            child.transport_owner=&parent;
            child.register_child_traffic();
            child.route_snapshot=parent.route_snapshot;
            child.ordered_tcp=parent.ordered_tcp;
            child.inbound=parent.inbound;
            if (!child.admit_principal_child(parent)) {
                (void)co_await protocol.acknowledge(id,false,Clock::now()+std::chrono::seconds(5));
                protocol.release(id); co_return;
            }
            child.dns=parent.dns; child.local_dns=parent.local_dns;
            child.tunnel_factories=parent.tunnel_factories;
            child.direct_connect_timeout_ms=parent.direct_connect_timeout_ms;
            child.direct_tcp_options=parent.direct_tcp_options;
            child.started=child.touched=Clock::now();
            child.handshake_deadline=child.started+std::chrono::seconds(10);
            Incoming<LowerStream> incoming(protocol,parent,id);
            ChildGuard<anytls::Session<LowerStream>> guard{child,protocol,id};
            std::stop_callback cancel_channel(child.stop.get_token(),[&]() noexcept {incoming.cancel();});
            std::stop_callback stop(parent.stop.get_token(),[&]() noexcept {child.close();});
            if (child.closed) co_return;
            auto address=co_await destination(incoming,child.handshake_deadline);
            if (!address || child.closed) co_return;
            auto host=std::string_view(reinterpret_cast<char const*>(address->bytes.data()),address->length);
            if (address->family==net::ProxyAddressFamily::domain && host==uot::v2_destination) {
                co_await datagrams(child,context,policy,incoming,child.handshake_deadline); co_return;
            }
            socks5::Request target; target.status=socks5::Status::accepted;
            target.address_type=address->family==net::ProxyAddressFamily::ipv4 ? 1 : address->family==net::ProxyAddressFamily::ipv6 ? 4 : 3;
            target.address_length=address->length; target.port=address->port;
            std::copy_n(address->bytes.begin(),address->length,target.address.begin());
            child.begin_traffic(TrafficProtocol::anytls,target.port);
            auto [signal,code,watched]=co_await nex::capy::when_all(dial_stream(child,context,policy,target,incoming),watch_stream(child,protocol,id));
            (void)signal; (void)watched;
            if (child.closed) co_return;
            if (!co_await protocol.acknowledge(id,!code,child.handshake_deadline) || code) co_return;
            child.relaying=true; child.touched=Clock::now();
            (void)co_await nex::capy::when_all(stream_relay::direction(child,stream_relay::upload(child,incoming)),
                stream_relay::direction(child,stream_relay::download(child,incoming)));
        }
        template<class LowerStream>
        auto worker(Session& parent,nex::corosio::io_context& context,rules::RouteMatcher const& policy,anytls::Session<LowerStream>& protocol)
            -> nex::capy::task<nex::capy::results<>> {
            while (!parent.closed) {
                auto accepted=co_await protocol.accept();
                if (!accepted) break;
                co_await serve_stream(parent,context,policy,protocol,*accepted);
            }
            co_return nex::capy::results<>{};
        }
        template<class LowerStream>
        auto run_protocol(Session& parent,anytls::Session<LowerStream>& protocol,bool close_parent) -> nex::capy::task<nex::capy::results<>> {
            struct Guard { Session& p; bool active; ~Guard() { if (active) { p.done=true; p.close(); } } } g{parent,close_parent};
            co_return co_await protocol.run();
        }
        template<class LowerStream>
        auto serve_anytls_lower(Session& parent,nex::corosio::io_context& context,rules::RouteMatcher const& policy,
            Profile const& profile,LowerStream& lower,Clock::time_point deadline,bool close_parent,unsigned workers_n) -> nex::capy::task<> {
            auto padding=anytls::PaddingScheme::parse(anytls::default_padding_scheme);
            if (!padding) co_return;
            anytls::Session<LowerStream> protocol(lower,*padding,false);
            auto accepted=co_await protocol.start_server(profile.users,deadline);
            if (!accepted || parent.closed || *accepted>=profile.users.size()) co_return;
            if (!profile.names.empty() && !parent.admit_principal(profile.names[*accepted])) co_return;
            parent.relaying=true; parent.touched=Clock::now();
            std::vector<nex::capy::task<nex::capy::results<>>> tasks;
            tasks.reserve(workers_n+1); tasks.push_back(run_protocol(parent,protocol,close_parent));
            for (unsigned i=0;i<workers_n;++i) tasks.push_back(worker(parent,context,policy,protocol));
            (void)co_await nex::capy::when_all(std::move(tasks));
        }
        auto serve(Session& parent,nex::corosio::io_context& context,rules::RouteMatcher const& policy,Profile const& profile) -> nex::capy::task<> {
            ParentGuard guard{parent};
            auto deadline=parent.started+std::chrono::seconds(10);
            auto milliseconds=[](auto value) { return std::chrono::duration_cast<std::chrono::milliseconds>(value.time_since_epoch()).count(); };
            auto start=milliseconds(parent.started),end=milliseconds(deadline);
            if (start<0 || end<=start) co_return;
            auto budget=std::make_shared<memory::Budget>(8u*1024*1024);
            std::string_view req_alpn = profile.grpc ? "h2" : profile.transport ? "http/1.1" : "";
            auto handshake=tls::make_server_handshake(profile.credential,start,end,budget,req_alpn);
            if (!handshake) co_return;
            auto established=co_await tls::detail::server_handshake(parent.client,*handshake,budget);
            if (!established || parent.closed) co_return;
            Application application(parent.client,std::move(established->records),std::move(established->unread));
            if (!established->release_unread_reservation()) co_return;
            if (profile.grpc) {
                using Lower=tls::detail::ByteStream<nex::corosio::tcp_socket>;
                using Channel=grpc::MultiplexChannel<Lower,16,grpc::detail::ByteStreamReadPolicy>;
                Lower lower(application);
                auto proto=grpc::MultiplexSession<16>::create(grpc::Role::server,profile.grpc->request,grpc::ResponsePolicy::standard,profile.grpc->limits);
                if (!proto) co_return;
                Channel channel(lower,std::move(*proto));
                parent.relaying=true; parent.touched=Clock::now();
                auto run_ch=[&]() -> nex::capy::task<nex::capy::results<>> { co_return co_await channel.run(); };
                auto rpc_worker=[&]() -> nex::capy::task<nex::capy::results<>> {
                    while (!parent.closed) {
                        if (auto ticket=channel.accept()) {
                            typename Channel::Stream rpc(channel,*ticket);
                            transport_detail::GrpcByteStream<typename Channel::Stream> adapted{rpc,&parent};
                            try { co_await serve_anytls_lower(parent,context,policy,profile,adapted,Clock::now()+std::chrono::seconds(10),false,8); } catch (...) {}
                            rpc.cancel();
                            continue;
                        }
                        if (!co_await channel.wait_change()) break;
                    }
                    co_return nex::capy::results<>{};
                };
                std::vector<nex::capy::task<nex::capy::results<>>> tasks;
                tasks.reserve(17); tasks.push_back(run_ch());
                for (unsigned i=0;i<16;++i) tasks.push_back(rpc_worker());
                try { (void)co_await nex::capy::when_all(std::move(tasks)); } catch (...) { channel.cancel(); }
                co_return;
            }
            TlsStream lower(application);
            if (profile.transport) {
                if (!co_await transport_detail::handshake_ws_or_hu(lower,*profile.transport,deadline) || parent.closed) co_return;
            }
            co_await serve_anytls_lower(parent,context,policy,profile,lower,deadline,true,64);
        }
    }
    auto make_anytls_inbound_factory(std::string_view certificate,std::string_view key,std::span<std::string const> passwords,
        std::span<std::string const> names,std::optional<HttpUpgradeTransport> transport,std::optional<GrpcTransport> grpc_cfg) -> std::expected<InboundFactory,std::string> {
        if (passwords.empty() || passwords.size()>64 || (!names.empty() && names.size()!=passwords.size())) return std::unexpected("invalid AnyTLS users");
        if (transport && grpc_cfg) return std::unexpected("AnyTLS inbound accepts at most one transport");
        for (std::size_t i=0;i<names.size();++i)
            if (names[i].empty() || names[i].size()>255 || names[i].find('\0')!=std::string::npos || std::ranges::contains(names.first(i),names[i]))
                return std::unexpected("invalid or duplicate AnyTLS user name");
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
            auto password=anytls::PasswordKey::load(path);
            if (!password) return std::unexpected(password.error());
            if (anytls::authenticate(profile->users,password->view())) return std::unexpected("duplicate AnyTLS password");
            profile->users.push_back(std::move(*password));
        }
        profile->names.assign(names.begin(),names.end());
        return InboundFactory{[profile=std::move(profile)](Session& session,nex::corosio::io_context& context,rules::RouteMatcher const& policy) {
            return serve(session,context,policy,*profile);
        }};
    }
}
