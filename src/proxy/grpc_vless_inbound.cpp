module proxy;
import std;
import proxy.v4;
import rules;
import socks5;
import memory.budget;
import grpc.headers;
import grpc.session;
import grpc.stream;
import grpc.multiplex;
import grpc.multiplex_channel;
import grpc.connection;
import tls.corosio_server_handshake;
import tls.corosio_application;
import tls.byte_stream;
import vless;
import vless.server_profile;
import vless.tls_server;
import proxy.stream_relay;
import proxy.vless_mux;
import xudp.server_io;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace proxy {
    namespace grpc_vless_inbound {
        namespace g=grpc;
        using Lower=tls::detail::ByteStream<nex::corosio::tcp_socket>;
        using ReadPolicy=g::detail::ByteStreamReadPolicy;
        using Channel=g::MultiplexChannel<Lower,16,ReadPolicy>;
        struct RpcTransport {
            Channel::Stream rpc;Session& parent;
            RpcTransport(Channel& channel,Session& owner,g::RpcTicket ticket) :rpc(channel,ticket),parent(owner){}
            auto read(std::span<std::uint8_t> bytes,g::Deadline deadline={}) {parent.touched=Clock::now();return rpc.read(bytes,deadline?deadline:Clock::now()+std::chrono::seconds(300));}
            auto send(std::span<std::uint8_t const> bytes,g::Deadline deadline={}) {parent.touched=Clock::now();return rpc.send(bytes,deadline?deadline:Clock::now()+std::chrono::seconds(300));}
            auto close_output(g::Deadline deadline={}) {return rpc.close_output(deadline?deadline:Clock::now()+std::chrono::seconds(300));}
            auto cancel() noexcept -> void {rpc.cancel();}
        };
        using Incoming=vless::detail::TlsInbound<nex::corosio::tcp_socket,false,RpcTransport&>;
        struct Profile {vless::ServerProfile vless;g::RequestProfile grpc;g::Limits limits;std::vector<std::string> names;};
        struct MuxStream {
            Session& session;Incoming& incoming;
            template<class Operation> struct ReadResult {
                Session& session;Operation operation;
                auto await_ready() const noexcept {return operation.await_ready();}
                template<class Context> auto await_suspend(std::coroutine_handle<> continuation,Context const* context) {
                    return operation.await_suspend(continuation,context);
                }
                auto await_resume() {
                    auto result=operation.await_resume();if (result && *result) session.touched=Clock::now();return result;
                }
            };
            auto read(std::span<std::uint8_t> bytes) {
                auto operation=incoming.read(bytes);return ReadResult<decltype(operation)>{session,std::move(operation)};
            }
            auto write(std::span<std::uint8_t const> bytes) {session.touched=Clock::now();return incoming.send(bytes);}
            auto cancel() noexcept -> void {session.close();}
        };
        struct MuxLookup {
            auto operator()(Session& session,nex::corosio::io_context& context,std::string name,std::uint16_t port,Clock::time_point deadline) const {
                return resolve_udp_domain(session,context,std::move(name),port,deadline);
            }
        };
        using MuxResolver=vless_mux::Resolver<Session,MuxLookup>;
        using MuxServer=vless_mux::Server<MuxStream,MuxResolver>;
        auto failure() -> nex::capy::results<> {return {std::make_error_code(std::errc::io_error)};}
        auto watch_rpc(Session& session,Channel& channel,RpcTransport& transport,Clock::time_point deadline)
            -> nex::capy::task<nex::capy::results<>> {
            while(!session.closed){
                if(transport.rpc.failure()){session.close();break;}
                if(!co_await channel.wait_change(deadline)){
                    // A successful dial cancels only this observer. That
                    // private join signal is not a peer reset or deadline.
                    if(transport.rpc.failure()||channel.failure()||channel.finished()||Clock::now()>=deadline)session.close();
                    break;
                }
            }
            co_return nex::capy::results<>{};
        }
        auto dial_rpc(Session& session,nex::corosio::io_context& context,rules::RouteMatcher const& policy,
            socks5::Request const& request,Clock::time_point deadline) -> nex::capy::task<nex::capy::results<std::uint8_t>> {
            auto code=co_await dial_destination(session,context,policy,request,deadline);
            co_return nex::capy::results<std::uint8_t>{std::make_error_code(std::errc::operation_canceled),code};
        }
        auto payload(Session& session,nex::corosio::io_context& context,rules::RouteMatcher const& policy,
            Profile const& profile,Channel& owner,RpcTransport& channel,Clock::time_point limit) -> nex::capy::task<nex::capy::results<>> {
            struct Guard {Session& session;RpcTransport& channel;bool done=false;~Guard() {if (!done) {channel.cancel();session.close();}}} guard{session,channel};
            if (Clock::now()>=limit || session.closed) co_return failure();
            auto handshake=profile.vless.vless_handshake();if (!handshake) co_return failure();
            Incoming incoming(channel,std::move(*handshake));if (!incoming.allow_mux()) co_return failure();
            auto header=co_await incoming.read_header(limit);if (!header || session.closed) co_return failure();
            if (!profile.names.empty()) {
                auto const& identity=std::holds_alternative<vless::UserId>(*header) ? std::get<vless::UserId>(*header) : std::get<vless::TcpRequest>(*header).user;
                auto index=profile.vless.user_index(identity);
                if (!index || *index>=profile.names.size() || !session.admit_principal(profile.names[*index])) co_return failure();
            }
            if (std::holds_alternative<vless::UserId>(*header)) {
                if (!co_await incoming.complete_dial(true,limit) || session.closed) co_return failure();
                session.relaying=true;session.touched=Clock::now();
                MuxStream stream{session,incoming};MuxResolver resolver{session,context};auto source=source_endpoint(session,policy);
                MuxServer mux(stream,resolver,policy,256,65535,source ? &*source : nullptr,session.auth_user,
                    session.direct_tcp_options ? &session.direct_tcp_options->binding : nullptr,vless_mux::FlowAccounting(session));
                (void)co_await nex::capy::when_all(vless_mux::read(session,mux),vless_mux::poll(session,mux),vless_mux::timeout(session,mux,resolver));
                co_return failure();
            }
            auto const& request=std::get<vless::TcpRequest>(*header);socks5::Request target;
            target.status=socks5::Status::accepted;target.port=request.port;
            target.address_type=request.kind==vless::AddressKind::ipv4 ? 1 : request.kind==vless::AddressKind::ipv6 ? 4 : 3;
            target.address_length=static_cast<std::uint8_t>(request.address.size());std::ranges::copy(request.address,target.address.begin());
            session.begin_traffic(TrafficProtocol::grpc_vless,target.port);
            auto [signal,dialed,watched]=co_await nex::capy::when_all(dial_rpc(session,context,policy,target,limit),watch_rpc(session,owner,channel,limit));
            (void)signal;(void)watched;
            if (dialed || session.closed || !co_await incoming.complete_dial(true,limit)) co_return failure();
            session.relaying=true;session.touched=Clock::now();
            auto [error,upload,download]=co_await nex::capy::when_all(
                stream_relay::direction(session,stream_relay::upload(session,incoming)),
                stream_relay::direction(session,stream_relay::download(session,incoming)));
            (void)upload;(void)download;if (error || session.closed) co_return failure();
            guard.done=true;co_return nex::capy::results<>{};
        }
        struct Slots {bool primary=true;};
        auto serve_rpc(Session& parent,nex::corosio::io_context& context,rules::RouteMatcher const& policy,
            Profile const& profile,Channel& channel,g::RpcTicket ticket,Slots& slots) -> nex::capy::task<> {
            RpcTransport transport(channel,parent,ticket);
            try{
            struct Primary {Slots& slots;bool borrowed=false;~Primary(){if(borrowed)slots.primary=true;}} primary{slots};
            std::optional<SessionQuota::Lease> lease;
            if(parent.quota){
                if(slots.primary){slots.primary=false;primary.borrowed=true;}
                else{lease=parent.quota->try_acquire();if(!lease)co_return;}
            }
            Session child(context);child.quota=std::move(lease);child.transport_owner=&parent;
            child.register_child_traffic();
            child.route_snapshot=parent.route_snapshot;
            child.principal_policy=parent.principal_policy;
            child.inbound=parent.inbound;child.dns=parent.dns;child.local_dns=parent.local_dns;
            child.tunnel_factories=parent.tunnel_factories;child.direct_connect_timeout_ms=parent.direct_connect_timeout_ms;
            child.direct_tcp_options=parent.direct_tcp_options;
            child.started=child.touched=Clock::now();child.handshake_deadline=child.started+std::chrono::seconds(10);
            struct Close {Session& child;~Close(){child.close();}} close{child};
            std::stop_callback cancel_channel(child.stop.get_token(),[&]() noexcept {transport.cancel();});
            std::stop_callback stop(parent.stop.get_token(),[&]() noexcept {child.close();});
            (void)co_await payload(child,context,policy,profile,channel,transport,child.handshake_deadline);
            }catch(std::bad_alloc const&){transport.rpc.cancel({g::Error::allocation});}
            catch(...){
                // A failed business relay can throw its quitter cancellation
                // sentinel while draining its sibling. Its failure belongs to
                // this RPC; it must not stop the shared connection workers.
                transport.rpc.cancel({g::Error::canceled});
            }
        }
        auto worker(Session& parent,nex::corosio::io_context& context,rules::RouteMatcher const& policy,
            Profile const& profile,Channel& channel,Slots& slots) -> nex::capy::task<nex::capy::results<>> {
            while(!parent.closed){
                if(auto accepted=channel.accept()){co_await serve_rpc(parent,context,policy,profile,channel,*accepted,slots);continue;}
                if(!co_await channel.wait_change())break;
            }
            co_return nex::capy::results<>{};
        }
        auto run_protocol(Session& parent,Channel& channel) -> nex::capy::task<nex::capy::results<>> {
            struct Close {Session& parent;bool normal=false;~Close(){if(!normal)parent.close();}} close{parent};
            auto result=co_await channel.run();close.normal=channel.finished()&&!channel.failure();
            co_return result;
        }
        auto serve(Session& session,nex::corosio::io_context& context,rules::RouteMatcher const& policy,Profile const& profile) -> nex::capy::task<> {
            struct Close {Session& session;~Close() {session.close();session.done=true;}} close{session};
            if(session.ordered_tcp)co_return;
            auto limit=session.started+std::chrono::seconds(10);
            auto ms=[](Clock::time_point value) {return std::chrono::duration_cast<std::chrono::milliseconds>(value.time_since_epoch()).count();};
            auto start=ms(session.started),end=ms(limit);if (start<0 || end<=start) co_return;
            auto budget=std::make_shared<memory::Budget>(8u*1024*1024);
            auto handshake=profile.vless.tls_handshake(start,end,budget,"h2");if (!handshake) co_return;
            auto established=co_await tls::detail::server_handshake(session.client,*handshake,budget);if (!established || session.closed) co_return;
            tls::detail::ApplicationConnection connection(session.client,std::move(established->records),std::move(established->unread));
            if (!established->release_unread_reservation()) co_return;
            Lower lower(connection);auto protocol=g::MultiplexSession<16>::create(g::Role::server,profile.grpc,g::ResponsePolicy::standard,profile.limits);if (!protocol) co_return;
            Channel channel(lower,std::move(*protocol));
            Slots slots;session.relaying=true;session.touched=Clock::now();
            try {
                std::vector<nex::capy::task<nex::capy::results<>>> tasks;tasks.reserve(17);tasks.push_back(run_protocol(session,channel));
                for(unsigned i=0;i<16;++i)tasks.push_back(worker(session,context,policy,profile,channel,slots));
                (void)co_await nex::capy::when_all(std::move(tasks));
            } catch (...) {channel.cancel();session.close();}
        }
    }
    auto make_vless_grpc_inbound_factory(std::string_view certificate,std::string_view key,std::span<std::string const> users,
        std::span<std::string const> names,GrpcTransport transport) -> std::expected<InboundFactory,std::string> {
        namespace v=grpc_vless_inbound;
        if (!names.empty() && names.size()!=users.size()) return std::unexpected("VLESS user names do not match UUIDs");
        for (std::size_t i=0;i<names.size();++i) if (names[i].empty() || names[i].size()>255 || names[i].contains('\0') ||
            std::find(names.begin(),names.begin()+i,names[i])!=names.begin()+i) return std::unexpected("invalid or duplicate VLESS user name");
        if (transport.response_policy!=GrpcTransport::ResponsePolicy::standard || transport.authority.empty()) return std::unexpected("invalid gRPC inbound policy/authority");
        auto profile=vless::ServerProfile::load(certificate,key,users);auto request=grpc::RequestProfile::create(transport.service_name,transport.authority,true);
        grpc::Limits limits{transport.input_window,transport.message_bytes,transport.hunk_bytes,transport.output_bytes,transport.output_messages,transport.library_bytes};
        if (!profile || !request || !grpc::Session::create(grpc::Role::server,*request,grpc::ResponsePolicy::standard,limits)) return std::unexpected("invalid gRPC VLESS inbound profile");
        auto owned=std::make_unique<v::Profile>(std::move(*profile),std::move(*request),limits,std::vector<std::string>(names.begin(),names.end()));
        return InboundFactory{[profile=std::move(owned)](Session& session,nex::corosio::io_context& context,rules::RouteMatcher const& policy) {
            return v::serve(session,context,policy,*profile);
        }};
    }
}
