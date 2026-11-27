export module relay.hysteria2_business;
import std;
import config;
import relay;
import relay.hysteria2_masquerade;
import relay.session_quota;
import relay.principal_limits;
import relay.dns_state;
import relay.stream_relay;
import hysteria2.credential;
import hysteria2.listener;
import hysteria2.auth;
import hysteria2.wire;
import http.connect;
import net.udp_socket;
import net.stream_datagrams;
import net.datagram_frame;
import hysteria2.udp_receiver;
import hysteria2.udp_transmitter;
import ngtcp2;
import quic.cid_registry;
import rules;
import socks5;
import capy;
import corosio;

export namespace relay {
    // The caller owns credentials and server until Listener and all its
    // business tasks have drained. UDP is deliberately not advertised by the
    // host until a datagram routing owner is installed.
    struct Hysteria2Business {
        using ConnectionState=SessionQuota::Lease;
        Server& server;
        std::span<hysteria2::Password const> passwords;
        hysteria2::PasswordIndex password_index;
        std::span<std::string const> names;
        config::Hysteria2Masquerade masquerade;
        auto has_masquerade() const noexcept -> bool { return !masquerade.type.empty(); }
        auto admit(quic::SessionHandle,corosio::endpoint const&) noexcept -> std::optional<ConnectionState> {
            return server.acquire_session();
        }
        auto authenticate(hysteria2::ClientAuthView request) noexcept -> std::optional<std::size_t> {
            return password_index.authenticate(passwords,request.credential);
        }
        struct UdpOwner;
        std::array<std::unique_ptr<UdpOwner>,16> udp;
        struct PeerState {quic::SessionHandle owner;ConnectionState* connection=nullptr;net::UdpEndpoint source;std::size_t user=0;bool authenticated=false;std::optional<SessionQuota::Lease> principal;};
        std::array<PeerState,16> peers;
        using Listener=hysteria2::Listener<Hysteria2Business,16,16,16384>;
        Listener* listener=nullptr;
        auto maintain_udp() noexcept -> void;
        auto udp_failure() const noexcept -> bool;
        bool udp_enabled=false,udp_failed=false;int udp_error=0;std::error_code udp_system;std::exception_ptr udp_exception;
        auto opened(quic::SessionHandle,corosio::endpoint const&,ConnectionState&) -> void;
        auto admit_authenticated(quic::SessionHandle,std::size_t) noexcept -> bool;
        auto authenticated(quic::SessionHandle,std::size_t) noexcept -> void;
        auto datagram(quic::SessionHandle,std::span<std::uint8_t const>) noexcept -> int;
        auto datagram_output(quic::SessionHandle) noexcept -> std::optional<hysteria2::UdpWriteView>;
        auto datagram_accepted(quic::SessionHandle) noexcept -> void;
        auto datagram_rejected(quic::SessionHandle) noexcept -> void;
        auto stopping(quic::SessionHandle) noexcept -> void;
        auto drained(quic::SessionHandle) const noexcept -> bool;
        auto closed(quic::SessionHandle,std::optional<int>) noexcept -> void;
        Hysteria2Business(Server&,std::span<hysteria2::Password const>,std::span<std::string const>,config::Hysteria2Masquerade={});
        Hysteria2Business(Hysteria2Business const&)=delete;
        ~Hysteria2Business();
        template<class MasqRequest>
        auto serve_masquerade(MasqRequest& request) -> capy::task<> {
            auto parsed=hysteria2_masquerade::parse_request(request.headers());
            auto resp=co_await hysteria2_masquerade::serve(server.executor_context(),masquerade,parsed,request.stop_token());
            (void)request.respond(resp.status,resp.headers,std::move(resp.body),resp.omit_body);
        }
        template<class Request>
        auto serve(Request& request) -> capy::task<> {
            auto user=request.user();
            if(!user || *user>=passwords.size() || (!names.empty() && *user>=names.size())) {
                (void)request.respond(hysteria2::TcpStatus::error,"authentication");co_return;
            }
            auto lease=request.connection().try_acquire();
            if(!lease) {(void)request.respond(hysteria2::TcpStatus::error,"capacity");co_return;}
            auto parsed=http::parse_destination_authority(request.address());
            if(parsed.status!=http::ConnectStatus::accepted) {(void)request.respond(hysteria2::TcpStatus::error,"destination");co_return;}
            socks5::Request target;target.status=socks5::Status::accepted;target.port=parsed.port;
            if(parsed.kind==http::HostKind::domain) {
                if(parsed.host.size()>target.address.size()) {(void)request.respond(hysteria2::TcpStatus::error,"destination");co_return;}
                target.address_type=3;target.address_length=parsed.host.size();
                std::ranges::copy(parsed.host,target.address.begin());
            } else {
                target.address_type=parsed.kind==http::HostKind::ipv4 ? 1 : 4;
                target.address_length=target.address_type==1 ? 4 : 16;
                std::copy_n(parsed.address.begin(),target.address_length,target.address.begin());
            }
            auto& context=server.executor_context();Session session(context);
            server.attach_session(session,std::move(*lease));
            auto const& policy=session.route_snapshot ? session.route_snapshot->matcher : server.routing_policy();
            if (!names.empty() && !session.admit_principal(names[*user],PrincipalResource::stream)) {
                (void)request.respond(hysteria2::TcpStatus::error,"capacity");
                session.close(); co_return;
            }
            net::UdpEndpoint source;auto address=request.peer().address();source.port=request.peer().port();
            if(address.is_v4()) {source.family=4;auto bytes=address.to_v4().to_bytes();std::ranges::copy(bytes,source.address.begin());}
            else {source.family=6;auto bytes=address.to_v6().to_bytes();std::ranges::copy(bytes,source.address.begin());}
            session.datagram_source=source;
            session.begin_traffic(TrafficProtocol::hysteria2,target.port);
            std::stop_callback cancel_channel(session.stop.get_token(),[&]() noexcept {request.channel.cancel();});
            std::stop_callback canceled(request.stop_token(),[&]() noexcept {session.close();});
            auto code=co_await dial_destination(session,context,policy,target,source,session.handshake_deadline);
            if(code || session.closed) {(void)request.respond(hysteria2::TcpStatus::error,"dial");session.close();co_return;}
            if(!request.respond(hysteria2::TcpStatus::success)) {session.close();co_return;}
            session.relaying=true;session.touched=std::chrono::steady_clock::now();
            try {
                (void)co_await capy::when_all(stream_relay::direction(session,stream_relay::upload(session,request.channel)),
                    stream_relay::direction(session,stream_relay::download(session,request.channel)));
            } catch (...) {session.close();throw;}
            session.close();
        }
    };
}
