import std;
import grpc.headers;
import grpc.session;
import grpc.stream;
import nexus.thirdparty.nghttp2;
import net.socket_stream;
import net.stream_relay;
import tls.profiles;
import tls.server_credential;
import tls.byte_stream;
import tls.corosio_client;
import tls.corosio_application;
import tls.corosio_server_handshake;
import vless;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace g=grpc;
namespace v=vless;
namespace capy=nex::capy;
namespace io=nex::corosio;
using namespace std::chrono_literals;
using Lower=tls::detail::ByteStream<io::tcp_socket>;
using Channel=g::Channel<Lower>;
struct Fixture {
    io::io_context context;
    io::tcp_acceptor listener{context};
    io::tcp_socket incoming{context},target{context};
    bool done=false,success=false,application=false;
    std::string_view stage="start",expected_authority;
    std::optional<g::Failure> failure;
    std::optional<int> tls_error;
    explicit Fixture(bool uring) : context(io::make_io_context(uring)) {}
};
template<class Owner> struct CancelGuard { Owner& owner; ~CancelGuard() { owner.cancel(); } };
auto milliseconds(g::Clock::time_point point) -> std::uint64_t {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(point.time_since_epoch()).count());
}
auto h2_selected(std::span<std::uint8_t const> protocol) -> bool {
    return std::ranges::equal(protocol,std::array<std::uint8_t,2>{'h','2'});
}
auto pattern() -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> result(512*1024);
    for (std::size_t i=0;i<result.size();++i) result[i]=static_cast<std::uint8_t>(i);
    return result;
}
auto error() -> capy::results<> { return capy::results<>{std::make_error_code(std::errc::io_error)}; }
auto transfer(capy::task<bool> operation) -> capy::task<capy::results<>> {
    if (!co_await std::move(operation)) co_return error();
    co_return capy::results<>{};
}
auto lite_upload(Channel& channel,net::SocketByteStream<io::tcp_socket>& target,std::size_t remaining) -> capy::task<bool> {
    std::array<std::uint8_t,16384> bytes{};
    while (remaining) {
        auto received=co_await channel.read(std::span(bytes).first(std::min(bytes.size(),remaining)));
        if (!received || !*received || *received>remaining || !co_await target.send(std::span(bytes).first(*received))) co_return false;
        remaining-=*received;
    }
    co_return co_await target.close_output();
}
auto serve(Fixture& fixture,Channel& channel,bool lite,g::Clock::time_point deadline) -> capy::task<capy::results<>> {
    fixture.stage="gRPC request headers";
    if (!co_await channel.accept(deadline)) co_return error();
    auto user=v::parse_user_id("00010203-0405-0607-0809-0a0b0c0d0e0f"); if (!user) co_return error();
    std::array<v::UserId,1> users{*user}; auto handshake=v::ServerHandshake::create(users);
    if (!handshake) co_return error();
    std::array<std::uint8_t,4096> buffer{}; std::vector<std::uint8_t> prefetched;
    fixture.stage="VLESS request";
    for (;;) {
        auto received=co_await channel.read(buffer,deadline);
        if (!received || !*received) co_return error();
        auto input=std::span(buffer).first(*received); auto fed=handshake->feed(input);
        if (fed.status==v::ServerStatus::rejected) co_return error();
        if (fed.status==v::ServerStatus::dialing) { prefetched.assign(input.begin()+fed.consumed,input.end()); break; }
    }
    auto request=handshake->request();
    if (!request || request->kind!=v::AddressKind::ipv4 || request->address!=std::vector<std::uint8_t>{127,0,0,1}) co_return error();
    fixture.stage="target connect";
    auto [connected]=co_await io::timeout(fixture.target.connect(io::endpoint(io::ipv4_address::loopback(),request->port)),deadline);
    auto response=handshake->complete_dial(!connected);
    if (!response || !co_await channel.send(*response,deadline)) co_return error();
    net::SocketByteStream target(fixture.target);
    if (!prefetched.empty() && !co_await target.send(prefetched,deadline)) co_return error();
    fixture.stage="relay";
    auto adapter=net::ByteRelayAdapter{fixture.target,channel,[] {},false};
    if (lite) {
        if (prefetched.size()>512*1024) co_return error();
        auto [signal,upload,download]=co_await capy::when_all(
            transfer(lite_upload(channel,target,512*1024-prefetched.size())),
            transfer(net::stream_relay::upload(adapter)));
        (void)upload; (void)download;
        if (signal) co_return error();
        fixture.application=true;
    } else {
        auto [signal,upload,download]=co_await capy::when_all(
            transfer(net::stream_relay::download(adapter)),transfer(net::stream_relay::upload(adapter)));
        (void)upload; (void)download;
        if (signal) co_return error();
        fixture.application=true;
    }
    co_return capy::results<>{};
}
auto request(Fixture& fixture,Channel& channel,std::uint16_t target,g::Clock::time_point deadline) -> capy::task<capy::results<>> {
    auto user=v::parse_user_id("00010203-0405-0607-0809-0a0b0c0d0e0f"); if (!user) co_return error();
    auto header=v::encode_tcp_request({*user,v::AddressKind::ipv4,target,{127,0,0,1}}); if (!header) co_return error();
    auto payload=pattern(); header->insert(header->end(),payload.begin(),payload.end());
    fixture.stage="request/payload send and half-close";
    if (!co_await channel.send(*header,deadline) || !co_await channel.close_output(deadline)) co_return error();
    std::array<std::uint8_t,16384> bytes{}; std::vector<std::uint8_t> received;
    fixture.stage="response read";
    while (received.size()<=payload.size()+2) {
        auto size=co_await channel.read(bytes,deadline);
        if (!size) co_return error();
        if (!*size) break;
        received.insert(received.end(),bytes.begin(),bytes.begin()+*size);
    }
    auto response=v::parse_response(received); fixture.stage="response compare";
    fixture.application=response.status==v::HeaderStatus::accepted && response.consumed==2 && received.size()==payload.size()+2 &&
        std::ranges::equal(std::span(received).subspan(2),payload);
    co_return fixture.application ? capy::results<>{} : error();
}
auto run_channel(Fixture& fixture,Lower& lower,bool server,bool lite,std::string const& authority,std::uint16_t target,
                 g::Clock::time_point deadline) -> capy::task<> {
    auto profile=g::RequestProfile::create("nexus.Service",authority,true);
    if (!profile) co_return;
    auto protocol=g::Session::create(server ? g::Role::server : g::Role::client,*profile,
        lite ? g::ResponsePolicy::sing_box_lite : g::ResponsePolicy::standard);
    if (!protocol) co_return;
    Channel channel(lower,std::move(*protocol),deadline);
    if (server) {
        auto [signal,run,application]=co_await capy::when_all(channel.run(),serve(fixture,channel,lite,deadline));
        (void)run; (void)application;
        fixture.failure=channel.failure(); fixture.success=fixture.application && channel.drained() && ((!signal && channel.finished() && !fixture.failure) ||
            (lite && fixture.failure && fixture.failure->error==g::Error::reset && fixture.failure->code==nex::nghttp2::NGHTTP2_CANCEL));
    } else {
        auto [signal,run,application]=co_await capy::when_all(channel.run(),request(fixture,channel,target,deadline));
        (void)run; (void)application;
        fixture.failure=channel.failure(); fixture.success=fixture.application && !signal && channel.finished();
    }
}
auto client(Fixture& fixture,std::uint16_t remote,std::uint16_t target,std::string_view ca,std::string_view name,bool lite)
    -> capy::task<> {
    fixture.stage="TLS profile";
    constexpr std::array<std::string_view,1> protocols{"h2"};
    auto profile=tls::ClientProfile::load(name,ca,0x001d,false,protocols);
    if (!profile) co_return;
    auto now=g::Clock::now(),deadline=now+12s;
    auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto handshake=profile->handshake(milliseconds(now),milliseconds(deadline),wall);
    if (!handshake) co_return;
    tls::detail::OwnedClient owner(fixture.context,std::move(*handshake)); CancelGuard guard{owner};
    fixture.stage="TLS client handshake";
    auto connected=co_await owner.start(io::endpoint(io::ipv4_address::loopback(),remote));
    if (!connected) { fixture.tls_error=static_cast<int>(connected.error()); co_return; }
    auto* connection=owner.client(); fixture.stage="TLS h2 ALPN";
    if (!connection || !connection->application() || !connection->negotiated() ||
        !connection->negotiated()->alpn || !h2_selected(*connection->negotiated()->alpn)) co_return;
    Lower lower(*connection->application()); std::string authority="localhost";
    co_await run_channel(fixture,lower,false,lite,authority,target,deadline);
}
auto server(Fixture& fixture,tls::ServerCredential const& credential,std::uint16_t port,bool lite) -> capy::task<> {
    fixture.stage="accept";
    auto [error,socket]=co_await fixture.listener.accept(); fixture.listener.close();
    if (error) co_return;
    fixture.incoming=std::move(socket); CancelGuard guard{fixture.incoming};
    auto now=g::Clock::now(),deadline=now+12s; fixture.stage="TLS server handshake";
    auto handshake=tls::make_server_handshake(credential,milliseconds(now),milliseconds(deadline),{},"h2");
    if (!handshake) co_return;
    auto established=co_await tls::detail::server_handshake(fixture.incoming,*handshake);
    if (!established) { fixture.tls_error=static_cast<int>(established.error()); co_return; }
    fixture.stage="TLS h2 ALPN";
    if (!h2_selected(handshake->negotiated_alpn())) co_return;
    tls::detail::ApplicationConnection<io::tcp_socket> connection(fixture.incoming,std::move(established->records),std::move(established->unread));
    if (!established->release_unread_reservation()) co_return;
    Lower lower(connection);
    std::string authority=lite ? "localhost:"+std::to_string(port) : "localhost";
    if(!fixture.expected_authority.empty())authority=fixture.expected_authority;
    co_await run_channel(fixture,lower,true,lite,authority,0,deadline);
}
template<class Operation>
auto execute(Fixture& fixture,Operation operation) -> capy::task<> {
    try { co_await std::move(operation); } catch (...) { fixture.success=false; }
    fixture.incoming.close(); fixture.target.close(); fixture.listener.close(); fixture.done=true;
}
auto number(std::string_view text) -> std::optional<unsigned> {
    unsigned value=0; auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),value);
    if (error!=std::errc{} || end!=text.data()+text.size()) return {}; return value;
}
auto main(int argc,char** argv) -> int {
    if (argc!=7 && argc!=8) return 64;
    bool is_server=std::string_view(argv[1])=="server";
    if ((!is_server && std::string_view(argv[1])!="client") || (!is_server && argc!=8)) return 64;
    auto port=number(argv[2]),backend=number(argv[is_server ? 5 : 6]),policy=number(argv[is_server ? 6 : 7]);
    auto target=is_server ? std::optional<unsigned>{0} : number(argv[3]);
    if (!port || *port>65535 || (!is_server && !*port) || !target || *target>65535 || (!is_server && !*target) ||
        !backend || *backend>1 || !policy || *policy>1) return 64;
    if (*backend && !io::has_uring) return 77;
    Fixture fixture(*backend!=0);
    if(is_server&&argc==8)fixture.expected_authority=argv[7];
    std::optional<tls::ServerCredential> credential;
    if (is_server) {
        auto loaded=tls::load_server_credential(argv[3],argv[4]); if (!loaded) return 65;
        credential.emplace(std::move(*loaded));
        if (fixture.listener.open() || fixture.listener.bind(io::endpoint(io::ipv4_address::loopback(),static_cast<std::uint16_t>(*port))) || fixture.listener.listen()) return 66;
        *port=fixture.listener.local_endpoint().port(); std::cout << *port << '\n' << std::flush;
        capy::run_async(fixture.context.get_executor())(execute(fixture,server(fixture,*credential,static_cast<std::uint16_t>(*port),*policy!=0)));
    } else {
        capy::run_async(fixture.context.get_executor())(execute(fixture,client(fixture,static_cast<std::uint16_t>(*port),static_cast<std::uint16_t>(*target),argv[4],argv[5],*policy!=0)));
    }
    fixture.context.run_for(15s);
    if (!fixture.done) { fixture.incoming.close(); fixture.target.close(); fixture.listener.close(); fixture.context.restart(); fixture.context.run_for(2s); }
    if (!fixture.done || !fixture.context.stopped()) std::_Exit(67);
    if (!fixture.success) {
        std::cerr << "gRPC TLS fixture failed at " << fixture.stage;
        if (fixture.failure) std::cerr << " error=" << int(fixture.failure->error) << " code=" << fixture.failure->code;
        if (fixture.tls_error) std::cerr << " tls-error=" << *fixture.tls_error;
        std::cerr << '\n';
    }
    return fixture.success ? 0 : 1;
}
