import std;
import grpc.headers;
import grpc.session;
import grpc.stream;
import nghttp2;
import net.socket_stream;
import net.stream_relay;
import vless;
import capy;
import corosio;
namespace g=grpc;
namespace v=vless;
namespace io = ::corosio;
using namespace std::chrono_literals;
using Lower=net::SocketByteStream<io::tcp_socket>;
using Channel=g::Channel<Lower>;
struct Fixture {
    io::io_context context;
    io::tcp_acceptor listener{context};
    io::tcp_socket incoming{context},target{context};
    bool done=false,success=false,application=false;
    std::string_view stage="start",expected_authority;
    std::optional<g::Failure> failure;
    explicit Fixture(bool uring) : context(io::make_io_context(uring)) {}
};
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
// The fixed lite client's net.Conn has no CloseWrite. Its reverse-direction
// test therefore forwards a known payload before closing the target half;
// it checks bytes and trailers, not a peer TCP half-close promise.
auto lite_upload(Channel& channel,Lower& target,std::size_t remaining) -> capy::task<bool> {
    std::array<std::uint8_t,16384> bytes{};
    while (remaining) {
        auto received=co_await channel.read(std::span(bytes).first(std::min(bytes.size(),remaining)));
        if (!received || !*received || *received>remaining || !co_await target.send(std::span(bytes).first(*received))) co_return false;
        remaining-=*received;
    }
    co_return co_await target.close_output();
}
auto serve(Fixture& fixture,Channel& channel,bool lite) -> capy::task<capy::results<>> {
    fixture.stage="gRPC request headers";
    if (!co_await channel.accept(g::Clock::now()+5s)) co_return error();
    auto user=v::parse_user_id("00010203-0405-0607-0809-0a0b0c0d0e0f"); if (!user) co_return error();
    std::array<v::UserId,1> users{*user}; auto handshake=v::ServerHandshake::create(users);
    if (!handshake) co_return error();
    std::array<std::uint8_t,4096> buffer{}; std::vector<std::uint8_t> prefetched;
    fixture.stage="VLESS request";
    for (;;) {
        auto received=co_await channel.read(buffer,g::Clock::now()+5s);
        if (!received || !*received) co_return error();
        auto input=std::span(buffer).first(*received); auto fed=handshake->feed(input);
        if (fed.status==v::ServerStatus::rejected) co_return error();
        if (fed.status==v::ServerStatus::dialing) { prefetched.assign(input.begin()+fed.consumed,input.end()); break; }
    }
    auto request=handshake->request();
    if (!request || request->kind!=v::AddressKind::ipv4 || request->address!=std::vector<std::uint8_t>{127,0,0,1}) co_return error();
    fixture.stage="target connect";
    auto [connected]=co_await io::timeout(fixture.target.connect(io::endpoint(io::ipv4_address::loopback(),request->port)),g::Clock::now()+5s);
    auto response=handshake->complete_dial(!connected);
    if (!response || !co_await channel.send(*response)) co_return error();
    Lower target(fixture.target);
    if (!prefetched.empty() && !co_await target.send(prefetched)) co_return error();
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
            transfer(net::stream_relay::download(adapter)),
            transfer(net::stream_relay::upload(adapter)));
        (void)upload; (void)download;
        if (signal) co_return error();
        fixture.application=true;
    }
    co_return capy::results<>{};
}
auto request(Fixture& fixture,Channel& channel,std::uint16_t target) -> capy::task<capy::results<>> {
    auto user=v::parse_user_id("00010203-0405-0607-0809-0a0b0c0d0e0f"); if (!user) co_return error();
    auto header=v::encode_tcp_request({*user,v::AddressKind::ipv4,target,{127,0,0,1}}); if (!header) co_return error();
    auto payload=pattern(); header->insert(header->end(),payload.begin(),payload.end());
    fixture.stage="request/payload send and half-close";
    if (!co_await channel.send(*header,g::Clock::now()+10s) || !co_await channel.close_output(g::Clock::now()+10s)) co_return error();
    std::array<std::uint8_t,16384> bytes{}; std::vector<std::uint8_t> received;
    fixture.stage="response read";
    while (received.size()<=payload.size()+2) {
        auto size=co_await channel.read(bytes,g::Clock::now()+10s);
        if (!size) co_return error();
        if (!*size) break;
        received.insert(received.end(),bytes.begin(),bytes.begin()+*size);
    }
    auto response=v::parse_response(received); fixture.stage="response compare";
    fixture.application=response.status==v::HeaderStatus::accepted && response.consumed==2 && received.size()==payload.size()+2 &&
        std::ranges::equal(std::span(received).subspan(2),payload);
    co_return fixture.application ? capy::results<>{} : error();
}
auto execute(Fixture& fixture,bool server,bool lite,std::uint16_t remote,std::uint16_t target) -> capy::task<> {
    try {
        fixture.stage=server ? "accept" : "connect";
        if (server) {
            auto [accepted,socket]=co_await fixture.listener.accept(); fixture.listener.close();
            if (accepted) { fixture.done=true; co_return; }
            fixture.incoming=std::move(socket);
        } else {
            auto [connected]=co_await io::timeout(fixture.incoming.connect(io::endpoint(io::ipv4_address::loopback(),remote)),g::Clock::now()+5s);
            if (connected) { fixture.done=true; co_return; }
        }
        auto authority="127.0.0.1:"+std::to_string(remote);
        if(server&&!fixture.expected_authority.empty())authority=fixture.expected_authority;
        // The fixed plaintext lite client still emits :scheme https.
        auto profile=g::RequestProfile::create("nexus.Service",authority,server && lite);
        if (!profile) { fixture.done=true; co_return; }
        auto protocol=g::Session::create(server ? g::Role::server : g::Role::client,*profile,
            lite ? g::ResponsePolicy::sing_box_lite : g::ResponsePolicy::standard);
        if (!protocol) { fixture.done=true; co_return; }
        Lower lower(fixture.incoming); Channel channel(lower,std::move(*protocol),g::Clock::now()+15s);
        if (server) {
            auto [signal,run,application]=co_await capy::when_all(channel.run(),serve(fixture,channel,lite));
            (void)run; (void)application;
            fixture.failure=channel.failure();
            fixture.success=fixture.application && channel.drained() && ((!signal && channel.finished() && !fixture.failure) ||
            (lite && fixture.failure && fixture.failure->error==g::Error::reset && fixture.failure->code==nghttp2::NGHTTP2_CANCEL));
        } else {
            auto [signal,run,application]=co_await capy::when_all(channel.run(),request(fixture,channel,target));
            (void)run; (void)application;
            fixture.failure=channel.failure(); fixture.success=fixture.application && !signal && channel.finished();
        }
    } catch (...) { fixture.success=false; }
    fixture.incoming.close(); fixture.target.close(); fixture.listener.close(); fixture.done=true;
}
auto number(std::string_view text) -> std::optional<unsigned> {
    unsigned value=0; auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),value);
    if (error!=std::errc{} || end!=text.data()+text.size()) return {}; return value;
}
auto main(int argc,char** argv) -> int {
    if (argc<5 || argc>6) return 64;
    bool server=std::string_view(argv[1])=="server";
    if ((!server && std::string_view(argv[1])!="client") || (!server && argc!=6)) return 64;
    auto port=number(argv[2]),backend=number(argv[server ? 3 : 4]),policy=number(argv[server ? 4 : 5]);
    auto target=server ? std::optional<unsigned>{0} : number(argv[3]);
    if (!port || *port>65535 || (!server && !*port) || !target || *target>65535 || (!server && !*target) || !backend || *backend>1 || !policy || *policy>1) return 64;
    if (*backend && !io::has_uring) return 77;
    Fixture fixture(*backend!=0);
    if(server&&argc==6)fixture.expected_authority=argv[5];
    if (server) {
        if (fixture.listener.open() || fixture.listener.bind(io::endpoint(io::ipv4_address::loopback(),static_cast<std::uint16_t>(*port))) || fixture.listener.listen()) return 66;
        *port=fixture.listener.local_endpoint().port(); std::cout << *port << '\n' << std::flush;
    }
    capy::run_async(fixture.context.get_executor())(execute(fixture,server,*policy!=0,static_cast<std::uint16_t>(*port),static_cast<std::uint16_t>(*target)));
    fixture.context.run_for(18s);
    if (!fixture.done) {
        fixture.incoming.close(); fixture.target.close(); fixture.listener.close(); fixture.context.restart(); fixture.context.run_for(2s);
    }
    if (!fixture.done || !fixture.context.stopped()) std::_Exit(67);
    if (!fixture.success) {
        std::cerr << "gRPC fixture failed at " << fixture.stage;
        if (fixture.failure) std::cerr << " error=" << int(fixture.failure->error) << " code=" << fixture.failure->code;
        std::cerr << '\n';
    }
    return fixture.success ? 0 : 1;
}
