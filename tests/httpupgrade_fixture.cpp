import std;
import httpupgrade;
import httpupgrade.stream;
import net.stream_relay;
import vless;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace h=httpupgrade;
namespace v=vless;
namespace capy=nex::capy;
namespace io=nex::corosio;
using namespace std::chrono_literals;
struct Fixture {
    io::io_context context;
    io::tcp_acceptor listener{context};
    io::tcp_socket incoming{context},target{context};
    bool done=false,success=false;
    std::string_view stage="start";
    explicit Fixture(bool uring) : context(io::make_io_context(uring)) {}
};
auto pattern() -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> result(512*1024);
    for (std::size_t i=0;i<result.size();++i) result[i]=static_cast<std::uint8_t>(i);
    return result;
}
template<class Stream>
auto direction(capy::task<bool> operation,Stream& stream,io::tcp_socket& target) -> capy::task<capy::results<>> {
    if (co_await std::move(operation)) co_return capy::results<>{};
    stream.cancel(); target.cancel();
    co_return capy::results<>{std::make_error_code(std::errc::io_error)};
}
auto serve(Fixture& fixture,h::Profile const& profile) -> capy::task<> {
    fixture.stage="accept";
    auto [error,accepted]=co_await fixture.listener.accept();
    fixture.listener.close();
    if (error) co_return;
    fixture.incoming=std::move(accepted);
    auto deadline=h::Clock::now()+5s;
    h::SocketByteStream lower(fixture.incoming);
    fixture.stage="server Upgrade";
    auto upgraded=co_await h::accept(lower,profile,deadline);
    if (!upgraded) co_return;
    auto user=v::parse_user_id("00010203-0405-0607-0809-0a0b0c0d0e0f");
    if (!user) co_return;
    std::array<v::UserId,1> users{*user};
    auto handshake=v::ServerHandshake::create(users);
    if (!handshake) co_return;
    std::array<std::uint8_t,4096> buffer{};
    std::span<std::uint8_t const> input=upgraded->unread;
    std::vector<std::uint8_t> prefetched;
    fixture.stage="VLESS request";
    for (;;) {
        if (input.empty()) {
            auto received=co_await lower.read(buffer,deadline);
            if (!received || !*received) co_return;
            input=std::span(buffer).first(*received);
        }
        auto fed=handshake->feed(input);
        if (fed.status==v::ServerStatus::rejected) co_return;
        if (fed.status==v::ServerStatus::dialing) {
            prefetched.assign(input.begin()+fed.consumed,input.end()); break;
        }
        input={};
    }
    auto request=handshake->request();
    if (!request || request->kind!=v::AddressKind::ipv4 || request->address!=std::vector<std::uint8_t>{127,0,0,1}) co_return;
    fixture.stage="target connect";
    auto [connected]=co_await io::timeout(fixture.target.connect(io::endpoint(io::ipv4_address::loopback(),request->port)),deadline);
    auto response=handshake->complete_dial(!connected);
    if (!response || !co_await lower.send(*response,deadline)) co_return;
    h::SocketByteStream target(fixture.target);
    if (!prefetched.empty() && !co_await target.send(prefetched,deadline)) co_return;
    fixture.stage="relay";
    auto adapter=net::ByteRelayAdapter{fixture.target,lower,[] {},false};
    auto [signal,upload,download]=co_await capy::when_all(
        direction(net::stream_relay::upload(adapter),lower,fixture.target),
        direction(net::stream_relay::download(adapter),lower,fixture.target));
    (void)upload; (void)download; fixture.success=!signal;
}
auto client(Fixture& fixture,h::Profile const& profile,std::uint16_t remote,std::uint16_t target) -> capy::task<> {
    fixture.stage="connect";
    auto deadline=h::Clock::now()+5s;
    auto [error]=co_await io::timeout(fixture.incoming.connect(io::endpoint(io::ipv4_address::loopback(),remote)),deadline);
    if (error) co_return;
    h::SocketByteStream lower(fixture.incoming);
    fixture.stage="client Upgrade";
    auto upgraded=co_await h::connect(lower,profile,deadline);
    if (!upgraded) co_return;
    auto user=v::parse_user_id("00010203-0405-0607-0809-0a0b0c0d0e0f"); if (!user) co_return;
    auto header=v::encode_tcp_request({*user,v::AddressKind::ipv4,target,{127,0,0,1}}); if (!header) co_return;
    auto payload=pattern();
    header->insert(header->end(),payload.begin(),payload.end());
    fixture.stage="request/payload send and half-close";
    if (!co_await lower.send(*header,h::Clock::now()+10s) || !co_await lower.close_output()) co_return;
    auto received=std::move(upgraded->unread);
    std::array<std::uint8_t,16384> bytes{};
    fixture.stage="response read";
    while (received.size()<=payload.size()+2) {
        auto n=co_await lower.read(bytes,h::Clock::now()+10s);
        if (!n) co_return;
        if (!*n) break;
        received.insert(received.end(),bytes.begin(),bytes.begin()+*n);
    }
    auto response=v::parse_response(received);
    fixture.stage="response compare";
    fixture.success=response.status==v::HeaderStatus::accepted && response.consumed==2 && received.size()==payload.size()+2 &&
        std::ranges::equal(std::span(received).subspan(2),payload);
}
auto execute(Fixture& fixture,h::Profile const& profile,bool server,std::uint16_t remote,std::uint16_t target) -> capy::task<> {
    try {
        if (server) co_await serve(fixture,profile);
        else co_await client(fixture,profile,remote,target);
    } catch (...) { fixture.success=false; }
    fixture.incoming.close(); fixture.target.close(); fixture.listener.close(); fixture.done=true;
}
auto number(std::string_view text) -> std::optional<unsigned> {
    unsigned value=0; auto [end,error]=std::from_chars(text.data(),text.data()+text.size(),value);
    if (error!=std::errc{} || end!=text.data()+text.size()) return {};
    return value;
}
auto main(int argc,char** argv) -> int {
    if (argc!=4 && argc!=5) return 64;
    auto mode=std::string_view(argv[1]);
    bool server=mode=="server";
    if ((!server && mode!="client") || argc!=(server ? 4 : 5)) return 64;
    auto port=number(argv[2]),backend=number(argv[argc-1]);
    auto target=server ? std::optional<unsigned>{0} : number(argv[3]);
    if (!port || *port>65535 || (!server && !*port) || !target || *target>65535 || (!server && !*target) || !backend || *backend>1) return 64;
    if (*backend && !io::has_uring) return 77;
    Fixture fixture(*backend!=0);
    auto profile=server ? h::Profile::server("cover.example","/nexus-upgrade") : h::Profile::client("cover.example","/nexus-upgrade");
    if (!profile) return 65;
    if (server) {
        if (fixture.listener.open() || fixture.listener.bind(io::endpoint(io::ipv4_address::loopback(),static_cast<std::uint16_t>(*port))) || fixture.listener.listen()) return 66;
        std::cout << fixture.listener.local_endpoint().port() << '\n' << std::flush;
    }
    capy::run_async(fixture.context.get_executor())(execute(fixture,*profile,server,static_cast<std::uint16_t>(*port),static_cast<std::uint16_t>(*target)));
    fixture.context.run_for(20s);
    if (!fixture.done) {
        fixture.incoming.close(); fixture.target.close(); fixture.listener.close();
        fixture.context.restart(); fixture.context.run_for(2s);
    }
    if (!fixture.done || !fixture.context.stopped()) std::_Exit(67);
    if (!fixture.success) std::cerr << "HTTPUpgrade fixture failed at " << fixture.stage << '\n';
    return fixture.success ? 0 : 1;
}
