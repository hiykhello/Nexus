import std;
import httpupgrade;
import httpupgrade.stream;
import vless;
import vless.corosio_client;
import vless.tls_server;
import tls.profiles;
import tls.server_credential;
import tls.corosio_client;
import tls.corosio_application;
import tls.corosio_server_handshake;
import capy;
import corosio;
namespace h=httpupgrade;
namespace v=vless;
namespace t=tls;
namespace io = ::corosio;
using namespace std::chrono_literals;
using Connection=t::detail::ApplicationConnection<io::tcp_socket>;
using Client=v::detail::TcpClient<io::tcp_socket>;
using Relay=v::detail::DuplexRelay<io::tcp_socket,io::tcp_socket>;
using Inbound=v::detail::TlsInbound<io::tcp_socket>;
struct Fixture {
    io::io_context context;
    io::tcp_acceptor listener{context};
    io::tcp_socket incoming{context},target{context};
    bool done=false,success=false;
    std::string_view stage="start";
    std::optional<int> tls_error;
    std::optional<h::Failure> upgrade_error;
    explicit Fixture(bool uring) : context(io::make_io_context(uring)) {}
};
template<class Owner> struct CancelGuard { Owner& owner; ~CancelGuard() { owner.cancel(); } };
auto milliseconds(h::Clock::time_point point) -> std::uint64_t {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(point.time_since_epoch()).count());
}
auto h1_selected(std::span<std::uint8_t const> protocol) -> bool {
    constexpr std::string_view h1="http/1.1";
    return std::ranges::equal(protocol,std::span(reinterpret_cast<std::uint8_t const*>(h1.data()),h1.size()));
}
auto pattern() -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> result(512*1024);
    for (std::size_t i=0;i<result.size();++i) result[i]=static_cast<std::uint8_t>(i);
    return result;
}
auto direction(capy::task<bool> operation) -> capy::task<capy::results<>> {
    if (!co_await std::move(operation)) co_return capy::results<>{std::make_error_code(std::errc::io_error)};
    co_return capy::results<>{};
}
auto serve(Fixture& fixture,Connection& connection,h::Clock::time_point deadline) -> capy::task<> {
    auto profile=h::Profile::server("cover.example","/nexus-upgrade");
    auto user=v::parse_user_id("00010203-0405-0607-0809-0a0b0c0d0e0f"); if (!profile || !user) co_return;
    std::array<v::UserId,1> users{*user}; auto handshake=v::ServerHandshake::create(users); if (!handshake) co_return;
    Inbound inbound(connection,std::move(*handshake)); CancelGuard guard{inbound};
    fixture.stage="server Upgrade";
    auto upgraded=co_await inbound.upgrade(*profile,deadline);
    if (!upgraded) { fixture.upgrade_error=upgraded.error(); co_return; }
    std::cout << "prefetch=" << *upgraded << '\n' << std::flush;
    fixture.stage="VLESS request";
    auto request=co_await inbound.read_request(deadline);
    if (!request || request->kind!=v::AddressKind::ipv4 || request->address!=std::vector<std::uint8_t>{127,0,0,1}) co_return;
    fixture.stage="target connect";
    auto [connected]=co_await io::timeout(fixture.target.connect(io::endpoint(io::ipv4_address::loopback(),request->port)),deadline);
    if (!co_await inbound.complete_dial(!connected,deadline)) co_return;
    fixture.stage="relay";
    v::detail::TlsRelay relay(inbound,fixture.target); CancelGuard relay_guard{relay};
    auto operation=capy::when_all(direction(relay.upload()),direction(relay.download()));
    auto [error,upload,download]=co_await io::timeout(std::move(operation),deadline);
    (void)upload; (void)download; fixture.success=!error;
}
auto request(Fixture& fixture,Connection& connection,std::uint16_t target,h::Clock::time_point deadline) -> capy::task<> {
    auto profile=h::Profile::client("cover.example","/nexus-upgrade");
    auto user=v::parse_user_id("00010203-0405-0607-0809-0a0b0c0d0e0f"); if (!profile || !user) co_return;
    Client client(connection); CancelGuard guard{client};
    fixture.stage="client Upgrade";
    auto upgraded=co_await client.upgrade(*profile,deadline);
    if (!upgraded) { fixture.upgrade_error=upgraded.error(); co_return; }
    std::cout << "prefetch=" << *upgraded << '\n' << std::flush;
    fixture.stage="VLESS request";
    if (!co_await client.start({*user,v::AddressKind::ipv4,target,{127,0,0,1}},deadline)) co_return;
    Relay relay(fixture.target,connection,client,{},false); CancelGuard relay_guard{relay};
    auto payload=pattern(); fixture.stage="request/payload send and half-close";
    if (!co_await relay.write(payload,deadline) || !co_await relay.close_output(deadline)) co_return;
    std::array<std::uint8_t,16384> bytes{}; std::vector<std::uint8_t> received;
    fixture.stage="response read";
    while (received.size()<=payload.size()) {
        auto size=co_await relay.read(bytes,deadline); if (!size) co_return;
        if (!*size) break;
        received.insert(received.end(),bytes.begin(),bytes.begin()+*size);
    }
    fixture.stage="response compare"; fixture.success=received==payload;
}
auto client(Fixture& fixture,std::uint16_t remote,std::uint16_t target,std::string_view ca,std::string_view name) -> capy::task<> {
    fixture.stage="TLS profile"; constexpr std::array<std::string_view,1> alpn{"http/1.1"};
    auto profile=t::ClientProfile::load(name,ca,0x001d,false,alpn); if (!profile) co_return;
    auto now=h::Clock::now(),deadline=now+12s;
    auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto handshake=profile->handshake(milliseconds(now),milliseconds(deadline),wall); if (!handshake) co_return;
    t::detail::OwnedClient owner(fixture.context,std::move(*handshake)); CancelGuard guard{owner};
    fixture.stage="TLS client handshake";
    auto connected=co_await owner.start(io::endpoint(io::ipv4_address::loopback(),remote));
    if (!connected) { fixture.tls_error=static_cast<int>(connected.error()); co_return; }
    auto* connection=owner.client(); fixture.stage="TLS http/1.1 ALPN";
    if (!connection || !connection->application() || !connection->negotiated() || !connection->negotiated()->alpn || !h1_selected(*connection->negotiated()->alpn)) co_return;
    co_await request(fixture,*connection->application(),target,deadline);
}
auto server(Fixture& fixture,t::ServerCredential const& credential) -> capy::task<> {
    fixture.stage="accept";
    auto [error,socket]=co_await fixture.listener.accept(); fixture.listener.close(); if (error) co_return;
    fixture.incoming=std::move(socket); CancelGuard guard{fixture.incoming};
    auto now=h::Clock::now(),deadline=now+12s; fixture.stage="TLS server handshake";
    auto handshake=t::make_server_handshake(credential,milliseconds(now),milliseconds(deadline),{},"http/1.1"); if (!handshake) co_return;
    auto established=co_await t::detail::server_handshake(fixture.incoming,*handshake);
    if (!established) { fixture.tls_error=static_cast<int>(established.error()); co_return; }
    fixture.stage="TLS http/1.1 ALPN"; if (!h1_selected(handshake->negotiated_alpn())) co_return;
    Connection connection(fixture.incoming,std::move(established->records),std::move(established->unread));
    if (!established->release_unread_reservation()) co_return;
    co_await serve(fixture,connection,deadline);
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
    if (argc!=6 && argc!=7) return 64;
    bool is_server=std::string_view(argv[1])=="server";
    if ((!is_server && std::string_view(argv[1])!="client") || argc!=(is_server ? 6 : 7)) return 64;
    auto port=number(argv[2]),backend=number(argv[argc-1]); auto target=is_server ? std::optional<unsigned>{0} : number(argv[3]);
    if (!port || *port>65535 || (!is_server && !*port) || !target || *target>65535 || (!is_server && !*target) || !backend || *backend>1) return 64;
    if (*backend && !io::has_uring) return 77;
    Fixture fixture(*backend!=0); std::optional<t::ServerCredential> credential;
    if (is_server) {
        auto loaded=t::load_server_credential(argv[3],argv[4]); if (!loaded) return 65; credential.emplace(std::move(*loaded));
        if (fixture.listener.open() || fixture.listener.bind(io::endpoint(io::ipv4_address::loopback(),static_cast<std::uint16_t>(*port))) || fixture.listener.listen()) return 66;
        std::cout << fixture.listener.local_endpoint().port() << '\n' << std::flush;
        capy::run_async(fixture.context.get_executor())(execute(fixture,server(fixture,*credential)));
    } else capy::run_async(fixture.context.get_executor())(execute(fixture,client(fixture,static_cast<std::uint16_t>(*port),static_cast<std::uint16_t>(*target),argv[4],argv[5])));
    fixture.context.run_for(15s);
    if (!fixture.done) { fixture.incoming.close(); fixture.target.close(); fixture.listener.close(); fixture.context.restart(); fixture.context.run_for(2s); }
    if (!fixture.done || !fixture.context.stopped()) std::_Exit(67);
    if (!fixture.success) {
        std::cerr << "HTTPUpgrade VLESS fixture failed at " << fixture.stage;
        if (fixture.upgrade_error) std::cerr << " upgrade=" << int(fixture.upgrade_error->error) << ':' << int(fixture.upgrade_error->status);
        if (fixture.tls_error) std::cerr << " tls-error=" << *fixture.tls_error;
        std::cerr << '\n';
    }
    return fixture.success ? 0 : 1;
}
