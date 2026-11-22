import std;
import anytls;
import anytls.auth;
import anytls.padding;
import anytls.session;
import anytls.writer;
import anytls.connection;
import anytls.pool;
import net.stream_relay;
import tls.profiles;
import tls.server_credential;
import tls.byte_stream;
import tls.corosio_client;
import tls.corosio_application;
import tls.corosio_server_handshake;
import tls.connector;
import platform.socket_options;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace a=anytls;
namespace tls=tls;
namespace capy=nex::capy;
namespace io=nex::corosio;
using namespace std::chrono_literals;
using Lower=tls::detail::ByteStream<io::tcp_socket>;
using Session=a::Session<Lower>;
struct Resolver {
    io::endpoint node;
    bool canceled=false;
    auto cancel() noexcept -> void { canceled=true; }
    auto operator()(a::IoClock::time_point deadline) -> capy::task<std::optional<std::vector<io::endpoint>>> {
        if (canceled || a::IoClock::now()>=deadline) co_return std::nullopt;
        co_return std::vector<io::endpoint>{node};
    }
};
using Connector=tls::detail::PhysicalConnector<Resolver,tls::ClientProfile>;
using Connection=a::PooledConnection<Connector>;
struct PoolState {
    tls::ClientProfile profile;
    a::PaddingScheme padding;
    ::platform::TcpSocketOptions options;
    capy::async_event changed;
    a::ClientPool<Connection> pool{{.max_sessions=2,.min_idle=1}};
    Connection* last=nullptr;
    PoolState(tls::ClientProfile tls,a::PaddingScheme scheme) : profile(std::move(tls)),padding(std::move(scheme)) {}
};
auto pool_root(PoolState& state,io::io_context& context,std::uint16_t peer,std::uint16_t target,
    std::span<std::uint8_t const> key,std::string_view mode,bool& ready,int& result) -> capy::task<> {
    auto creation=state.pool.reserve();
    if (!creation) { result=70; co_return; }
    auto connection=std::make_unique<Connection>(state.padding,&state.changed,context,
        Resolver{io::endpoint(io::ipv4_address::loopback(),peer)},state.profile,state.options);
    if (co_await connection->start(key,a::IoClock::now()+5s)!=tls::detail::ConnectResult::connected) { result=71; co_return; }
    state.last=connection.get();
    auto lease=creation->commit(std::move(connection));
    if (!lease) { result=72; co_return; }
    lease->connection().run(context);
    if (mode=="pool-active") {
        auto* protocol=lease->connection().protocol();
        a::Address address{net::ProxyAddressFamily::ipv4,{127,0,0,1},4,target};
        auto id=co_await protocol->open(address,a::IoClock::now()+5s);
        if (!id) { result=73; co_return; }
        a::StreamChannel channel(*protocol,*id);
        ready=true;
        std::array<std::uint8_t,1> bytes{};
        (void)co_await channel.read(bytes,a::IoClock::now()+60s);
    } else {
        lease->reset(); ready=true;
        if (mode=="pool-queued") context.stop();
        (void)co_await io::delay(60s);
    }
    result=74;
}
auto pool_lifetime(std::uint16_t peer,std::uint16_t target,std::string_view ca,a::PasswordKey const& key,bool uring,std::string_view mode) -> int {
    auto profile=tls::ClientProfile::load("localhost",ca);
    auto padding=a::PaddingScheme::parse(a::default_padding_scheme);
    if (!profile || !padding) return 75;
    PoolState state(std::move(*profile),std::move(*padding));
    bool ready=false,done=false;
    int result=0;
    {
        auto context=io::make_io_context(uring);
        capy::run_async(context.get_executor(),[&] { done=true; },[&](std::exception_ptr) { result=76; done=true; })(
            pool_root(state,context,peer,target,key.view(),mode,ready,result));
        auto deadline=a::IoClock::now()+6s;
        while (!ready && !done && a::IoClock::now()<deadline) { context.restart(); context.run_for(10ms); }
        if (!ready || done || result) { state.pool.stop(); context.restart(); context.run_for(1s); return result ? result : 77; }
        // Intentionally abandon the idle reader or active logical stream.
        // State and profile outlive this context, as in the real factory.
    }
    if (!state.last || !state.pool.drained() || !state.last->drained() || state.last->protocol()) {
        std::cerr<<"pooled I/O survived context abandonment"<<std::endl; std::_Exit(78);
    }
    state.pool.stop(); state.pool.reap(a::IoClock::now());
    if (state.pool.size()) return 79;
    std::cout<<"pool-abandoned"<<std::endl; return 0;
}
auto milliseconds(a::IoClock::time_point value) -> std::uint64_t {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(value.time_since_epoch()).count());
}
auto read_exact(Session& session,std::uint32_t id,std::span<std::uint8_t> bytes) -> capy::task<bool> {
    auto deadline=a::IoClock::now()+5s;
    while (!bytes.empty()) {
        auto received=co_await session.read(id,bytes,deadline);
        if (!received || !*received) co_return false;
        bytes=bytes.subspan(*received);
    }
    co_return true;
}
auto destination(Session& session,std::uint32_t id) -> capy::task<std::optional<a::Address>> {
    std::array<std::uint8_t,259> bytes{};
    for (std::size_t size=0;size<bytes.size();++size) {
        if (!co_await read_exact(session,id,std::span(bytes).subspan(size,1))) co_return std::nullopt;
        auto parsed=net::parse_proxy_address(std::span(bytes).first(size+1),net::AddressWire::socks);
        if (parsed.status==net::DatagramStatus::accepted) co_return parsed.address;
        if (parsed.status!=net::DatagramStatus::incomplete) co_return std::nullopt;
    }
    co_return std::nullopt;
}
auto direction(capy::task<bool> operation,a::StreamChannel<Lower>& stream,io::tcp_socket& target) -> capy::task<capy::results<>> {
    if (co_await std::move(operation)) co_return capy::results<>{};
    stream.cancel(); target.cancel(); co_return capy::results<>{std::make_error_code(std::errc::io_error)};
}
auto server_app(Session& session,io::io_context& context,std::uint16_t port,int& result) -> capy::task<capy::results<>> {
    for (unsigned index=0;index<3;++index) {
        auto id=co_await session.accept(a::IoClock::now()+5s);
        if (!id) { result=20; co_return capy::results<>{std::make_error_code(std::errc::io_error)}; }
        a::StreamChannel channel(session,*id);
        auto address=co_await destination(session,*id);
        if (!address || address->port!=port || address->family!=net::ProxyAddressFamily::ipv4 || address->length!=4 ||
            !std::ranges::equal(std::span(address->bytes).first(4),std::array<std::uint8_t,4>{127,0,0,1})) {
            result=21; co_return capy::results<>{std::make_error_code(std::errc::io_error)};
        }
        io::tcp_socket target(context);
        auto [connected]=co_await io::timeout(target.connect(io::endpoint(io::ipv4_address::loopback(),port)),a::IoClock::now()+5s);
        if (connected || !co_await session.acknowledge(*id,true,a::IoClock::now()+5s)) {
            result=22; co_return capy::results<>{std::make_error_code(std::errc::io_error)};
        }
        auto adapter=net::ByteRelayAdapter{target,channel,[] {},false};
        auto [error,upload,download]=co_await capy::when_all(
            direction(net::stream_relay::upload(adapter),channel,target),
            direction(net::stream_relay::download(adapter),channel,target));
        (void)upload; (void)download;
        if (error) { result=23; co_return capy::results<>{error}; }
    }
    result=0; session.cancel(); co_return capy::results<>{};
}
auto client_app(Session& session,std::uint16_t port,int& result) -> capy::task<capy::results<>> {
    a::Address address{net::ProxyAddressFamily::ipv4,{127,0,0,1},4,port};
    for (unsigned index=0;index<3;++index) {
        auto id=co_await session.open(address,a::IoClock::now()+5s);
        if (!id || *id!=index+1) { result=30; co_return capy::results<>{std::make_error_code(std::errc::io_error)}; }
        a::StreamChannel channel(session,*id);
        std::array<std::uint8_t,16384> data{},received{};
        for (std::size_t i=0;i<data.size();++i) data[i]=static_cast<std::uint8_t>(i+index);
        if (!co_await channel.send(data,a::IoClock::now()+5s) || !co_await read_exact(session,*id,received) || data!=received ||
            !co_await channel.close_output(a::IoClock::now()+5s)) { result=31; co_return capy::results<>{std::make_error_code(std::errc::io_error)}; }
    }
    // The driver observes all three target EOFs before releasing this gate.
    // Its lifetime assertion does not depend on an arbitrary sleep.
    std::cout<<"streams-done"<<std::endl;
    char release=0;
    std::cin.get(release);
    if (!std::cin || release!='x') { result=32; co_return capy::results<>{std::make_error_code(std::errc::io_error)}; }
    result=0; session.cancel(); co_return capy::results<>{};
}
auto client(io::io_context& context,std::uint16_t proxy,std::uint16_t target,std::string_view ca,a::PasswordKey const& key,int& result) -> capy::task<> {
    auto profile=tls::ClientProfile::load("localhost",ca);
    auto padding=a::PaddingScheme::parse(a::default_padding_scheme);
    if (!profile || !padding) { result=10; co_return; }
    auto now=a::IoClock::now(),deadline=now+5s;
    auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto handshake=profile->handshake(milliseconds(now),milliseconds(deadline),wall);
    if (!handshake) { result=11; co_return; }
    tls::detail::OwnedClient owner(context,std::move(*handshake));
    auto connected=co_await owner.start(io::endpoint(io::ipv4_address::loopback(),proxy));
    auto* connection=owner.client();
    if (!connected || !connection || !connection->application()) { result=12; co_return; }
    Lower stream(*connection->application()); Session session(stream,*padding,true);
    if (!co_await session.start_client(key.view(),deadline)) { result=13; co_return; }
    (void)co_await capy::when_all(session.run(),client_app(session,target,result));
}
auto server(io::io_context& context,io::tcp_acceptor& listener,std::uint16_t target,tls::ServerCredential const& credential,
    std::span<a::PasswordKey const> users,int& result) -> capy::task<> {
    auto [error,socket]=co_await listener.accept(); listener.close();
    if (error) { result=14; co_return; }
    auto now=a::IoClock::now(),deadline=now+5s;
    auto padding=a::PaddingScheme::parse(a::default_padding_scheme);
    auto handshake=tls::make_server_handshake(credential,milliseconds(now),milliseconds(deadline));
    if (!padding || !handshake) { result=15; co_return; }
    auto established=co_await tls::detail::server_handshake(socket,*handshake);
    if (!established) { result=16; co_return; }
    tls::detail::ApplicationConnection<io::tcp_socket> connection(socket,std::move(established->records),std::move(established->unread));
    if (!established->release_unread_reservation()) { result=17; co_return; }
    Lower stream(connection); Session session(stream,*padding,false);
    auto authenticated=co_await session.start_server(users,deadline);
    if (!authenticated) { result=18; co_return; }
    (void)co_await capy::when_all(session.run(),server_app(session,context,target,result));
}
auto main(int argc,char** argv) -> int {
    if (argc!=8) return 64;
    auto mode=std::string_view(argv[1]);
    auto number=[](char const* text) -> unsigned { unsigned value=0; auto end=text+std::char_traits<char>::length(text); auto parsed=std::from_chars(text,end,value); return parsed.ec==std::errc{} && parsed.ptr==end ? value : 0; };
    auto peer=number(argv[2]),target=number(argv[3]);
    if (!peer || peer>65535 || !target || target>65535 ||
        (mode!="client" && mode!="server" && mode!="pool-idle" && mode!="pool-active" && mode!="pool-queued")) return 64;
    auto password=a::PasswordKey::load(argv[6]); if (!password) return 65;
    if (mode.starts_with("pool-")) return pool_lifetime(peer,target,argv[4],*password,std::string_view(argv[7])=="1",mode);
    auto context=io::make_io_context(std::string_view(argv[7])=="1");
    int result=99; bool done=false;
    auto finish=[&] { done=true; };
    auto failed=[&](std::exception_ptr) { result=98; done=true; };
    if (mode=="client") capy::run_async(context.get_executor(),finish,failed)(client(context,peer,target,argv[4],*password,result));
    else {
        auto credential=tls::load_server_credential(argv[4],argv[5]); if (!credential) return 66;
        std::vector<a::PasswordKey> users; users.push_back(std::move(*password));
        io::tcp_acceptor listener(context);
        if (listener.open() || listener.bind(io::endpoint(io::ipv4_address::loopback(),peer)) || listener.listen()) return 67;
        std::cout<<"ready"<<std::endl;
        capy::run_async(context.get_executor(),finish,failed)(server(context,listener,target,*credential,users,result));
        context.run_for(15s);
        if (!done) { std::cerr<<"server timed out"<<std::endl; std::_Exit(68); }
        return result;
    }
    context.run_for(15s);
    if (!done) { std::cerr<<"client timed out"<<std::endl; std::_Exit(69); }
    return result;
}
