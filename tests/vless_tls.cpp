import std;
import vless;
import config;
import rulefile;
import tls.client_handshake_io;
import tls.application_io;
import capy;
import corosio;
import tls.corosio_client;
import tls.corosio_application;
import vless.corosio_client;
import vless.client_profile;
namespace io = ::corosio; namespace t=tls; namespace v=vless;
using Bytes=std::vector<std::uint8_t>; using namespace std::chrono_literals;
struct Fixture {
    io::io_context context=io::make_io_context(std::getenv("NEXUS_TEST_URING")!=nullptr);
    std::optional<t::ClientHandshakeIo> handshake; std::array<std::uint8_t,16> user{}; std::uint16_t port, destination_port=443; bool invalid=false, bad_user=false, relay=false, relay_cancel=false, numeric_destination=false,done=false,success=false;
    ~Fixture() { context.restart(); (void)context.run_for(1s); if (!context.stopped()) std::_Exit(90); }
};
using Relay=v::detail::DuplexRelay<io::local_stream_socket,io::tcp_socket>;
struct RelayState { Relay& relay; capy::async_event finished; unsigned pending=3; bool upload=false, download=false, peer=false, cancel=false;
    auto complete() -> void { if (--pending==0) finished.set(); } };
auto relay_upload(RelayState& state, std::chrono::steady_clock::time_point deadline) -> capy::task<> {
    state.upload=co_await state.relay.upload(deadline); state.complete();
}
auto relay_download(RelayState& state, std::chrono::steady_clock::time_point deadline) -> capy::task<> {
    state.download=co_await state.relay.download(deadline); state.complete();
}
auto relay_peer(RelayState& state, io::local_stream_socket& peer) -> capy::task<> {
    Bytes data{'h','e','l','l','o'}; std::size_t sent=0;
    while (sent<data.size()) {
        auto [error,n]=co_await peer.write_some(capy::const_buffer(data.data()+sent,data.size()-sent));
        if (error || !n) { state.relay.cancel(); state.complete(); co_return; }
        sent+=n;
    }
    if (state.cancel) { state.relay.cancel(); peer.close(); state.peer=true; state.complete(); co_return; }
    (void)peer.shutdown(io::shutdown_send);
    std::array<char,5> received{}; std::size_t size=0;
    while (size<received.size()) {
        auto [error,n]=co_await peer.read_some(capy::mutable_buffer(received.data()+size,received.size()-size));
        if (error || !n) { state.relay.cancel(); state.complete(); co_return; }
        size+=n;
    }
    std::array<char,1> trailing{};
    auto [error,n]=co_await peer.read_some(capy::mutable_buffer(trailing.data(),trailing.size()));
    state.peer=std::string_view(received.data(),received.size())=="world" && capy::is_eof(error) && n==0;
    if (!state.peer) state.relay.cancel();
    state.complete();
}
auto run(Fixture& f) -> capy::task<> {
    t::detail::OwnedClient owner(f.context,std::move(*f.handshake)); f.handshake.reset();
    if (!co_await owner.start(io::endpoint(io::ipv4_address::loopback(),f.port))) { f.done=true; co_return; }
    auto& connection=*owner.client()->application(); v::detail::TcpClient client(connection); v::TcpRequest request;
    request.user=f.user;
    if (f.bad_user) request.user[15]^=1;
    request.kind=f.numeric_destination ? v::AddressKind::ipv4 : v::AddressKind::domain; request.port=f.destination_port;
    request.address=f.numeric_destination ? Bytes{127,0,0,1} : Bytes{'e','x','a','m','p','l','e','.','c','o','m'};
    auto deadline=std::chrono::steady_clock::now()+8s;
    auto started=co_await client.start(request,deadline); if (!started) { f.done=true; co_return; }
    if (f.relay) {
        io::local_stream_socket local(f.context), peer(f.context);
        if (io::connect_pair(local,peer)) { f.done=true; co_return; }
        Relay relay(local,connection,client); RelayState state{relay}; state.cancel=f.relay_cancel;
        capy::run_async(f.context.get_executor())(relay_upload(state,deadline));
        capy::run_async(f.context.get_executor())(relay_download(state,deadline));
        capy::run_async(f.context.get_executor())(relay_peer(state,peer));
        (void)co_await state.finished.wait();
        f.success=state.peer && connection.idle() && (f.relay_cancel ? !state.upload && !state.download : state.upload && state.download);
        f.done=true; co_return;
    }
    Bytes outgoing{'h','e','l','l','o'}; auto sent=co_await client.send(outgoing,deadline); if (!sent) { f.done=true; co_return; }
    auto accepted=co_await client.receive_response(deadline);
    if (f.bad_user) {
        f.success=!accepted && !connection.active() && connection.idle();
        f.done=true; co_return;
    }
    if (f.invalid) { f.success=!accepted && accepted.error()==v::detail::ClientError::response && !connection.active() && connection.idle(); f.done=true; co_return; }
    if (!accepted || !client.reader()) { f.done=true; co_return; }
    std::array<std::uint8_t,3> chunk{}; Bytes payload;
    while (payload.size()<5) {
        auto result=co_await client.reader()->read_some(chunk,deadline);
        if (!result || result->kind!=t::detail::AsyncStreamReadKind::data) { f.done=true; co_return; }
        payload.insert(payload.end(),chunk.begin(),chunk.begin()+static_cast<std::ptrdiff_t>(result->size));
    }
    auto closed=co_await connection.close_notify(deadline);
    f.success=payload==Bytes({'w','o','r','l','d'}) && closed.has_value(); f.done=true;
}
int main(int argc,char** argv) {
    if (argc!=5 && argc!=6) return 1; auto port=std::strtoul(argv[1],nullptr,10); if (!port || port>65535) return 2;
    config::VlessOutbound config{"127.0.0.1",static_cast<std::uint16_t>(port),argv[3],"server.example",argv[2]};
    auto profile=v::detail::ClientProfile::load(config); if (!profile) return 3;
    auto invalid_name=config; invalid_name.server_name="bad/name";
    if (v::detail::ClientProfile::load(invalid_name)) return 4;
    auto invalid_server=config; invalid_server.port=0;
    if (v::detail::ClientProfile::load(invalid_server)) return 4;
    auto invalid_ca=config; invalid_ca.ca_file="relative.pem";
    if (v::detail::ClientProfile::load(invalid_ca)) return 4;
    auto seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    auto now=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    auto handshake=profile->handshake(now,now+10000,seconds); if (!handshake) return 6;
    auto another=profile->handshake(now,now+10000,seconds);
    if (!another || std::ranges::equal(handshake->pending_output(),another->pending_output()) ||
        profile->handshake(now,now,seconds)) return 8;
    Fixture f; f.user=profile->user; f.port=profile->port; f.invalid=std::string_view(argv[4])=="invalid";
    f.bad_user=std::string_view(argv[4])=="bad-user";
    f.relay_cancel=std::string_view(argv[4])=="relay-cancel";
    f.relay=std::string_view(argv[4])=="relay" || f.relay_cancel;
    if (argc==6) { auto destination=std::strtoul(argv[5],nullptr,10); if (!destination || destination>65535) return 2; f.destination_port=static_cast<std::uint16_t>(destination); f.numeric_destination=true; }
    f.handshake=std::move(*handshake);
    capy::run_async(f.context.get_executor())(run(f)); (void)f.context.run_for(10s);
    if (!f.done || !f.success) return 7;
    std::cout << "VLESS TCP over authenticated TLS passed\n";
}
