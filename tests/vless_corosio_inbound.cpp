#include <sys/socket.h>
#include <unistd.h>
#include <boost/corosio/backend.hpp>

import std;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import vless;
import vless.corosio_server;

namespace io=nex::corosio;
namespace capy=nex::capy;
using namespace std::chrono_literals;
struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    io::tcp_socket incoming{context}, target{context};
    bool done=false, success=false;
};
using Relay=vless::detail::ServerRelay<io::tcp_socket,io::tcp_socket>;
struct RelayState {
    Relay& relay;
    capy::async_event finished;
    unsigned pending=2;
    bool upload=false,download=false;
    auto complete() -> void { if (--pending==0) finished.set(); }
};
auto upload(RelayState& state) -> capy::task<> { state.upload=co_await state.relay.upload(); state.complete(); }
auto download(RelayState& state) -> capy::task<> { state.download=co_await state.relay.download(); state.complete(); }
auto run(Fixture& f) -> capy::task<> {
    auto user=vless::parse_user_id("00010203-0405-0607-0809-0a0b0c0d0e0f");
    std::array<vless::UserId,1> users{*user};
    auto state=vless::ServerHandshake::create(users);
    vless::detail::TcpServer server(f.incoming,std::move(*state));
    auto request=co_await server.read_request();
    if (!request || request->kind!=vless::AddressKind::ipv4 || request->address!=std::vector<std::uint8_t>{127,0,0,1}) { f.done=true; co_return; }
    auto [error]=co_await f.target.connect(io::endpoint(io::ipv4_address::loopback(),request->port));
    auto accepted=co_await server.complete_dial(!error);
    if (!accepted) { f.done=true; co_return; }
    Relay relay(server,f.incoming,f.target);
    RelayState relaying{relay};
    capy::run_async(f.context.get_executor())(upload(relaying));
    capy::run_async(f.context.get_executor())(download(relaying));
    (void)co_await relaying.finished.wait();
    f.success=relaying.upload && relaying.download; f.done=true;
}
int main(int argc,char** argv) {
    if (argc!=2) return 1;
    auto peer=::accept(std::atoi(argv[1]),nullptr,nullptr);
    if (peer<0) return 2;
    Fixture fixture;
    if (fixture.incoming.assign(peer)) { ::close(peer); return 3; }
    capy::run_async(fixture.context.get_executor())(run(fixture));
    (void)fixture.context.run_for(8s);
    if (!fixture.done) {
        fixture.incoming.cancel(); fixture.target.cancel();
        fixture.context.restart(); (void)fixture.context.run_for(1s);
        if (!fixture.done) std::_Exit(90);
    }
    return fixture.done && fixture.success ? 0 : 4;
}
