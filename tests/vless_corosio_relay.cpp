#include <sys/socket.h>
#include <boost/corosio/backend.hpp>

import std;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.vless;
import nexus.vless.corosio_server;

namespace io=nex::corosio;
namespace capy=nex::capy;
namespace v=nexus::vless;
using namespace std::chrono_literals;
using Socket=io::local_stream_socket;
struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    Socket incoming{context},client{context},target{context},origin{context};
    std::optional<v::detail::TcpServer<Socket>> server;
    std::optional<v::detail::ServerRelay<Socket,Socket>> relay;
    bool ready=false,failed=false,upload_done=false,download_done=false;
    bool upload_ok=false,download_ok=false;
};
auto upload(Fixture& f) -> capy::task<> { f.upload_ok=co_await f.relay->upload(); f.upload_done=true; }
auto download(Fixture& f) -> capy::task<> { f.download_ok=co_await f.relay->download(); f.download_done=true; }
auto setup(Fixture& f) -> capy::task<> {
    auto request=co_await f.server->read_request();
    if (!request) { f.failed=true; co_return; }
    auto accepted=co_await f.server->complete_dial(true);
    if (!accepted) { f.failed=true; co_return; }
    f.relay.emplace(*f.server,f.incoming,f.target);
    capy::run_async(f.context.get_executor())(upload(f));
    capy::run_async(f.context.get_executor())(download(f));
    f.ready=true;
}
int main() {
    Fixture f;
    if (io::connect_pair(f.incoming,f.client) || io::connect_pair(f.target,f.origin)) return 1;
    auto user=v::parse_user_id("00010203-0405-0607-0809-0a0b0c0d0e0f");
    std::array<v::UserId,1> users{*user};
    auto handshake=v::ServerHandshake::create(users);
    f.server.emplace(f.incoming,std::move(*handshake));
    v::TcpRequest request{*user,v::AddressKind::ipv4,443,{127,0,0,1}};
    auto bytes=v::encode_tcp_request(request);
    if (::send(f.client.native_handle(),bytes->data(),bytes->size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(bytes->size())) return 2;
    capy::run_async(f.context.get_executor())(setup(f));
    (void)f.context.run_for(50ms);
    if (!f.ready || f.failed || f.upload_done || f.download_done) {
        if (f.relay) f.relay->cancel(); else f.server->cancel();
        f.target.cancel(); f.context.restart(); (void)f.context.run_for(2s);
        if (!f.context.stopped()) std::_Exit(90);
        return 3;
    }
    f.relay->cancel(); f.context.restart(); (void)f.context.run_for(2s);
    if (!f.upload_done || !f.download_done) std::_Exit(90);
    if (f.upload_ok || f.download_ok) return 4;
    std::cout << "VLESS bidirectional relay cancellation passed\n";
}
