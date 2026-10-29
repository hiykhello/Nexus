#include <sys/socket.h>
#include <unistd.h>
#include <boost/corosio/backend.hpp>
import std;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.tls.corosio_server_handshake;
import nexus.tls.corosio_application;
import nexus.tls.server_handshake_io;
import nexus.vless;
import nexus.vless.tls_server;
import nexus.vless.server_profile;
namespace io=nex::corosio; namespace capy=nex::capy; namespace t=nexus::tls; namespace v=nexus::vless;
using namespace std::chrono_literals;
using Connection=t::detail::ApplicationConnection<io::tcp_socket>;
using Inbound=v::detail::TlsInbound<io::tcp_socket>;
using TlsRelay=v::detail::TlsRelay<io::tcp_socket,io::tcp_socket>;
struct Fixture {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
    io::tcp_socket incoming{context},target{context};
    std::optional<t::ServerHandshakeIo> handshake;
    std::shared_ptr<nexus::memory::Budget> budget;
    std::optional<v::ServerProfile> profile;
    bool done=false,success=false; unsigned activity=0;
};
struct RelayState {
    TlsRelay& relay; capy::async_event done; unsigned pending=2; bool uploaded=false,downloaded=false;
    void finish(bool ok,bool upload) { if (upload) uploaded=ok; else downloaded=ok; if (--pending==0) done.set(); }
};
auto upload(RelayState& r) -> capy::task<> { auto ok=co_await r.relay.upload(); r.finish(ok,true); }
auto download(RelayState& r) -> capy::task<> { auto ok=co_await r.relay.download(); r.finish(ok,false); }
auto serve(Fixture& f) -> capy::task<> {
    auto established=co_await t::detail::server_handshake(f.incoming,*f.handshake); if (!established) { f.done=true; co_return; }
    Connection tls(f.incoming,std::move(established->records),std::move(established->unread));
    if (!established->release_unread_reservation() || f.budget->reserved()) { f.done=true; co_return; }
    auto state=f.profile->vless_handshake(); if (!state) { f.done=true; co_return; }
    Inbound inbound(tls,std::move(*state)); auto request=co_await inbound.read_request();
    if (!request || request->kind!=v::AddressKind::ipv4 || request->address!=std::vector<std::uint8_t>{127,0,0,1}) { f.done=true; co_return; }
    auto [error]=co_await f.target.connect(io::endpoint(io::ipv4_address::loopback(),request->port));
    if (!(co_await inbound.complete_dial(!error))) { f.done=true; co_return; }
    TlsRelay worker(inbound,f.target,[&f] { ++f.activity; }); RelayState relay{worker};
    capy::run_async(f.context.get_executor())(upload(relay)); capy::run_async(f.context.get_executor())(download(relay));
    (void)co_await relay.done.wait(); f.success=relay.uploaded && relay.downloaded && f.activity>=2; f.done=true;
}
int main(int argc,char** argv) {
    if (argc!=5) return 1; auto fd=::accept(std::atoi(argv[1]),nullptr,nullptr); if (fd<0) return 2;
    Fixture f; if (f.incoming.assign(fd)) { ::close(fd); return 3; }
    std::array<std::string,1> user_paths{argv[4]};
    auto profile=v::ServerProfile::load(argv[2],argv[3],user_paths); if (!profile) return 4;
    f.profile.emplace(std::move(*profile));
    auto now=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    f.budget=std::make_shared<nexus::memory::Budget>(8u*1024*1024);
    auto h=f.profile->tls_handshake(now,now+5000,f.budget); if (!h) return 5;
    f.handshake.emplace(std::move(*h)); capy::run_async(f.context.get_executor())(serve(f)); (void)f.context.run_for(20s);
    if (!f.done) { f.incoming.cancel(); f.target.cancel(); f.context.restart(); (void)f.context.run_for(2s); if (!f.done) std::_Exit(90); }
    return f.success ? 0 : 6;
}
