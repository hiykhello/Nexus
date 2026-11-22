#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
import std;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import reality.auth;
import reality.server_auth;
import reality.server_probe;
import reality.server_credential;
import reality.server_profile;
import reality.fallback;
import tls.server_handshake_io;
import tls.corosio_server_handshake;
import tls.corosio_application;
import vless;
import vless.tls_server;
namespace r=reality; namespace t=tls; namespace c = ::crypto; namespace io=nex::corosio; namespace capy=nex::capy; namespace v=vless;
using namespace std::chrono_literals;
struct Fixture { io::io_context context{io::epoll}; io::tcp_socket socket{context},cover{context}; bool has_cover=false; std::size_t probe_limit=131072; r::ServerProfile& profile; bool done=false,success=false;
    explicit Fixture(r::ServerProfile& p) : profile(p) {} };
auto serve(Fixture& f) -> capy::task<> {
    auto finish=[&](std::string_view stage="done") { if (stage!="done") std::cerr << stage << std::endl; f.done=true; };
    auto probe=r::ServerProbe::create(f.probe_limit); if (!probe) { finish(); co_return; }
    auto policy=f.profile.policy(); std::array<std::uint8_t,4096> buffer{};
    while (probe->status()==r::ProbeStatus::pending) {
        auto [error,n]=co_await f.socket.read_some(capy::mutable_buffer(buffer.data(),buffer.size()));
        if (error || !n) { finish(); co_return; }
        auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        auto result=probe->feed(std::span(buffer).first(n),f.profile.private_key(),policy,now);
        if (result.status==r::ProbeStatus::fallback) {
            if (!f.has_cover) { finish("probe fallback"); co_return; }
            f.success=co_await r::fallback(f.socket,f.cover,probe->bytes(),std::span(buffer).subspan(result.consumed,n-result.consumed));
            finish(f.success ? "done" : "fallback relay"); co_return;
        }
        if (result.consumed!=n) { finish("probe consumption"); co_return; }
    }
    auto auth=probe->take_authentication(); if (!auth) { finish(); co_return; }
    auto now=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    auto handshake=f.profile.handshake(auth->key,now,now+10000); if (!handshake) { finish(); co_return; }
    auto result=co_await t::detail::server_handshake(f.socket,*handshake,{},probe->bytes());
    if (!result) { std::cerr << "TLS error " << static_cast<int>(result.error()) << std::endl; finish("TLS handshake"); co_return; }
    t::detail::ApplicationConnection<io::tcp_socket> connection(f.socket,std::move(result->records),std::move(result->unread));
    std::array<v::UserId,1> users{}; for (std::size_t i=0;i<16;++i) users[0][i]=static_cast<std::uint8_t>(i);
    auto state=v::ServerHandshake::create(users); if (!state) { finish(); co_return; }
    v::detail::TlsInbound<io::tcp_socket> inbound(connection,std::move(*state));
    auto request=co_await inbound.read_request(); if (!request || !co_await inbound.complete_dial(true)) { finish("VLESS request"); co_return; }
    auto n=co_await inbound.read(buffer); if (!n || !*n || !co_await inbound.send(std::span(buffer).first(*n))) { finish("VLESS data"); co_return; }
    f.success=true; finish();
}
int main(int argc,char** argv) {
    if (argc<5 || argc>7) return 1;
    std::array names{std::string("localhost")}; std::array<std::array<std::uint8_t,8>,1> ids{{{1,2,3,4,5,6,7,8}}};
    auto profile=r::ServerProfile::load(argv[4],argv[2],argv[3],names,ids,60); if (!profile) { std::cerr << profile.error() << '\n'; return 2; }
    auto public_key=profile->private_key().public_key(); if (!public_key) return 3;
    for (auto b:*public_key) std::cout << std::format("{:02x}",b); std::cout << std::endl;
    int fd=::accept(std::atoi(argv[1]),nullptr,nullptr); if (fd<0) return 4;
    if (fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0)|O_NONBLOCK)<0) { ::close(fd); return 5; }
    Fixture f(*profile);
    if (f.socket.assign(fd)) { ::close(fd); return 6; }
    if (argc>=6) {
        int cover=std::atoi(argv[5]);
        if (fcntl(cover,F_SETFL,fcntl(cover,F_GETFL,0)|O_NONBLOCK)<0 || f.cover.assign(cover)) return 8;
        f.has_cover=true;
        if (argc==7) f.probe_limit=std::strtoul(argv[6],nullptr,10);
    }
    capy::run_async(f.context.get_executor())(serve(f)); (void)f.context.run_for(15s);
    if (!f.done) { f.socket.cancel(); f.cover.cancel(); f.context.restart(); (void)f.context.run_for(1s); }
    return f.success ? 0 : 7;
}
