#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <boost/corosio/backend.hpp>
import std;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import tls.corosio_server_handshake;
import tls.corosio_application;
import tls.server_handshake_io;
import vless;
import vless.vision_server;
import vless.server_profile;
import vision;
namespace io=nex::corosio; namespace capy=nex::capy; namespace t=tls; namespace v=vless; namespace vis=vision;
using namespace std::chrono_literals;
using Connection=t::detail::ApplicationConnection<io::tcp_socket>; using Incoming=v::detail::VisionInbound<io::tcp_socket>;
struct Fixture { io::io_context context{io::epoll}; io::tcp_socket socket{context},target{context}; std::optional<t::ServerHandshakeIo> handshake; std::shared_ptr<::memory::Budget> budget; std::optional<v::ServerProfile> profile; bool done=false,success=false; };
struct Relay { Fixture& f; Incoming& inbound; capy::async_event done; unsigned remaining=2; bool up=false,down=false;
    void finish(bool ok,bool upload) { if (upload) up=ok; else down=ok; if (!ok) { inbound.cancel(); f.target.cancel(); } if (--remaining==0) done.set(); }
};
auto upload(Relay& r) -> capy::task<> {
    std::array<std::uint8_t,16384> buffer{};
    for (;;) {
        auto n=co_await r.inbound.read(buffer); if (!n) { r.finish(false,true); co_return; }
        if (!*n) { r.finish(!r.f.target.shutdown(io::shutdown_send),true); co_return; }
        std::size_t offset=0;
        while (offset<*n) { auto [error,count]=co_await r.f.target.write_some(capy::const_buffer(buffer.data()+offset,*n-offset)); if (error || !count || count>*n-offset) { r.finish(false,true); co_return; } offset+=count; }
    }
}
auto download(Relay& r) -> capy::task<> {
    std::array<std::uint8_t,16384> buffer{};
    for (;;) {
        auto [error,n]=co_await r.f.target.read_some(capy::mutable_buffer(buffer.data(),buffer.size()));
        if (capy::is_eof(error)) { auto closed=co_await r.inbound.close_output(); r.finish(closed,false); co_return; }
        if (error || !n || n>buffer.size() || !co_await r.inbound.send(std::span(buffer).first(n))) { r.finish(false,false); co_return; }
    }
}
auto serve(Fixture& f) -> capy::task<> {
    auto established=co_await t::detail::server_handshake(f.socket,*f.handshake); if (!established) { std::cerr << "outer handshake failure\n"; f.done=true; co_return; }
    Connection connection(f.socket,std::move(established->records),std::move(established->unread));
    if (!established->release_unread_reservation()) { std::cerr << "budget failure\n"; f.done=true; co_return; }
    auto state=f.profile->vision_handshake(); if (!state) { f.done=true; co_return; }
    Incoming inbound(f.socket,connection,std::move(*state)); auto request=co_await inbound.read_request();
    if (!request || request->kind!=v::AddressKind::ipv4 || request->address!=std::vector<std::uint8_t>{127,0,0,1}) { std::cerr << "request failure\n"; f.done=true; co_return; }
    auto [error]=co_await f.target.connect(io::endpoint(io::ipv4_address::loopback(),request->port));
    auto accepted=co_await inbound.complete_dial(!error); if (!accepted) { std::cerr << "dial failure " << error.message() << "\n"; f.done=true; co_return; }
    Relay relay{f,inbound}; capy::run_async(f.context.get_executor())(upload(relay)); capy::run_async(f.context.get_executor())(download(relay));
    (void)co_await relay.done.wait();
    auto status=inbound.send_status(); bool sent=status && *status==vis::SendStatus::direct; bool received=inbound.receive_direct();
    std::cerr << "send_direct=" << sent << " receive_direct=" << received << " up=" << relay.up << " down=" << relay.down << '\n';
    f.success=relay.up && relay.down && sent && received; f.done=true;
}
int main(int argc,char** argv) {
    if (argc!=5) return 1; int fd=::accept(std::atoi(argv[1]),nullptr,nullptr); if (fd<0) return 2;
    if (fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0)|O_NONBLOCK)<0) { ::close(fd); return 3; }
    Fixture f; if (f.socket.assign(fd)) { ::close(fd); return 3; }
    std::array<std::string,1> paths{argv[4]}; auto profile=v::ServerProfile::load(argv[2],argv[3],paths); if (!profile) return 4; f.profile.emplace(std::move(*profile));
    auto now=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
    f.budget=std::make_shared<::memory::Budget>(8u*1024*1024); auto h=f.profile->tls_handshake(now,now+10000,f.budget); if (!h) return 5;
    f.handshake.emplace(std::move(*h)); capy::run_async(f.context.get_executor())(serve(f)); (void)f.context.run_for(20s);
    if (!f.done) { f.socket.cancel(); f.target.cancel(); f.context.restart(); (void)f.context.run_for(2s); if (!f.done) std::_Exit(90); }
    return f.success ? 0 : 6;
}
