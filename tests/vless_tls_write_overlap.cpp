#include <boost/corosio/backend.hpp>
#include <cerrno>
#include <sys/socket.h>
import std;
import nexus.vless;
import nexus.tls.application_io;
import nexus.tls.corosio_application;
import nexus.vless.tls_server;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace v=nexus::vless; namespace t=nexus::tls; namespace c=nexus::crypto;
namespace io=nex::corosio; namespace capy=nex::capy;
using Bytes=c::Bytes; using namespace std::chrono_literals;
auto secret(int n) -> t::Secret { return t::Secret(Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection direction,int n) -> t::RecordLayer {
    auto s=secret(n); auto key=t::expand_label(c::Hash::sha256,s.view(),"key",{},16), iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12);
    if (!key || !iv) std::abort(); auto value=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,key->view(),iv->view());
    if (!value) std::abort(); return std::move(*value);
}
auto records(int send,int receive) -> t::ApplicationRecords {
    return {layer(t::RecordDirection::send,send),layer(t::RecordDirection::receive,receive),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(send),secret(receive)};
}
using Socket=io::local_stream_socket;
struct Fixture {
    io::io_context context; Socket server{context},peer_socket{context};
    t::detail::ApplicationConnection<Socket> connection{server,records(1,2),{}};
    v::UserId user{}; v::detail::TlsInbound<Socket> inbound;
    bool accepted=false,write_done=false,write_ok=false,read_done=false,read_ok=false;
    template<class Backend> explicit Fixture(Backend backend) : context(backend), inbound(connection,*v::ServerHandshake::create(std::span{&user,1})) {}
    ~Fixture() { inbound.cancel(); server.close(); peer_socket.close(); context.restart(); (void)context.run_for(1s); if (!connection.idle()) std::_Exit(90); }
};
auto establish(Fixture& f) -> capy::task<> {
    auto request=co_await f.inbound.read_request();
    if (request && co_await f.inbound.complete_dial(true)) f.accepted=true;
}
auto write_data(Fixture& f) -> capy::task<> { f.write_ok=co_await f.inbound.send(Bytes(1024,42)); f.write_done=true; }
auto read_data(Fixture& f) -> capy::task<> {
    std::array<std::uint8_t,8> buffer{}; auto result=co_await f.inbound.read(buffer);
    f.read_ok=result && *result==1 && buffer[0]==73; f.read_done=true;
}
auto send_pending(t::ApplicationIo& peer,int fd) -> bool {
    auto data=peer.pending_output(); auto n=::send(fd,data.data(),data.size(),MSG_NOSIGNAL);
    return n==static_cast<ssize_t>(data.size()) && peer.written(data.size()).has_value();
}
template<class Backend> auto exercise(Backend backend) -> bool {
    Fixture f(backend); if (io::connect_pair(f.server,f.peer_socket)) return (std::cerr << "failed at " << __LINE__ << '\n', false);
    t::ApplicationIo peer(records(2,1));
    auto request=v::encode_tcp_request({f.user,v::AddressKind::ipv4,80,{127,0,0,1}});
    if (!request || !peer.send(*request) || !send_pending(peer,f.peer_socket.native_handle())) return (std::cerr << "failed at " << __LINE__ << '\n', false);
    auto ex=f.context.get_executor(); capy::run_async(ex)(establish(f)); (void)f.context.run_for(1s);
    if (!f.accepted) return (std::cerr << "failed at " << __LINE__ << '\n', false);
    std::array<std::uint8_t,4096> received{};
    auto n=::recv(f.peer_socket.native_handle(),received.data(),received.size(),MSG_DONTWAIT);
    if (n<=0) return (std::cerr << "failed at " << __LINE__ << '\n', false);
    auto response=peer.feed(std::span{received}.first(static_cast<std::size_t>(n)));
    if (!response || !response->event || response->event->data!=Bytes({0,0})) return (std::cerr << "failed at " << __LINE__ << '\n', false);
    std::array<char,4096> filler{}; std::size_t filled=0;
    for (;;) { auto count=::send(f.server.native_handle(),filler.data(),filler.size(),MSG_DONTWAIT|MSG_NOSIGNAL);
        if (count>0) { filled+=static_cast<std::size_t>(count); continue; }
        if (count<0 && errno==EINTR) continue;
        if (count<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break; return (std::cerr << "failed at " << __LINE__ << '\n', false);
    }
    capy::run_async(ex)(write_data(f)); f.context.restart(); (void)f.context.run_for(20ms);
    if (f.write_done || !f.connection.pending_output()) return (std::cerr << "failed at " << __LINE__ << '\n', false);
    if (!peer.request_key_update(true) || !send_pending(peer,f.peer_socket.native_handle()) ||
        !peer.send(Bytes{73}) || !send_pending(peer,f.peer_socket.native_handle())) return (std::cerr << "failed at " << __LINE__ << '\n', false);
    capy::run_async(ex)(read_data(f)); f.context.restart(); (void)f.context.run_for(20ms);
    if (f.write_done || f.read_done) return (std::cerr << "failed at " << __LINE__ << '\n', false);
    while (filled) { auto count=::recv(f.peer_socket.native_handle(),received.data(),std::min(filled,received.size()),MSG_DONTWAIT);
        if (count<=0) return (std::cerr << "failed at " << __LINE__ << '\n', false); filled-=static_cast<std::size_t>(count); }
    f.context.restart(); (void)f.context.run_for(1s);
    if (!f.write_done || !f.write_ok || !f.read_done || !f.read_ok) return (std::cerr << "failed at " << __LINE__ << '\n', false);
    Bytes wire;
    while ((n=::recv(f.peer_socket.native_handle(),received.data(),received.size(),MSG_DONTWAIT))>0) wire.insert(wire.end(),received.begin(),received.begin()+n);
    bool data=false,update=false; std::size_t offset=0;
    while (offset<wire.size()) { auto result=peer.feed(std::span{wire}.subspan(offset));
        if (!result || !result->consumed) return (std::cerr << "failed at " << __LINE__ << '\n', false); offset+=result->consumed;
        if (result->event && result->event->kind==t::ApplicationEventKind::data) data=result->event->data==Bytes(1024,42);
        if (result->event && result->event->kind==t::ApplicationEventKind::key_update) update=true;
    }
    return data && update;
}
int main() {
    if (!exercise(io::epoll)) { std::cerr << "epoll overlap failed\n"; return 1; }
#if BOOST_COROSIO_HAVE_LIBURING
    if (!exercise(io::uring)) { std::cerr << "io_uring overlap failed\n"; return 2; }
#endif
    std::cout << "VLESS/TLS blocked write and peer KeyUpdate overlap passed\n";
}
