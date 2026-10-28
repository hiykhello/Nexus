#include <boost/corosio/backend.hpp>
#include <sys/socket.h>
#include <errno.h>
import std;
import nexus.tls.application_io;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.tls.corosio_application;
namespace capy=nex::capy; namespace io=nex::corosio; namespace t=nexus::tls; namespace c=nexus::crypto;
using Bytes=c::Bytes; using namespace std::chrono_literals;
auto secret(int n) -> t::Secret { return t::Secret(Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection dir,int n) -> t::RecordLayer { auto s=secret(n); auto key=t::expand_label(c::Hash::sha256,s.view(),"key",{},16), iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12); if (!key || !iv) std::abort(); auto l=t::RecordLayer::create(dir,c::Aead::aes_128_gcm,key->view(),iv->view()); if (!l) std::abort(); return std::move(*l); }
auto app(int send,int recv) -> t::ApplicationIo { return t::ApplicationIo(t::ApplicationRecords(layer(t::RecordDirection::send,send),layer(t::RecordDirection::receive,recv),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(send),secret(recv),t::ApplicationRole::client)); }
struct Fixture {
    #if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context;
#endif
 io::local_stream_socket a{context},b{context}; t::ApplicationIo client=app(1,2), peer=app(2,1);
    bool write_started=false,write_done=false,read_done=false,peer_done=false; std::error_code write_error; Bytes received;
    ~Fixture() { a.close(); b.close(); context.restart(); (void)context.run_for(1s); if (!context.stopped()) std::_Exit(1); }
};
auto blocked_write(Fixture& f) -> capy::task<> {
    f.write_started=true;
    auto result=co_await t::detail::flush_application(f.a,f.client);
    if (!result) f.write_error=std::make_error_code(std::errc::operation_canceled); f.write_done=true;
}
auto read_client(Fixture& f) -> capy::task<> {
    std::array<std::uint8_t,128> buffer{};
    while (!f.read_done) {
        auto [error,n]=co_await f.a.read_some(capy::mutable_buffer(buffer.data(),buffer.size())); if (error || !n) co_return;
        std::size_t p=0; while (p<n) { auto result=f.client.feed(std::span{buffer}.subspan(p,n-p)); if (!result || !result->consumed) co_return; p+=result->consumed;
            if (result->event && result->event->kind==t::ApplicationEventKind::data) { f.received=std::move(result->event->data); f.read_done=true; } }
    }
}
auto write_peer(Fixture& f) -> capy::task<> {
    auto pending=f.peer.pending_output(); Bytes owned(pending.begin(),pending.end()); std::size_t p=0;
    while (p<owned.size()) { auto [error,n]=co_await f.b.write_some(capy::const_buffer(owned.data()+p,owned.size()-p)); if (error || !n) co_return; p+=n; }
    f.peer_done=true;
}
int main() {
    Fixture f; if (io::connect_pair(f.a,f.b)) return 1;
    std::array<char,4096> filler{};
    while (true) { auto n=::send(f.a.native_handle(),filler.data(),filler.size(),MSG_DONTWAIT|MSG_NOSIGNAL); if (n>0) continue; if (n<0 && errno==EINTR) continue; if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break; return 2; }
    Bytes msg{'p','i','n','g'}; if (!f.client.send(msg) || !f.peer.send(msg)) return 3;
    auto ex=f.context.get_executor(); capy::run_async(ex)(blocked_write(f)); capy::run_async(ex)(read_client(f)); capy::run_async(ex)(write_peer(f));
    f.context.restart(); (void)f.context.run_for(50ms);
    if (!f.write_started || f.write_done || !f.read_done || !f.peer_done || f.received!=msg || f.client.pending_output().empty()) return 4;
    f.a.cancel(); f.context.restart(); (void)f.context.run_for(1s);
    if (!f.write_done || !f.write_error || !f.context.stopped()) return 5;
    f.client.cancel(); if (!f.client.pending_output().empty()) return 6;
    std::cout << "Corosio TLS application full-duplex backpressure and cancellation passed\n";
}
