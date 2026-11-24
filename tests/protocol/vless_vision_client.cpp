#include <boost/corosio/backend.hpp>
#include <sys/socket.h>
#include <cerrno>
import std;
import vless;
import vless.vision_client;
import vless.corosio_client;
import vision;
import tls.application_io;
import tls.corosio_application;
import capy;
import corosio;
namespace v=vless; namespace vis=vision; namespace t=tls; namespace c = ::crypto; namespace io = ::corosio;
using Bytes=c::Bytes; using namespace std::chrono_literals;
auto secret(int n) -> t::Secret { return t::Secret(Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection direction,int n) -> t::RecordLayer {
    auto s=secret(n); auto key=t::expand_label(c::Hash::sha256,s.view(),"key",{},16),iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12);
    if (!key || !iv) std::abort(); auto r=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,key->view(),iv->view()); if (!r) std::abort(); return std::move(*r);
}
auto records(int send,int recv) -> t::ApplicationRecords { return {layer(t::RecordDirection::send,send),layer(t::RecordDirection::receive,recv),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(send),secret(recv),t::ApplicationRole::client}; }
using Client=v::detail::VisionClient<io::local_stream_socket>;
auto execute(Client& client,v::TcpRequest request,bool mux,bool& ok) -> capy::task<> {
    auto started=mux ? co_await client.start_mux() : co_await client.start(request); if (!started) co_return;
    Bytes upload{1,2,3}; auto sent=co_await client.write(upload); if (!sent) co_return;
    std::array<std::uint8_t,2> output{}; Bytes received;
    for (;;) {
        auto n=co_await client.read(output); if (!n) co_return; if (!*n) break;
        received.insert(received.end(),output.begin(),output.begin()+*n);
    }
    auto closed=co_await client.close_output(); ok=received==Bytes({9,8,7,6}) && closed;
}
auto start_client(Client& client,v::TcpRequest request,bool& ok) -> capy::task<> { ok=co_await client.start(request); }
template<class Relay> auto do_upload(Relay& relay,bool& ok) -> capy::task<> { ok=co_await relay.upload(); }
template<class Relay> auto do_download(Relay& relay,bool& ok) -> capy::task<> { ok=co_await relay.download(); }
template<class Backend> auto run(Backend backend,bool relay_mode,bool mux=false) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context),local(context),app(context); if (io::connect_pair(a,b) || io::connect_pair(local,app)) return false;
    v::TcpRequest request; std::iota(request.user.begin(),request.user.end(),std::uint8_t{0}); request.port=443; request.address={127,0,0,1};
    auto frame=vis::encode_block(request.user,vis::Command::end,Bytes{9,8,7,6},{}); if (!frame) return false;
    Bytes response{0,0}; response.insert(response.end(),frame->begin(),frame->end());
    t::ApplicationIo peer(records(2,1)); if (!peer.send(response)) return false;
    Bytes wire(peer.pending_output().begin(),peer.pending_output().end());
    if (!peer.written(peer.pending_output().size()) || !peer.close_notify()) return false;
    wire.insert(wire.end(),peer.pending_output().begin(),peer.pending_output().end());
    if (::send(b.native_handle(),wire.data(),wire.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(wire.size())) return false;
    t::detail::ApplicationConnection connection(a,records(1,2),{}); Client client(a,connection,request.user); bool ok=false;
    if (relay_mode) {
        capy::run_async(context.get_executor())(start_client(client,request,ok)); context.restart(); (void)context.run_for(3s);
        if (!context.stopped() || !ok) { client.cancel(); return false; }
        std::array<std::uint8_t,3> upload{1,2,3};
        if (::send(app.native_handle(),upload.data(),upload.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(upload.size()) || app.shutdown(io::shutdown_send)) return false;
        v::detail::VisionRelay relay(local,client); bool up=false,down=false;
        capy::run_async(context.get_executor())(do_upload(relay,up));
        capy::run_async(context.get_executor())(do_download(relay,down));
        context.restart(); (void)context.run_for(3s);
        if (!context.stopped() || !up || !down) { relay.cancel(); context.restart(); (void)context.run_for(1s); return false; }
        std::array<std::uint8_t,8> received{}; auto n=::recv(app.native_handle(),received.data(),received.size(),0);
        if (n!=4 || !std::ranges::equal(std::span(received).first(4),std::array<std::uint8_t,4>{9,8,7,6}) || ::recv(app.native_handle(),received.data(),received.size(),0)!=0) return false;
    } else {
        capy::run_async(context.get_executor())(execute(client,request,mux,ok)); context.restart(); (void)context.run_for(3s);
    }
    if (!context.stopped() || !ok || !connection.idle()) { client.cancel(); return false; }
    wire.clear(); std::array<std::uint8_t,4096> buf{};
    for (;;) { auto n=::recv(b.native_handle(),buf.data(),buf.size(),MSG_DONTWAIT); if (n>0) { wire.insert(wire.end(),buf.begin(),buf.begin()+n); continue; } if (n<0 && errno==EINTR) continue; if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break; return false; }
    // Decode independent TLS records and ensure the first is the Vision request,
    // the second is framed upload, followed by authenticated close_notify.
    auto decrypt=layer(t::RecordDirection::receive,1); std::size_t offset=0; int index=0;
    while (offset<wire.size()) {
        if (wire.size()-offset<5) return false; auto length=(std::size_t(wire[offset+3])<<8)|wire[offset+4];
        if (length+5>wire.size()-offset) return false;
        auto plain=decrypt.open(std::span(wire).subspan(offset,length+5)); if (!plain) return false;
        if (index==0) {
            if (mux) { auto parsed=v::parse_mux_request(plain->content,true); if (parsed.status!=v::HeaderStatus::accepted || parsed.consumed!=plain->content.size() || !parsed.user || *parsed.user!=request.user) return false; }
            else { auto parsed=v::parse_vision_tcp_request(plain->content); if (parsed.status!=v::HeaderStatus::accepted || parsed.consumed!=plain->content.size() || !parsed.request || parsed.request->user!=request.user) return false; }
        }
        else if (index==1) { vis::Receiver receiver(request.user); std::array<std::uint8_t,3> decoded{}; auto step=receiver.feed(plain->content,decoded); if (step.written!=3 || decoded!=std::array<std::uint8_t,3>{1,2,3}) return false; }
        else if (index==2) { if (plain->type!=t::ContentType::alert) return false; }
        else return false;
        offset+=length+5; ++index;
    }
    return index==3;
}
template<class Relay> auto canceled_upload(Relay& relay,bool& done,bool& ok) -> capy::task<> { ok=co_await relay.upload(); done=true; }
template<class Relay> auto canceled_download(Relay& relay,bool& done,bool& ok) -> capy::task<> { ok=co_await relay.download(); done=true; }
template<class Backend> auto cancel_test(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket remote(context),peer(context),local(context),app(context);
    if (io::connect_pair(remote,peer) || io::connect_pair(local,app)) return false;
    v::TcpRequest request; request.port=443; request.address={127,0,0,1};
    t::detail::ApplicationConnection connection(remote,records(1,2),{}); Client client(remote,connection,request.user); bool started=false;
    capy::run_async(context.get_executor())(start_client(client,request,started)); context.restart(); (void)context.run_for(1s);
    if (!context.stopped() || !started) { client.cancel(); return false; }
    v::detail::VisionRelay relay(local,client); bool up_done=false,down_done=false,up_ok=false,down_ok=false;
    capy::run_async(context.get_executor())(canceled_upload(relay,up_done,up_ok));
    capy::run_async(context.get_executor())(canceled_download(relay,down_done,down_ok));
    context.restart(); (void)context.run_for(30ms);
    if (up_done || down_done || connection.idle()) { relay.cancel(); return false; }
    relay.cancel(); context.restart(); (void)context.run_for(1s);
    return context.stopped() && up_done && down_done && !up_ok && !down_ok && connection.idle() && !connection.active();
}

using PlainClient=v::detail::TcpClient<io::local_stream_socket>;
auto plain_mux(PlainClient& client,v::UserId user,bool& ok) -> capy::task<> {
    if (!co_await client.start_mux(user)) co_return;
    if (!co_await client.send(Bytes{1,2,3})) co_return;
    if (!co_await client.receive_response()) co_return;
    auto reader=client.reader(); if (!reader) co_return;
    std::array<std::uint8_t,4> data{};
    auto result=co_await reader->read_some(data);
    ok=result && result->kind==t::detail::AsyncStreamReadKind::data && result->size==4 && data==std::array<std::uint8_t,4>{9,8,7,6};
}
template<class Backend> auto plain_mux_test(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket a(context),b(context);
    if (io::connect_pair(a,b)) return false;
    v::UserId user{}; std::iota(user.begin(),user.end(),std::uint8_t{0});
    t::ApplicationIo peer(records(2,1)); if (!peer.send(Bytes{0,0,9,8,7,6})) return false;
    auto wire=peer.pending_output(); if (::send(b.native_handle(),wire.data(),wire.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(wire.size())) return false;
    t::detail::ApplicationConnection connection(a,records(1,2),{}); PlainClient client(connection); bool ok=false;
    capy::run_async(context.get_executor())(plain_mux(client,user,ok)); context.restart(); (void)context.run_for(3s);
    if (!context.stopped() || !ok || !connection.idle()) { connection.cancel(); return false; }
    std::array<std::uint8_t,4096> buf{}; auto n=::recv(b.native_handle(),buf.data(),buf.size(),MSG_DONTWAIT); if (n<=0) return false;
    auto decrypt=layer(t::RecordDirection::receive,1); std::size_t offset=0; int index=0;
    while (offset<static_cast<std::size_t>(n)) {
        if (static_cast<std::size_t>(n)-offset<5) return false;
        auto length=(std::size_t(buf[offset+3])<<8)|buf[offset+4]; if (length+5>static_cast<std::size_t>(n)-offset) return false;
        auto plain=decrypt.open(std::span(buf).subspan(offset,length+5)); if (!plain) return false;
        if (index==0) { auto parsed=v::parse_mux_request(plain->content); if (parsed.status!=v::HeaderStatus::accepted || parsed.consumed!=plain->content.size() || !parsed.user || *parsed.user!=user) return false; }
        else if (index==1) { if (plain->content!=Bytes{1,2,3}) return false; }
        else return false;
        offset+=length+5; ++index;
    }
    return index==2;
}

int main() {
    if (!run(io::epoll,false) || !run(io::epoll,true) || !run(io::epoll,false,true) || !plain_mux_test(io::epoll) || !cancel_test(io::epoll)) return 1;
#if BOOST_COROSIO_HAVE_LIBURING
    if (!run(io::uring,false) || !run(io::uring,true) || !run(io::uring,false,true) || !plain_mux_test(io::uring) || !cancel_test(io::uring)) return 2;
#endif
    std::cout << "Vision VLESS client preserves response suffix and frames early upload\n";
}
