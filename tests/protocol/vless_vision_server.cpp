#include <boost/corosio/backend.hpp>
#include <sys/socket.h>
#include <cerrno>
import std;
import vless;
import vless.vision_server;
import vless.tls_server;
import vision;
import tls.application_io;
import tls.corosio_application;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace v=vless; namespace vis=vision; namespace t=tls; namespace c = ::crypto; namespace capy=nex::capy; namespace io=nex::corosio;
using Bytes=c::Bytes; using namespace std::chrono_literals;
auto secret(int n) -> t::Secret { return t::Secret(Bytes(32,static_cast<std::uint8_t>(n))); }
auto layer(t::RecordDirection direction,int n) -> t::RecordLayer {
    auto s=secret(n); auto key=t::expand_label(c::Hash::sha256,s.view(),"key",{},16),iv=t::expand_label(c::Hash::sha256,s.view(),"iv",{},12);
    if (!key || !iv) std::abort(); auto r=t::RecordLayer::create(direction,c::Aead::aes_128_gcm,key->view(),iv->view()); if (!r) std::abort(); return std::move(*r);
}
auto records(int send,int recv,t::ApplicationRole role) -> t::ApplicationRecords { return {layer(t::RecordDirection::send,send),layer(t::RecordDirection::receive,recv),16385,16385,c::Hash::sha256,c::Aead::aes_128_gcm,16,secret(send),secret(recv),role}; }
using Server=v::detail::VisionInbound<io::local_stream_socket>;
auto serve(Server& server,v::TcpRequest expected,bool mux,bool& ok) -> capy::task<> {
    auto request=co_await server.read_header(); if (!request) co_return;
    if (mux) { auto user=std::get_if<v::UserId>(&*request); if (!user || *user!=expected.user) co_return; }
    else { auto tcp=std::get_if<v::TcpRequest>(&*request); if (!tcp || tcp->user!=expected.user || tcp->port!=expected.port) co_return; }
    auto completed=co_await server.complete_dial(true); if (!completed) co_return;
    std::array<std::uint8_t,2> output{}; Bytes received;
    for (;;) { auto n=co_await server.read(output); if (!n) co_return; if (!*n) break; received.insert(received.end(),output.begin(),output.begin()+*n); }
    Bytes reply{9,8,7}; auto sent=co_await server.send(reply); auto closed=co_await server.close_output();
    ok=received==Bytes({1,2,3,4}) && sent && closed;
}
template<class Backend> auto run(Backend backend,bool mux) -> bool {
    io::io_context context(backend); io::local_stream_socket server_socket(context),peer_socket(context); if (io::connect_pair(server_socket,peer_socket)) return false;
    v::TcpRequest request; std::iota(request.user.begin(),request.user.end(),std::uint8_t{0}); request.port=443; request.address={127,0,0,1};
    auto header=mux ? std::expected<Bytes,v::EncodeError>{v::encode_mux_request(request.user,true)} : v::encode_vision_tcp_request(request); auto frame=vis::encode_block(request.user,vis::Command::end,Bytes{1,2,3,4},{}); if (!header || !frame) return false;
    header->insert(header->end(),frame->begin(),frame->end()); t::ApplicationIo peer(records(2,1,t::ApplicationRole::client));
    if (!peer.send(*header)) return false; Bytes wire(peer.pending_output().begin(),peer.pending_output().end());
    if (!peer.written(peer.pending_output().size()) || !peer.close_notify()) return false;
    wire.insert(wire.end(),peer.pending_output().begin(),peer.pending_output().end());
    if (::send(peer_socket.native_handle(),wire.data(),wire.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(wire.size())) return false;
    t::detail::ApplicationConnection connection(server_socket,records(1,2,t::ApplicationRole::server),{});
    auto handshake=v::ServerHandshake::create_vision(std::span{&request.user,1}); if (!handshake) return false;
    Server server(server_socket,connection,std::move(*handshake)); if (mux && !server.allow_mux()) return false; bool ok=false;
    capy::run_async(context.get_executor())(serve(server,request,mux,ok)); context.restart(); (void)context.run_for(3s);
    if (!context.stopped() || !ok || !connection.idle()) { server.cancel(); return false; }
    wire.clear(); std::array<std::uint8_t,4096> buffer{};
    for (;;) { auto n=::recv(peer_socket.native_handle(),buffer.data(),buffer.size(),MSG_DONTWAIT); if (n>0) { wire.insert(wire.end(),buffer.begin(),buffer.begin()+n); continue; } if (n<0 && errno==EINTR) continue; if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break; return false; }
    auto decrypt=layer(t::RecordDirection::receive,1); std::size_t offset=0; int index=0;
    while (offset<wire.size()) {
        if (wire.size()-offset<5) return false; auto length=(std::size_t(wire[offset+3])<<8)|wire[offset+4]; if (length+5>wire.size()-offset) return false;
        auto plain=decrypt.open(std::span(wire).subspan(offset,length+5)); if (!plain) return false;
        if (index==0) { if (v::parse_response(plain->content).status!=v::HeaderStatus::accepted) return false; }
        else if (index==1) { vis::Receiver receiver(request.user); std::array<std::uint8_t,3> decoded{}; auto step=receiver.feed(plain->content,decoded); if (step.written!=3 || decoded!=std::array<std::uint8_t,3>{9,8,7}) return false; }
        else if (index==2) { if (plain->type!=t::ContentType::alert) return false; }
        else return false;
        offset+=length+5; ++index;
    }
    return index==3;
}
using PlainServer=v::detail::TlsInbound<io::local_stream_socket>;
auto serve_plain(PlainServer& server,v::UserId expected,bool& ok) -> capy::task<> {
    auto request=co_await server.read_header();
    if (!request || !std::holds_alternative<v::UserId>(*request) || std::get<v::UserId>(*request)!=expected) co_return;
    if (!co_await server.complete_dial(true)) co_return;
    std::array<std::uint8_t,4> bytes{}; auto n=co_await server.read(bytes);
    ok=n && *n==4 && bytes==std::array<std::uint8_t,4>{1,2,3,4} && co_await server.send(bytes);
}
template<class Backend> auto run_plain(Backend backend) -> bool {
    io::io_context context(backend); io::local_stream_socket server_socket(context),peer_socket(context);
    if (io::connect_pair(server_socket,peer_socket)) return false;
    v::UserId user{}; std::iota(user.begin(),user.end(),std::uint8_t{0});
    auto header=v::encode_mux_request(user); header.insert(header.end(),{1,2,3,4});
    t::ApplicationIo peer(records(2,1,t::ApplicationRole::client)); if (!peer.send(header)) return false;
    auto wire=peer.pending_output(); if (::send(peer_socket.native_handle(),wire.data(),wire.size(),MSG_NOSIGNAL)!=static_cast<ssize_t>(wire.size())) return false;
    t::detail::ApplicationConnection connection(server_socket,records(1,2,t::ApplicationRole::server),{});
    auto handshake=v::ServerHandshake::create(std::span{&user,1}); if (!handshake) return false;
    PlainServer server(connection,std::move(*handshake)); if (!server.allow_mux()) return false;
    bool ok=false; capy::run_async(context.get_executor())(serve_plain(server,user,ok));
    context.restart(); (void)context.run_for(3s); if (!context.stopped() || !ok || !connection.idle()) { server.cancel(); return false; }
    std::array<std::uint8_t,4096> output{}; auto n=::recv(peer_socket.native_handle(),output.data(),output.size(),MSG_DONTWAIT); if (n<=0) return false;
    auto decrypt=layer(t::RecordDirection::receive,1); std::size_t offset=0; Bytes plaintext;
    while (offset<static_cast<std::size_t>(n)) {
        if (static_cast<std::size_t>(n)-offset<5) return false;
        auto length=(std::size_t(output[offset+3])<<8)|output[offset+4]; if (length+5>static_cast<std::size_t>(n)-offset) return false;
        auto record=decrypt.open(std::span(output).subspan(offset,length+5)); if (!record) return false;
        plaintext.insert(plaintext.end(),record->content.begin(),record->content.end()); offset+=length+5;
    }
    return plaintext==Bytes({0,0,1,2,3,4});
}
int main() {
    if (!run(io::epoll,false) || !run(io::epoll,true) || !run_plain(io::epoll)) return 1;
#if BOOST_COROSIO_HAVE_LIBURING
    if (!run(io::uring,false) || !run(io::uring,true) || !run_plain(io::uring)) return 2;
#endif
    std::cout << "Vision inbound preserves request suffix and frames response\n";
}
